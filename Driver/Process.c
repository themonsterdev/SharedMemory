#include "Stdafx.h"
#include "Process.h"

HANDLE GetProcessId(const char* processName)
{
	ULONG bufferSize = 0;
	ZwQuerySystemInformation(SystemProcessInformation, NULL, 0, &bufferSize);

	PVOID buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, bufferSize, 'jldg');
	if (buffer == 0)
	{
		DbgPrint("failed to allocate pool (GetProcessId)");
		return 0;
	}

	ANSI_STRING processNameAnsi = { 0 };
	UNICODE_STRING processNameUnicode = { 0 };
	RtlInitAnsiString(&processNameAnsi, processName);
	if (!NT_SUCCESS(RtlAnsiStringToUnicodeString(&processNameUnicode, &processNameAnsi, TRUE)))
	{
		DbgPrint("failed to convert string (GetProcessId)");
		RtlFreeUnicodeString(&processNameUnicode);
		return 0;
	}

	PSYSTEM_PROCESS_INFO processInfo = (PSYSTEM_PROCESS_INFO)buffer;
	if (NT_SUCCESS(ZwQuerySystemInformation(SystemProcessInformation, processInfo, bufferSize, NULL)))
	{
		while (processInfo->NextEntryOffset)
		{
			if (RtlCompareUnicodeString(&processNameUnicode, &processInfo->ImageName, TRUE) == 0)
			{
				RtlFreeUnicodeString(&processNameUnicode);
				return processInfo->UniqueProcessId;
			}
			processInfo = (PSYSTEM_PROCESS_INFO)((PBYTE)processInfo + processInfo->NextEntryOffset);
		}
	}
	else
	{
		ExFreePoolWithTag(buffer, 'jldg');
	}

	return 0;
}

ULONG64 GetModuleBaseX64(HANDLE handle)
{
	PEPROCESS process;
	if (NT_SUCCESS(PsLookupProcessByProcessId(handle, &process)))
	{
		return (ULONG64)PsGetProcessSectionBaseAddress(process);
	}
	return 0;
}

PVOID GetSystemModuleBase(const char* moduleName)
{
	ULONG size = 0;
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	status = ZwQuerySystemInformation(SystemModuleInformation, NULL, size, &size);
	if (!NT_SUCCESS(status) && status != STATUS_INFO_LENGTH_MISMATCH)
	{
		DbgPrint("Failed to find ZwQuerySystemInformation 0x%x!", status);
		return 0;
	}

	const PVOID moduleList = ExAllocatePool2(POOL_FLAG_NON_PAGED, size, 'abcd');
	if (moduleList == 0)
	{
		DbgPrint("Failed to find ExAllocatePool2!");
		return 0;
	}

	status = ZwQuerySystemInformation(SystemModuleInformation, moduleList, size, &size);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("Failed to find ZwQuerySystemInformation 0x%x!", status);
		ExFreePoolWithTag(moduleList, 0);
		return 0;
	}

	PVOID mobuleBase = 0;
	const PSYSTEM_MODULE_INFORMATION pSystemModuleInformation = (PSYSTEM_MODULE_INFORMATION)moduleList;
	const ULONG moduleCount = pSystemModuleInformation->Count;

	for (SIZE_T i = 0; i < moduleCount; i++)
	{
		const SYSTEM_MODULE_ENTRY module = pSystemModuleInformation->Modules[i];
		// const auto currentModuleName = reinterpret_cast<const char*>(module.FullPathName + module.OffsetToFileName);
		if (strstr(module.FullPathName, moduleName))
		{
			mobuleBase = module.ImageBase;
			break;
		}
	}

	ExFreePoolWithTag(moduleList, 0);

	return mobuleBase <= 0 ? 0 : mobuleBase;
}
