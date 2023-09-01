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
