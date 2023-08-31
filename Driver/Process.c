#include "Stdafx.h"
#include "Process.h"

#include "Stdafx.h"
#include "Process.h"

HANDLE GetProcessHandle(const char* processName)
{
	ULONG bufferSize = 0;
	NTSTATUS ntStatus = ZwQuerySystemInformation(SystemProcessInformation, NULL, 0, &bufferSize);
	//if (!NT_SUCCESS(ntStatus))
	//{
	//	DbgPrintEx(0, 0, "failed to get buffer size (GetProcessHandle)");
	//	return ntStatus;
	//}

	/*if (bufferSize == 0)
	{
		DbgPrintEx(0, 0, "failed to get buffer size to zero (GetProcessHandle)");
		return NULL;
	}*/

	PVOID buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, bufferSize, 'zkjb');
	if (buffer == 0)
	{
		DbgPrint("failed to allocate pool (GetProcessHandle)");
		return NULL;
	}

	ANSI_STRING processNameAnsi = { 0 };
	UNICODE_STRING processNameUnicode = { 0 };
	RtlInitAnsiString(&processNameAnsi, processName);

	ntStatus = RtlAnsiStringToUnicodeString(&processNameUnicode, &processNameAnsi, TRUE);
	if (!NT_SUCCESS(ntStatus))
	{
		DbgPrint("failed to convert string (GetProcessHandle)");
		RtlFreeUnicodeString(&processNameUnicode);
		ExFreePoolWithTag(buffer, 'zkjb');
		return NULL;
	}

	PSYSTEM_PROCESS_INFO processInfo = (PSYSTEM_PROCESS_INFO)buffer;

	ntStatus = ZwQuerySystemInformation(SystemProcessInformation, processInfo, bufferSize, NULL);
	if (NT_SUCCESS(ntStatus))
	{
		while (processInfo->NextEntryOffset)
		{
			if (RtlCompareUnicodeString(&processNameUnicode, &processInfo->ImageName, TRUE) == 0)
			{
				return processInfo->UniqueProcessId;
			}
			processInfo = (PSYSTEM_PROCESS_INFO)((PBYTE)processInfo + processInfo->NextEntryOffset);
		}
	}

	RtlFreeUnicodeString(&processNameUnicode);
	ExFreePoolWithTag(buffer, 'zkjb');
	return NULL;
}
