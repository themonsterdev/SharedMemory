#pragma once

#include <ntdef.h>
#include <ntifs.h>
#include <ntddk.h>
#include <windef.h>
#include <ntstrsafe.h>
#include <stdlib.h>

typedef struct _KM_DRIVER_COMMAND {
	UINT8		code;

	// Memory
	PVOID		buffer;
	ULONG64		address;
	ULONG		size;

	// Process
	CHAR processName[32];
	HANDLE processId;
}KM_DRIVER_COMMAND, * PKM_DRIVER_COMMAND;
