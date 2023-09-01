#pragma once

#include <ntdef.h>
#include <ntifs.h>
#include <ntddk.h>
#include <windef.h>
#include <ntstrsafe.h>
#include <stdlib.h>
#include <ntimage.h>

#define COMMAND_COMPLETED				0
#define COMMAND_GET_PROCESS_ID			1
#define COMMAND_GET_BASE_ADDRESS		2
#define COMMAND_GET_PEB					3
#define COMMAND_READ_PROCESS_MEMORY		4
#define COMMAND_WRITE_PROCESS_MEMORY	5
#define COMMAND_CLEAR					6

typedef struct _KM_DRIVER_COMMAND {
	// Memory
	PVOID		buffer;
	ULONG64		address;
	ULONG		size;

	// Process
	CHAR processName[32];
	HANDLE processId;

	UINT8		code;
}KM_DRIVER_COMMAND, * PKM_DRIVER_COMMAND;
