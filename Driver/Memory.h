#pragma once

#define SHARED_MEMORY_TAG 'KDSM'

// Shared memory variables
SECURITY_DESCRIPTOR g_SecDescriptor;
ULONG               g_DaclLength;
PACL                g_Dacl; // this is the problem i guess PACL
UNICODE_STRING      g_SharedMemoryName;
static HANDLE       g_hSharedMemorySection = NULL;
static PVOID        g_SharedMemoryPointer = NULL;

NTSTATUS CreateSharedMemory();
NTSTATUS ReadSharedMemory();
VOID UnmapSharedMemory();
