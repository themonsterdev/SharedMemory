#pragma once

NTSTATUS NTAPI MmCopyVirtualMemory
(
	PEPROCESS SourceProcess,
	PVOID SourceAddress,
	PEPROCESS TargetProcess,
	PVOID TargetAddress,
	SIZE_T BufferSize,
	KPROCESSOR_MODE PreviousMode,
	PSIZE_T ReturnSize
);

// Define a custom tag for memory allocations.
#define SHARED_MEMORY_TAG 'KDSM'

// Declare global variables for security settings.
SECURITY_DESCRIPTOR g_SecDescriptor;
ULONG               g_DaclLength;
PACL                g_Dacl; // A pointer to an Access Control List (ACL) structure.

// Definition of variables related to shared memory:
// `g_SharedMemoryName` stores the name of the shared memory,
// `g_hSharedMemorySection` is a handle to the shared memory section,
// `g_SharedMemoryPointer` is a pointer to the shared memory area.
UNICODE_STRING g_SharedMemoryName;
HANDLE g_hSharedMemorySection;	// Initialize handle to NULL.
PVOID g_SharedMemoryPointer;		// Initialize pointer to NULL.

// Creates and configures shared memory with appropriate security settings.
NTSTATUS CreateSharedMemory();

// Reads shared memory by mapping it into the current process's address space.
NTSTATUS ReadSharedMemory();

// Unmaps the shared memory section and closes its handle.
VOID UnmapSharedMemory();

BOOL ReadVirtualMemory(HANDLE hProcess, PVOID address, PVOID buffer, SIZE_T size);
BOOL WriteVirtualMemory(HANDLE hProcess, PVOID address, PVOID buffer, SIZE_T size);

PVOID FindPattern(PVOID base, int length, const char* pattern, const char* mask);
PVOID FindPatternImage(PVOID base, const char* pattern, const char* mask);
