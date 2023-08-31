#pragma once

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
UNICODE_STRING g_SharedMemoryName = { 0 };
static HANDLE g_hSharedMemorySection = NULL;	// Initialize handle to NULL.
static PVOID g_SharedMemoryPointer = NULL;		// Initialize pointer to NULL.

// Creates and configures shared memory with appropriate security settings.
NTSTATUS CreateSharedMemory();

// Reads shared memory by mapping it into the current process's address space.
NTSTATUS ReadSharedMemory();

// Unmaps the shared memory section and closes its handle.
VOID UnmapSharedMemory();
