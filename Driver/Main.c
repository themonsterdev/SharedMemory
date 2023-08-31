#include "Stdafx.h"
#include "Process.h"
#include "Memory.h"

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;

#ifdef ALLOC_PRAGMA
#pragma alloc_text( INIT, DriverEntry )
#pragma alloc_text( PAGE, DriverUnload )
#endif // ALLOC_PRAGMA

// Thread variables
HANDLE g_hThread = NULL;

VOID DriverLoop()
{
    DbgPrint("Calling DriverLoop...");

    while (TRUE)
    {
        NTSTATUS ntStatus = ReadSharedMemory();

        if (NT_SUCCESS(ntStatus) && g_SharedMemoryPointer != NULL)
        {
            PKM_REQUEST_GET_PROCESS_HANDLE pRequest = (PKM_REQUEST_GET_PROCESS_HANDLE)g_SharedMemoryPointer;
            pRequest->count = 8;

            memcpy(g_SharedMemoryPointer, pRequest, sizeof(KM_REQUEST_GET_PROCESS_HANDLE));
        }

        break;
    }
}

NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
) {
    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrint("Calling DriverEntry...");

    DriverObject->DriverUnload = DriverUnload;

    NTSTATUS ntStatus = STATUS_SUCCESS;
    
    // Create shared memory
    {
        ntStatus = CreateSharedMemory();

        if (!NT_SUCCESS(ntStatus))
        {
            DbgPrint("Error: Create Shared Memory Failed. Status: %u", ntStatus);
            return ntStatus;
        }

        DbgPrint("CreateSharedMemory was successfully created: %u", ntStatus);
    }

    // Create the initial thread
    {
        ntStatus = PsCreateSystemThread(
            &g_hThread,
            THREAD_ALL_ACCESS,
            NULL,
            NULL,
            NULL,
            (PKSTART_ROUTINE)DriverLoop,
            NULL
        );

        if (!NT_SUCCESS(ntStatus))
        {
            DbgPrint("Error: Create Thread Failed. Status: %u", ntStatus);
            return ntStatus;
        }

        DbgPrint("PsCreateSystemThread was successfully created: %u", ntStatus);
    }

    DbgPrint("DriverEntry was successfully created: %u", ntStatus);

    return ntStatus;
}

VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    DbgPrint("Calling DriverUnload...");

    UnmapSharedMemory();

    if (g_hThread != NULL)
    {
        ZwClose(g_hThread);
        g_hThread = NULL;
    }
}
