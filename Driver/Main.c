#include "Stdafx.h"
#include "Process.h"
#include "Memory.h"

// Declarations of function pointers `DriverEntry` and `DriverUnload`, which will
// be used to indicate the initialization and unloading functions of the driver.
DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;

// Preprocessor directive to specify the memory section in which the `DriverEntry`
// and `DriverUnload` functions will be placed during compilation. `INIT` for driver
// initialization code and `PAGE` for paged memory code.
#ifdef ALLOC_PRAGMA
#pragma alloc_text( INIT, DriverEntry )
#pragma alloc_text( PAGE, DriverUnload )
#endif // ALLOC_PRAGMA

// Declaration of the `g_hThread` variable, which will store the handle of the thread.
HANDLE g_hThread = NULL;

VOID DriverLoop()
{
    DbgPrint("Calling DriverLoop...");

    // Infinite loop.
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
    // Ignore the unused parameter.
    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrint("Calling DriverEntry...");

    // Associates the `DriverUnload` function with `DriverObject->DriverUnload`.
    DriverObject->DriverUnload = DriverUnload;

    NTSTATUS ntStatus = STATUS_SUCCESS;
    
    // Create shared memory
    {
        // Call the `CreateSharedMemory` function to create the shared memory.
        ntStatus = CreateSharedMemory();

        // Check for the success of shared memory creation and display a debug message in case of failure.
        if (!NT_SUCCESS(ntStatus))
        {
            DbgPrint("Error: Create Shared Memory Failed. Status: %u", ntStatus);
            return ntStatus;
        }

        DbgPrint("CreateSharedMemory was successfully created: %u", ntStatus);
    }

    // Create the initial thread
    {
        // Create a system thread that will execute the `DriverLoop` function.
        ntStatus = PsCreateSystemThread(
            &g_hThread,
            THREAD_ALL_ACCESS,
            NULL,
            NULL,
            NULL,
            (PKSTART_ROUTINE)DriverLoop,
            NULL
        );

        // Check for the success of thread creation and display a debug message in case of failure.
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
    // Ignore the unused parameter.
    UNREFERENCED_PARAMETER(DriverObject);

    DbgPrint("Calling DriverUnload...");

    // Calls the `UnmapSharedMemory` function to unmap the shared memory.
    UnmapSharedMemory();

    if (g_hThread != NULL)
    {
        ZwClose(g_hThread);
        g_hThread = NULL;
    }
}
