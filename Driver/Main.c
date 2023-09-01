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

typedef struct _PiDDBCacheEntry
{
    LIST_ENTRY		List;
    UNICODE_STRING	DriverName;
    ULONG			TimeDateStamp;
    NTSTATUS		LoadStatus;
    char			_0x0028[16];
}PiDDBCacheEntry;

UINT64 Dereference(UINT64 address, UINT32 offset)
{
    if (address == 0)
        return 0;
    return address + (int)((*(int*)(address + offset) + offset) + sizeof(int));
}

BOOL CleanPiDDBCacheTable()
{
    const PVOID base = GetSystemModuleBase("ntoskrnl.exe");
    if (base == 0)
    {
        DbgPrint("Failed to find \"ntoskrnl.exe\"!");
        return FALSE;
    }

    // 48 8d 0d ?? ?? ?? ?? e8 ?? ?? ?? ?? 3d ?? ?? ?? ?? 0f 83
    const PVOID PiDDBCacheTablePtr = FindPatternImage(
        base,
        "\x48\x8d\x0d\x00\x00\x00\x00\xe8\x00\x00\x00\x00\x3d\x00\x00\x00\x00\x0f\x83",
        "xxx????x????x????xx"
    );
    if (PiDDBCacheTablePtr == 0)
    {
        DbgPrint("Failed to find \"PiDDBCacheTable\"!");
        return FALSE;
    }

    const PRTL_AVL_TABLE PiDDBCacheTable = (PRTL_AVL_TABLE)Dereference((UINT64)PiDDBCacheTablePtr, 3);
    if (!PiDDBCacheTable)
    {
        DbgPrint("Failed to dereference \"PiDDBCacheTable\"!");
        return FALSE;
    }

    UINT64 entry_address = (UINT64)(PiDDBCacheTable->BalancedRoot.RightChild) + sizeof(RTL_BALANCED_LINKS);

    PiDDBCacheEntry* entry = (PiDDBCacheEntry*)(entry_address);

    if (entry->TimeDateStamp == 0x57CD1415 || entry->TimeDateStamp == 0x5284EAC3)
    {
        entry->TimeDateStamp = 0x54EAC3;
        entry->DriverName = (UNICODE_STRING)RTL_CONSTANT_STRING(L"monitor.sys");
    }

    ULONG count = 0;
    for (PLIST_ENTRY link = entry->List.Flink; link != entry->List.Blink; link = link->Flink, count++)
    {
        PiDDBCacheEntry* cache_entry = (PiDDBCacheEntry*)(link);

        if (cache_entry->TimeDateStamp == 0x57CD1415 || cache_entry->TimeDateStamp == 0x5284EAC3)
        {
            cache_entry->TimeDateStamp = 0x54EAC4 + count;
            cache_entry->DriverName = (UNICODE_STRING)RTL_CONSTANT_STRING(L"monitor.sys");
        }
    }

    DbgPrint("Success Clean PiDDBCacheTable.");
    return TRUE;
}

BOOL CleanUnloadedDrivers()
{
    PVOID ntoskrnlBase = GetSystemModuleBase("ntoskrnl.exe");

    if (ntoskrnlBase <= 0)
    {
        DbgPrint("Failed to find ntoskrnl.exe!");
        return FALSE;
    }

    // 4C 8B ?? ?? ?? ?? ?? 4C 8B C9 4D 85 ?? 74
    const PVOID mmUnloadedDriversPtr = FindPatternImage(
        ntoskrnlBase,
        "\x4C\x8B\x00\x00\x00\x00\x00\x4C\x8B\xC9\x4D\x85\x00\x74",
        "xx?????xxxxx?x"
    );

    if (mmUnloadedDriversPtr == 0)
    {
        DbgPrint("Failed to find CleanUnloadedDrivers->mmUnloadedDriversPtr!");
        return FALSE;
    }

    UINT64 mmUnloadedDrivers = Dereference((UINT64)mmUnloadedDriversPtr, 3);
    memset(*(UINT64**)mmUnloadedDrivers, 0, 0x7D0);

    DbgPrint("Success clean unloaded drivers.");
    return TRUE;
}

VOID DriverLoop()
{
    DbgPrint("Calling DriverLoop...");



    __try
    {
        // Infinite loop.
        while (g_hSharedMemorySection != NULL)
        {
            NTSTATUS ntStatus = ReadSharedMemory();

            if (NT_SUCCESS(ntStatus) && g_SharedMemoryPointer != NULL)
            {
                PKM_DRIVER_COMMAND pCommand = (PKM_DRIVER_COMMAND)g_SharedMemoryPointer;

                if (pCommand->code == COMMAND_GET_PROCESS_ID)
                {
                    pCommand->code = COMMAND_COMPLETED;

                    // DbgPrint("PKM_DRIVER_COMMAND : Get Process Name (%s)", pCommand->processName);

                    pCommand->processId = GetProcessId(pCommand->processName);

                    memcpy(g_SharedMemoryPointer, pCommand, sizeof(KM_DRIVER_COMMAND));
                }
                else if (pCommand->code == COMMAND_GET_BASE_ADDRESS)
                {
                    pCommand->code = COMMAND_COMPLETED;

                    // DbgPrint("PKM_DRIVER_COMMAND : Get Base Address");

                    pCommand->buffer = (PVOID)GetModuleBaseX64(pCommand->processId);

                    memcpy(g_SharedMemoryPointer, pCommand, sizeof(KM_DRIVER_COMMAND));
                }
                else if (pCommand->code == COMMAND_READ_PROCESS_MEMORY)
                {
                    pCommand->code = COMMAND_COMPLETED;

                    // DbgPrint("PKM_DRIVER_COMMAND : Read Virtual Memory");

                    ReadVirtualMemory(pCommand->processId, (PVOID)pCommand->address, pCommand->buffer, pCommand->size);

                    memcpy(g_SharedMemoryPointer, pCommand, sizeof(KM_DRIVER_COMMAND));
                }
                else if (pCommand->code == COMMAND_WRITE_PROCESS_MEMORY)
                {
                    pCommand->code = COMMAND_COMPLETED;

                    // DbgPrint("PKM_DRIVER_COMMAND : Write Virtual Memory");

                    WriteVirtualMemory(pCommand->processId, pCommand->buffer, (PVOID)pCommand->address, pCommand->size);

                    memcpy(g_SharedMemoryPointer, pCommand, sizeof(KM_DRIVER_COMMAND));
                }
                else if (pCommand->code == COMMAND_CLEAR)
                {
                    pCommand->code = COMMAND_COMPLETED;

                    // DbgPrint("PKM_DRIVER_COMMAND : Clear");

                    CleanPiDDBCacheTable();
                    CleanUnloadedDrivers();
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
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
