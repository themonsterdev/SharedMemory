#include "Stdafx.h"
#include "Memory.h"

NTSTATUS CreateSharedMemory()
{
    DbgPrint("Calling CreateSharedMemory...");

    NTSTATUS ntStatus = STATUS_SUCCESS;

    {
        ntStatus = RtlCreateSecurityDescriptor(&g_SecDescriptor, SECURITY_DESCRIPTOR_REVISION);
        if (!NT_SUCCESS(ntStatus))
        {
            DbgPrint("RtlCreateSecurityDescriptor failed: %u", ntStatus);
            return ntStatus;
        }
        DbgPrint("RtlCreateSecurityDescriptor was successfully created : %u", ntStatus);
    }

    {
        g_DaclLength = sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE) * 3
            + RtlLengthSid(SeExports->SeLocalSystemSid)
            + RtlLengthSid(SeExports->SeAliasAdminsSid)
            + RtlLengthSid(SeExports->SeWorldSid);

        g_Dacl = ExAllocatePool2(POOL_FLAG_PAGED, g_DaclLength, SHARED_MEMORY_TAG);
        if (g_Dacl == NULL)
        {
            DbgPrint("ExAllocatePoolWithTag  failed  : %u", ntStatus);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        DbgPrint("ExAllocatePoolWithTag  succeed  : %u", ntStatus);
    }

    {
        ntStatus = RtlCreateAcl(g_Dacl, g_DaclLength, ACL_REVISION);

        if (!NT_SUCCESS(ntStatus))
        {
            ExFreePoolWithTag(g_Dacl, SHARED_MEMORY_TAG);
            DbgPrint("RtlCreateAcl  failed  : %u", ntStatus);
            return ntStatus;
        }

        DbgPrint("RtlCreateAcl  succeed  : %u", ntStatus);
    }

    {
        ntStatus = RtlAddAccessAllowedAce(g_Dacl, ACL_REVISION, FILE_ALL_ACCESS, SeExports->SeWorldSid);

        if (!NT_SUCCESS(ntStatus))
        {
            ExFreePoolWithTag(g_Dacl, SHARED_MEMORY_TAG);
            DbgPrint("RtlAddAccessAllowedAce SeWorldSid failed  : %u", ntStatus);
            return ntStatus;
        }

        DbgPrint("RtlAddAccessAllowedAce SeWorldSid succeed  : %u", ntStatus);
    }

    {
        ntStatus = RtlAddAccessAllowedAce(
            g_Dacl,
            ACL_REVISION,
            FILE_ALL_ACCESS,
            SeExports->SeAliasAdminsSid);

        if (!NT_SUCCESS(ntStatus))
        {
            ExFreePoolWithTag(g_Dacl, SHARED_MEMORY_TAG);
            DbgPrint("RtlAddAccessAllowedAce SeAliasAdminsSid failed  : %u", ntStatus);
            return ntStatus;
        }

        DbgPrint("RtlAddAccessAllowedAce SeAliasAdminsSid succeed  : %u", ntStatus);
    }

    {
        ntStatus = RtlAddAccessAllowedAce(
            g_Dacl,
            ACL_REVISION,
            FILE_ALL_ACCESS,
            SeExports->SeLocalSystemSid);

        if (!NT_SUCCESS(ntStatus))
        {
            ExFreePoolWithTag(g_Dacl, SHARED_MEMORY_TAG);
            DbgPrint("RtlAddAccessAllowedAce SeLocalSystemSid failed  : %u", ntStatus);
            return ntStatus;
        }

        DbgPrint("RtlAddAccessAllowedAce SeLocalSystemSid succeed  : %u", ntStatus);
    }

    {
        ntStatus = RtlSetDaclSecurityDescriptor(
            &g_SecDescriptor,
            TRUE,
            g_Dacl,
            FALSE);

        if (!NT_SUCCESS(ntStatus))
        {
            ExFreePoolWithTag(g_Dacl, SHARED_MEMORY_TAG);
            DbgPrint("RtlSetDaclSecurityDescriptor failed  : %u", ntStatus);
            return ntStatus;
        }

        DbgPrint("RtlSetDaclSecurityDescriptor  succeed  : %u", ntStatus);
    }

    OBJECT_ATTRIBUTES objectAttributes = { 0 };
    RtlInitUnicodeString(&g_SharedMemoryName, L"\\BaseNamedObjects\\MySharedMemory");

    InitializeObjectAttributes(
        &objectAttributes,
        &g_SharedMemoryName,
        OBJ_CASE_INSENSITIVE,
        NULL,
        &g_SecDescriptor
    );

    LARGE_INTEGER sectionSize = { 0 };
    sectionSize.HighPart = 0;
    sectionSize.LowPart = 1024 * 10;

    {
        ntStatus = ZwCreateSection(
            &g_hSharedMemorySection,
            SECTION_ALL_ACCESS,
            &objectAttributes,
            &sectionSize,
            PAGE_READWRITE,
            SEC_COMMIT,
            NULL
        );

        if (!NT_SUCCESS(ntStatus))
        {
            ExFreePoolWithTag(g_Dacl, SHARED_MEMORY_TAG);
            DbgPrint("Error: Create Section Failed. Status: %u", ntStatus);
            return ntStatus;
        }

        DbgPrint("ZwCreateSection was successfully created: %u", ntStatus);
    }

    {
        // My code starts from here xD
        SIZE_T size = 1024 * 10;   // &g_hSharedMemorySection before was here i guess i am correct 

        ntStatus = ZwMapViewOfSection(
            g_hSharedMemorySection,
            NtCurrentProcess(),
            &g_SharedMemoryPointer,
            0,
            size,
            NULL,
            &size,
            ViewShare,
            0,
            PAGE_READWRITE | PAGE_NOCACHE
        );

        if (!NT_SUCCESS(ntStatus))
        {
            ZwClose(g_hSharedMemorySection);
            ExFreePoolWithTag(g_Dacl, SHARED_MEMORY_TAG);
            DbgPrint("Map View Section Failed. Status: %u", ntStatus);
            return ntStatus;
        }

        DbgPrint("ZwMapViewOfSection was successfully created: %u", ntStatus);
    }

    DbgPrint("CreateSharedMemory called finished");

    return ntStatus;
}

NTSTATUS ReadSharedMemory()
{
    // DbgPrint("Calling ReadSharedMemory...");

    NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;

    if (g_hSharedMemorySection == NULL)
        return ntStatus;

    if (g_SharedMemoryPointer != NULL)
    {
        ZwUnmapViewOfSection(NtCurrentProcess(), g_SharedMemoryPointer);
        g_SharedMemoryPointer = NULL;
    }

    SIZE_T ulViewSize = 1024 * 10;

    return ZwMapViewOfSection(
        g_hSharedMemorySection,
        NtCurrentProcess(),
        &g_SharedMemoryPointer,
        0,
        ulViewSize,
        NULL,
        &ulViewSize,
        ViewShare,
        0,
        PAGE_READWRITE | PAGE_NOCACHE
    );
}

VOID UnmapSharedMemory()
{
    DbgPrint("Calling UnmapSharedMemory...");

    // Free Section Memory
    if (g_SharedMemoryPointer != NULL)
    {
        ZwUnmapViewOfSection(NtCurrentProcess(), g_SharedMemoryPointer);
        g_SharedMemoryPointer = NULL;
    }

    // Closing Handle
    if (g_hSharedMemorySection)
    {
        ZwClose(g_hSharedMemorySection);
        g_hSharedMemorySection = NULL;
    }
}
