#include "Stdafx.h"
#include "Memory.h"

// Creates and configures shared memory with appropriate security settings.
NTSTATUS CreateSharedMemory()
{
    DbgPrint("Calling CreateSharedMemory...");

    NTSTATUS ntStatus = STATUS_SUCCESS;

    // Create a security descriptor for the shared memory.
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
        // Calculate the size of the discretionary access control list (DACL) including SID lengths.
        g_DaclLength = sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE) * 3
            + RtlLengthSid(SeExports->SeLocalSystemSid)
            + RtlLengthSid(SeExports->SeAliasAdminsSid)
            + RtlLengthSid(SeExports->SeWorldSid);

        // Allocate memory for the DACL.
        g_Dacl = ExAllocatePool2(POOL_FLAG_PAGED, g_DaclLength, SHARED_MEMORY_TAG);
        if (g_Dacl == NULL)
        {
            DbgPrint("ExAllocatePoolWithTag  failed  : %u", ntStatus);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        DbgPrint("ExAllocatePoolWithTag  succeed  : %u", ntStatus);
    }

    // Create an access control list (ACL) with the calculated length.
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

    // Add an access control entry (ACE) for the "World" SID with full access.
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

    // Add an ACE for the "Alias Administrators" SID with full access.
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

    // Add an ACE for the "Local System" SID with full access.
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

    // Set the DACL in the security descriptor.
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

    // Initialization of `g_SharedMemoryName` with the name of the shared memory.
    RtlInitUnicodeString(&g_SharedMemoryName, L"\\BaseNamedObjects\\MySharedMemory");

    // Initialization of object attributes with the shared memory name.
    InitializeObjectAttributes(
        &objectAttributes,
        &g_SharedMemoryName,
        OBJ_CASE_INSENSITIVE,
        NULL,
        &g_SecDescriptor
    );

    // Creation of a `LARGE_INTEGER` structure to store the size of the memory section.
    LARGE_INTEGER sectionSize = { 0 };
    sectionSize.HighPart = 0;
    sectionSize.LowPart = 1024 * 10;

    // Call to `ZwCreateSection` to create a memory section.
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

        // Check for the success of section creation and display a debug message accordingly.
        if (!NT_SUCCESS(ntStatus))
        {
            ExFreePoolWithTag(g_Dacl, SHARED_MEMORY_TAG);
            DbgPrint("Error: Create Section Failed. Status: %u", ntStatus);
            return ntStatus;
        }

        DbgPrint("ZwCreateSection was successfully created: %u", ntStatus);
    }

    // Call to `ZwMapViewOfSection` to map the memory section into the current process's address space.
    {
        // Definition of the size of the shared memory in bytes.
        SIZE_T size = 1024 * 10; 

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

        // Check for the success of mapping and display a debug message in case of failure.
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

// Reads shared memory by mapping it into the current process's address space.
NTSTATUS ReadSharedMemory()
{
    // DbgPrint("Calling ReadSharedMemory...");

    NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;

    // Check if the shared memory section handle is NULL.
    if (g_hSharedMemorySection == NULL)
        return ntStatus;

    // If the shared memory pointer is not NULL, unmap the shared memory.
    if (g_SharedMemoryPointer != NULL)
    {
        ZwUnmapViewOfSection(NtCurrentProcess(), g_SharedMemoryPointer);
        g_SharedMemoryPointer = NULL;
    }

    // Define the size of the memory section view in bytes.
    SIZE_T ulViewSize = 1024 * 10;

    // Call `ZwMapViewOfSection` to map the memory section into the current process's address space.
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

// Unmaps the shared memory section and closes its handle.
VOID UnmapSharedMemory()
{
    DbgPrint("Calling UnmapSharedMemory...");

    // If the shared memory pointer is not null, unmaps the shared memory.
    if (g_SharedMemoryPointer != NULL)
    {
        ZwUnmapViewOfSection(NtCurrentProcess(), g_SharedMemoryPointer);
        g_SharedMemoryPointer = NULL;
    }

    // If the shared memory section handle is not null, closes it.
    if (g_hSharedMemorySection)
    {
        ZwClose(g_hSharedMemorySection);
        g_hSharedMemorySection = NULL;
    }
}
