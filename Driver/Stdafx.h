#pragma once

#include <ntdef.h>
#include <ntifs.h>
#include <ntddk.h>
#include <windef.h>
#include <Ntstrsafe.h>

typedef struct _KM_REQUEST_GET_PROCESS_HANDLE
{
    UINT32 count;
    UINT32 count2;
}KM_REQUEST_GET_PROCESS_HANDLE, * PKM_REQUEST_GET_PROCESS_HANDLE;
