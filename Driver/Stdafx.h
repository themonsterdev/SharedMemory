#pragma once

#include <ntdef.h>
#include <ntifs.h>
#include <ntddk.h>
#include <windef.h>
#include <Ntstrsafe.h>

typedef struct _KM_REQUEST_GET_PROCESS_HANDLE
{
    int count;
}KM_REQUEST_GET_PROCESS_HANDLE, * PKM_REQUEST_GET_PROCESS_HANDLE;
