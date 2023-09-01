#include <Windows.h>
#include <aclapi.h>
#include <iostream>

// Shared Memory
// https://github.com/fengjixuchui/SharedMemory-By-Frankoo/tree/master
// https://github.com/IAmTapped/Rust-Cheat-Shared-Memory-Driver/tree/main

using namespace std;

#define COMMAND_COMPLETED				0
#define COMMAND_GET_PROCESS_ID			1
#define COMMAND_GET_BASE_ADDRESS		2
#define COMMAND_GET_PEB					3
#define COMMAND_READ_PROCESS_MEMORY		4
#define COMMAND_WRITE_PROCESS_MEMORY	5
#define COMMAND_CLEAR					6

typedef struct _KM_DRIVER_COMMAND {
	// Memory
	PVOID		buffer;
	ULONG64		address;
	ULONG		size;

	// Process
	CHAR processName[32];
	HANDLE processId;

	UINT8		code;
}KM_DRIVER_COMMAND, * PKM_DRIVER_COMMAND;

// Shared memory mapping
HANDLE hMapFileW = NULL;
PKM_DRIVER_COMMAND pCommand = NULL;

bool OpenSharedMemory()
{
	hMapFileW = OpenFileMapping(
		FILE_MAP_ALL_ACCESS,		// Read/Write access
		FALSE,						// Do not inherit the name
		L"Global\\MySharedMemory"	// Name of mapping object
	);

	if (hMapFileW == INVALID_HANDLE_VALUE || hMapFileW == nullptr)
	{
		cerr << "Could not create file mapping object." << endl;
		return false;
	}

	cout << "[Completed] Shared Memory is available to use." << endl;
	cout << endl;
	return true;
}

PKM_DRIVER_COMMAND ReadSharedMemory()
{
	pCommand = (PKM_DRIVER_COMMAND)MapViewOfFile(
		hMapFileW,				// Handle to map object
		FILE_MAP_ALL_ACCESS,	// Read/Write permission
		0,
		0,
		sizeof(KM_DRIVER_COMMAND)
	);

	if (pCommand == nullptr)
	{
		cerr << "Could not map view of file." << endl;
		return nullptr;
	}

	return pCommand;
}

void CloseSharedMemory()
{
	if (pCommand != NULL)
	{
		UnmapViewOfFile(pCommand);
		pCommand = NULL;
	}

	if (hMapFileW != NULL)
	{
		CloseHandle(hMapFileW);
		hMapFileW = NULL;
	}
}

HANDLE GetProcessId(PKM_DRIVER_COMMAND pCommand, const char* processName)
{
	pCommand->code		= COMMAND_GET_PROCESS_ID;
	pCommand->processId = NULL;
	strcpy_s(pCommand->processName, processName);
	RtlCopyMemory(pCommand, pCommand, sizeof(KM_DRIVER_COMMAND));
	cout << "[+] Message has been sent to kernel (Get Process Id)." << endl;
	while (pCommand->code != COMMAND_COMPLETED || pCommand->processId == NULL);
	return pCommand->processId;
}

UINT64 GetBaseAddress(PKM_DRIVER_COMMAND pCommand, HANDLE hProcess)
{
	pCommand->code = COMMAND_GET_BASE_ADDRESS;
	pCommand->processId = hProcess;
	RtlCopyMemory(pCommand, pCommand, sizeof(KM_DRIVER_COMMAND));
	cout << "[+] Message has been sent to kernel (Get Base Address)." << endl;

	while (pCommand->code != COMMAND_COMPLETED || pCommand->buffer == nullptr);
	return (UINT64)pCommand->buffer;
}

template <typename T>
T ReadVirtualMemory(PKM_DRIVER_COMMAND pCommand, HANDLE hProcess, UINT64 address)
{
	T buffer{};

	pCommand->code = COMMAND_READ_PROCESS_MEMORY;
	pCommand->processId = hProcess;
	pCommand->address = address;
	pCommand->buffer = &buffer;
	pCommand->size = sizeof(buffer);
	RtlCopyMemory(pCommand, pCommand, sizeof(KM_DRIVER_COMMAND));
	cout << "[+] Message has been sent to kernel (Read Virtual Memory)." << endl;

	// while (pCommand->code != COMMAND_COMPLETED || pCommand->buffer == nullptr);
	Sleep(50);

	return buffer;
}

template <typename T>
void WriteVirtualMemory(PKM_DRIVER_COMMAND pCommand, HANDLE hProcess, UINT64 address, T buffer, ULONG size = 0)
{
	pCommand->code = COMMAND_WRITE_PROCESS_MEMORY;
	pCommand->processId = hProcess;
	pCommand->address = address;
	pCommand->buffer = &buffer;
	pCommand->size = size == 0 ? sizeof(buffer) : size, false;
	RtlCopyMemory(pCommand, pCommand, sizeof(KM_DRIVER_COMMAND));
	cout << "[+] Message has been sent to kernel (Write Virtual Memory)." << endl;
}

void Clear()
{
	// COMMAND_CLEAR
	pCommand->code = COMMAND_CLEAR;
	RtlCopyMemory(pCommand, pCommand, sizeof(KM_DRIVER_COMMAND));
	cout << "[+] Message has been sent to kernel (Clear)." << endl;
	while (pCommand->code != COMMAND_COMPLETED);
	cout << endl;
}

int main()
{
	if (!OpenSharedMemory())
		return EXIT_FAILURE;

	const auto pCommand = ReadSharedMemory();
	if (pCommand == nullptr)
	{
		CloseSharedMemory();
		return EXIT_FAILURE;
	}

	Clear();

	const HANDLE processId = GetProcessId(pCommand, "explorer.exe");
	cout << "[-] Process Name : " << pCommand->processName << endl;
	cout << "[-] Process ID   : " << hex << processId << endl;
	cout << endl;

	const UINT64 baseAddress = GetBaseAddress(pCommand, processId);
	cout << "[-] Process Addr : " << hex << baseAddress << endl;
	cout << endl;

	CloseSharedMemory();
	return EXIT_SUCCESS;
}
