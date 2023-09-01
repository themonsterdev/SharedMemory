#include <Windows.h>
#include <aclapi.h>
#include <iostream>

// Shared Memory
// https://github.com/fengjixuchui/SharedMemory-By-Frankoo/tree/master
// https://github.com/IAmTapped/Rust-Cheat-Shared-Memory-Driver/tree/main

using namespace std;

typedef struct _KM_DRIVER_COMMAND {
	UINT8		code;

	// Memory
	PVOID		buffer;
	ULONG64		address;
	ULONG		size;

	// Process
	CHAR processName[32];
	HANDLE processId;
}KM_DRIVER_COMMAND, * PKM_DRIVER_COMMAND;

// shared memory mapping
HANDLE hMapFileW = NULL;

HANDLE GetProcessId(PKM_DRIVER_COMMAND pCommand, const char* processName)
{
	pCommand->code		= 1;
	pCommand->processId = NULL;
	strcpy_s(pCommand->processName, processName);
	RtlCopyMemory(pCommand, pCommand, sizeof(KM_DRIVER_COMMAND));
	cout << "[+] Message has been sent to kernel (Get Process Id)." << endl;

	while (pCommand->code == 1 || pCommand->processId == NULL);
	return pCommand->processId;
}

UINT64 GetBaseAddress(PKM_DRIVER_COMMAND pCommand, HANDLE hProcess)
{
	pCommand->code = 2;
	pCommand->processId = hProcess;
	RtlCopyMemory(pCommand, pCommand, sizeof(KM_DRIVER_COMMAND));
	cout << "[+] Message has been sent to kernel (Get Base Address)." << endl;

	while (pCommand->code == 2 || pCommand->buffer == nullptr);
	return (UINT64)pCommand->buffer;
}

int main()
{
	hMapFileW = OpenFileMapping(
		FILE_MAP_ALL_ACCESS,
		FALSE,
		L"Global\\MySharedMemory"
	);

	if (hMapFileW == INVALID_HANDLE_VALUE || hMapFileW == nullptr)
	{
		cerr << "Erreur lors de l'ouverture de la mémoire partagée." << endl;
		return EXIT_FAILURE;
	}

	const auto pCommand = (PKM_DRIVER_COMMAND)MapViewOfFile(
		hMapFileW,
		FILE_MAP_ALL_ACCESS,
		0,
		0,
		sizeof(KM_DRIVER_COMMAND)
	);

	if (pCommand == nullptr)
	{
		cerr << "Error MapViewOfFile(pCommand)" << endl;
		return EXIT_FAILURE;
	}

	GetProcessId(pCommand, "explorer.exe");
	cout << "[-] Process Name : " << pCommand->processName << endl;
	cout << "[-] Process ID   : " << hex << pCommand->processId << endl;
	cout << endl;

	UINT64 baseAddress = GetBaseAddress(pCommand, pCommand->processId);
	cout << "[-] Process Addr : " << hex << baseAddress << endl;

	UnmapViewOfFile(pCommand);
	CloseHandle(hMapFileW);
	return EXIT_SUCCESS;
}
