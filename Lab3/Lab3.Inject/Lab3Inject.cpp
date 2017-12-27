// Lab3Inject.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "windows.h"
#include <iostream>

struct Params {
	char* sourceStr;
	char* destStr;
};

extern "C" typedef bool(_cdecl *ReplaceMemory)(const char *, const char *);

DWORD InjectDll(HANDLE hRemoteProcess, const wchar_t* dll_name) {
	DWORD hLibModule;
	PCWSTR lib = dll_name;
	int cb = (1 + lstrlenW(lib)) * sizeof(WCHAR);

	PWSTR pszLibFileRemote = (PWSTR)VirtualAllocEx(hRemoteProcess, nullptr, cb, MEM_COMMIT, PAGE_READWRITE);
	WriteProcessMemory(hRemoteProcess, pszLibFileRemote, (PVOID)lib, cb, nullptr);

	PTHREAD_START_ROUTINE pfnThreadRtn =(PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(TEXT("Kernel32")), "LoadLibraryW");

	HANDLE hThread = CreateRemoteThread(hRemoteProcess, nullptr, 0, pfnThreadRtn, pszLibFileRemote, 0, nullptr);
	WaitForSingleObject(hThread, INFINITE);
	GetExitCodeThread(hThread, &hLibModule);
	return hLibModule;
}

int main() {
	const wchar_t* lib_name = L"Lab3.Dll.dll";

	printf("PID: ");

	DWORD pid;
	std::cin >> pid;

	HANDLE hRemoteProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, pid);
	if (hRemoteProcess) {
		LPVOID hLibModule = (LPVOID)InjectDll(hRemoteProcess, lib_name);
	}
	else {
		printf("Process not found\r\n");
	}

	system("pause");
	
	return 0;
}