#include <ntifs.h>
#include <ntddk.h>
#include "Driver.h"
#include "Common.h"
#include "ProcessWatcher.h"
#include "DriverFunctions.h"

PDRIVER_OBJECT gDriverObject = NULL; 

typedef struct _SYSTEM_THREAD_INFORMATION {
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER CreateTime;
	ULONG WaitTime;
	PVOID StartAddress;
	CLIENT_ID ClientId;
	KPRIORITY Priority;
	LONG BasePriority;
	ULONG ContextSwitches;
	ULONG ThreadState;
	KWAIT_REASON WaitReason;
}SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFO {
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER WorkingSetPrivateSize;
	ULONG HardFaultCount;
	ULONG NumberOfThreadsHighWatermark;
	ULONGLONG CycleTime;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	ULONG_PTR UniqueProcessKey;
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER ReadOperationCount;
	LARGE_INTEGER WriteOperationCount;
	LARGE_INTEGER OtherOperationCount;
	LARGE_INTEGER ReadTransferCount;
	LARGE_INTEGER WriteTransferCount;
	LARGE_INTEGER OtherTransferCount;
	SYSTEM_THREAD_INFORMATION Threads[1];
}SYSTEM_PROCESS_INFO, *PSYSTEM_PROCESS_INFO;

typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;

	union {
		LIST_ENTRY HashLinks;

		struct {
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};

	union {
		ULONG TimeDateStamp;
		PVOID LoadedImports;
	};

	struct _ACTIVATION_CONTEXT * EntryPointActivationContext;
	PVOID PatchInformation;
	LIST_ENTRY ForwarderLinks;
	LIST_ENTRY ServiceTagLinks;
	LIST_ENTRY StaticLinks;
}LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA {
	ULONG Length;
	UCHAR Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID EntryInProgress;
}PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _IMAGE_DOS_HEADER {
	USHORT e_magic;
	USHORT e_cblp;
	USHORT e_cp;
	USHORT e_crlc;
	USHORT e_cparhdr;
	USHORT e_minalloc;
	USHORT e_maxalloc;
	USHORT e_ss;
	USHORT e_sp;
	USHORT e_csum;
	USHORT e_ip;
	USHORT e_cs;
	USHORT e_lfarlc;
	USHORT e_ovno;
	USHORT e_res[4];
	USHORT e_oemid;
	USHORT e_oeminfo;
	USHORT e_res2[10];
	LONG e_lfanew;
}IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
	ULONG VirtualAddress;
	ULONG Size;
}IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_FILE_HEADER {
	USHORT Machine;
	USHORT NumberOfSections;
	ULONG TimeDateStamp;
	ULONG PointerToSymbolTable;
	ULONG NumberOfSymbols;
	USHORT SizeOfOptionalHeader;
	USHORT Characteristics;
}IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_OPTIONAL_HEADER {
	USHORT Magic;
	UCHAR MajorLinkerVersion;
	UCHAR MinorLinkerVersion;
	ULONG SizeOfCode;
	ULONG SizeOfInitializedData;
	ULONG SizeOfUninitializedData;
	ULONG AddressOfEntryPoint;
	ULONG BaseOfCode;
	ULONG BaseOfData;
	ULONG ImageBase;
	ULONG SectionAlignment;
	ULONG FileAlignment;
	USHORT MajorOperatingSystemVersion;
	USHORT MinorOperatingSystemVersion;
	USHORT MajorImageVersion;
	USHORT MinorImageVersion;
	USHORT MajorSubsystemVersion;
	USHORT MinorSubsystemVersion;
	ULONG Win32VersionValue;
	ULONG SizeOfImage;
	ULONG SizeOfHeaders;
	ULONG CheckSum;
	USHORT Subsystem;
	USHORT DllCharacteristics;
	ULONG SizeOfStackReserve;
	ULONG SizeOfStackCommit;
	ULONG SizeOfHeapReserve;
	ULONG SizeOfHeapCommit;
	ULONG LoaderFlags;
	ULONG NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[16];
}IMAGE_OPTIONAL_HEADER, *PIMAGE_OPTIONAL_HEADER;

typedef struct _IMAGE_NT_HEADERS {
	ULONG Signature;
	IMAGE_FILE_HEADER FileHeader;
	IMAGE_OPTIONAL_HEADER OptionalHeader;
}IMAGE_NT_HEADERS, *PIMAGE_NT_HEADERS;

typedef struct _IMAGE_EXPORT_DIRECTORY {
	ULONG Characteristics;
	ULONG TimeDateStamp;
	USHORT MajorVersion;
	USHORT MinorVersion;
	ULONG Name;
	ULONG Base;
	ULONG NumberOfFunctions;
	ULONG NumberOfNames;
	ULONG AddressOfFunctions;
	ULONG AddressOfNames;
	ULONG AddressOfNameOrdinals;
}IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;

#define IMAGE_DIRECTORY_ENTRY_EXPORT 0

typedef struct _STARTUPINFOA {
	ULONG cb;
	LPSTR lpReserved;
	LPSTR lpDesktop;
	LPSTR lpTitle;
	ULONG dwX;
	ULONG dwY;
	ULONG dwXSize;
	ULONG dwYSize;
	ULONG dwXCountChars;
	ULONG dwYCountChars;
	ULONG dwFillAttribute;
	ULONG dwFlags;
	USHORT wShowWindow;
	USHORT cbReserved2;
	PUCHAR lpReserved2;
	HANDLE hStdInput;
	HANDLE hStdOutput;
	HANDLE hStdError;
}STARTUPINFOA, *LPSTARTUPINFOA;

typedef struct _PROCESS_INFORMATION {
	HANDLE hProcess;
	HANDLE hThread;
	ULONG dwProcessId;
	ULONG dwThreadId;
}PROCESS_INFORMATION, *LPPROCESS_INFORMATION;

extern NTSTATUS ZwQuerySystemInformation(ULONG InfoClass, PVOID Buffer, ULONG Length, PULONG ReturnLength);
extern PPEB PsGetProcessPeb(PEPROCESS Process);

typedef enum _KAPC_ENVIRONMENT {
	OriginalApcEnvironment,
	AttachedApcEnvironment,
	CurrentApcEnvironment,
	InsertApcEnvironment
}KAPC_ENVIRONMENT, *PKAPC_ENVIRONMENT;

typedef VOID(NTAPI *PKNORMAL_ROUTINE)(
	PVOID NormalContext,
	PVOID SystemArgument1,
	PVOID SystemArgument2
	);

typedef VOID KKERNEL_ROUTINE(
	PRKAPC Apc,
	PKNORMAL_ROUTINE *NormalRoutine,
	PVOID *NormalContext,
	PVOID *SystemArgument1,
	PVOID *SystemArgument2
);

typedef KKERNEL_ROUTINE(NTAPI *PKKERNEL_ROUTINE);

typedef VOID(NTAPI *PKRUNDOWN_ROUTINE)(
	PRKAPC Apc
	);

extern void KeInitializeApc(
	PRKAPC Apc,
	PRKTHREAD Thread,
	KAPC_ENVIRONMENT Environment,
	PKKERNEL_ROUTINE KernelRoutine,
	PKRUNDOWN_ROUTINE RundownRoutine,
	PKNORMAL_ROUTINE NormalRoutine,
	KPROCESSOR_MODE ProcessorMode,
	PVOID NormalContext
);

extern BOOLEAN KeInsertQueueApc(
	PRKAPC Apc,
	PVOID SystemArgument1,
	PVOID SystemArgument2,
	KPRIORITY Increment
);

typedef int(*pCreateProcessA)(
	LPCSTR lpApplicationName,
	LPSTR lpCommandLine,
	PVOID lpProcessAttributes,
	PVOID lpThreadAttributes,
	int bInheritHandles,
	ULONG dwCreationFlags,
	PVOID lpEnvironment,
	LPCTSTR lpCurrentDirectory,
	LPSTARTUPINFOA lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
	);

typedef struct _KCREATE_PROCESS {
	LPSTR CommandLine;
	pCreateProcessA CreateProcessA;
	STARTUPINFOA StartupInfo;
	PROCESS_INFORMATION ProcessInfo;
	ULONG Completed;
}KCREATE_PROCESS, *PKCREATE_PROCESS;

typedef struct _CREATE_PROCESS_INFO {
	LPSTR CommandLine;
	ULONG System;
}CREATE_PROCESS_INFO, *PCREATE_PROCESS_INFO;

ULONG ApcStateOffset;

VOID UnloadRoutine(IN PDRIVER_OBJECT DriverObject);

VOID NotifyRoutine(
	HANDLE ParentId,
	HANDLE ProcessId,
	BOOLEAN Create
);

extern UCHAR *PsGetProcessImageFileName(IN PEPROCESS);

//extern NTSTATUS PsLookupProcessByProcessId(HANDLE ProcessId, PEPROCESS *Process);

void NTAPI CreateProcessApc(PVOID NormalContext, PVOID SystemArgument1, PVOID SystemArgument2) {

	PKCREATE_PROCESS CreateProcess = (PKCREATE_PROCESS)NormalContext;

	CreateProcess->CreateProcessA(NULL, CreateProcess->CommandLine,
		NULL, NULL, FALSE, 0, NULL, NULL, &CreateProcess->StartupInfo, &CreateProcess->ProcessInfo);
	CreateProcess->Completed = TRUE;
}

void NTAPI KernelRoutine(PKAPC apc, PKNORMAL_ROUTINE* NormalRoutine, PVOID* NormalContext, PVOID* SystemArgument1, PVOID* SystemArgument2) {
	ExFreePool(apc);
}


ULONG CreatedProcessID = 0;

BOOLEAN CreateProcessFromKernel(LPSTR MyCommandLineStr) {
	PEPROCESS Process;
	PETHREAD Thread;

	PKCREATE_PROCESS CreateProcess;
	ULONG i, size, CommandLineLen, ApcCodeSize;

	LPSTR CommandLine;
	LARGE_INTEGER delay;

	PKAPC_STATE ApcState;
	PKAPC apc;

	PVOID buffer, Kernel32;
	PSYSTEM_PROCESS_INFO pSpi;

	PPEB_LDR_DATA Ldr;
	PLDR_DATA_TABLE_ENTRY ModuleEntry;

	PIMAGE_DOS_HEADER pIDH;
	PIMAGE_NT_HEADERS pINH;
	PIMAGE_EXPORT_DIRECTORY pIED;

	PULONG Functions, Names;
	PUSHORT Ordinals;

	BOOLEAN Found = FALSE;

	buffer = ExAllocatePool(NonPagedPool, 1024 * 1024);

	if (!buffer) {
		DbgPrint("ERROR !!! Allocated buffer for all processes information");
		return FALSE;
	}

	DbgPrint("Allocated buffer for all processes information");

	if (!NT_SUCCESS(ZwQuerySystemInformation(5, buffer, 1024 * 1024, NULL))) {
		DbgPrint("ERROR !!! retrive processes information");
		ExFreePool(buffer);
		return FALSE;
	}

	DbgPrint("Processes information retrieved");
	pSpi = (PSYSTEM_PROCESS_INFO)buffer;

	// Find a target process

	while (pSpi->NextEntryOffset) {
		if (pSpi->ImageName.Buffer) {
			if (!_wcsicmp(L"explorer.exe", pSpi->ImageName.Buffer)) {
				Found = TRUE;
				break;
			}
		}

		pSpi = (PSYSTEM_PROCESS_INFO)((PUCHAR)pSpi + pSpi->NextEntryOffset);
	}

	if (!Found) {
		DbgPrint("Explorer process not found!");
		ExFreePool(buffer);
		return FALSE;
	}

	DbgPrint("Target process found. PID: %d", pSpi->UniqueProcessId);

	__try {
		// Allocate buffer to store the command line because we will not able to access when we attached to the target process

		CommandLineLen = strlen(MyCommandLineStr) + 1;
		CommandLine = (LPSTR)ExAllocatePool(NonPagedPool, CommandLineLen);

		if (!CommandLine) {
			ExFreePool(buffer);
			return FALSE;
		}

		strcpy(CommandLine, MyCommandLineStr); // Copy the command line into the buffer
	}

	__except (EXCEPTION_EXECUTE_HANDLER) {
		ExFreePool(buffer);
		return FALSE;
	}

	//gets EPROCESS structure of the process
	if (!NT_SUCCESS(PsLookupProcessByProcessId(pSpi->UniqueProcessId, &Process))) {
		DbgPrint("ERROR !!! get EPROCESS");
		return FALSE;
	}

	// gets ETHREAD structure of the thread.
	if (!NT_SUCCESS(PsLookupThreadByThreadId(pSpi->Threads[0].ClientId.UniqueThread, &Thread))) {
		DbgPrint("ERROR !!! get ETHREAD");
		return FALSE;
	}


	//	int MyInt = -5000;
	//	KeDelayExecutionThread(KernelMode, FALSE, MyInt);

	ExFreePool(buffer);
	KeAttachProcess(Process); // Attach to the target process

	ApcCodeSize = (ULONG)CreateProcessFromKernel - (ULONG)CreateProcessApc; // Calculate the code size

	CreateProcess = NULL;
	//size of all memory to allocate in target process
	size = sizeof(KCREATE_PROCESS) + ApcCodeSize + CommandLineLen;

	if (!NT_SUCCESS(ZwAllocateVirtualMemory(NtCurrentProcess(), (PVOID*)&CreateProcess, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE))) {
		DbgPrint("ERROR !!! Failed to allocate all memory");
		KeDetachProcess();
		ExFreePool(CommandLine);

		ObDereferenceObject(Process);
		ObDereferenceObject(Thread);

		return FALSE;
	}

	DbgPrint("Memory allocated");

	// Get the PEB address and read the loader data

	Ldr = *(PPEB_LDR_DATA*)((PUCHAR)PsGetProcessPeb(Process) + 0xc);
	ModuleEntry = CONTAINING_RECORD(Ldr->InMemoryOrderModuleList.Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks.Flink); // Process's EXE

	ModuleEntry = CONTAINING_RECORD(ModuleEntry->InMemoryOrderLinks.Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks.Flink); // ntdll.dll (not used)
	ModuleEntry = CONTAINING_RECORD(ModuleEntry->InMemoryOrderLinks.Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks.Flink); // kernel32.dll

	Kernel32 = ModuleEntry->DllBase;
	DbgPrint("kernel32.dll base: %#x", Kernel32);

	pIDH = (PIMAGE_DOS_HEADER)Kernel32;
	pINH = (PIMAGE_NT_HEADERS)((PUCHAR)Kernel32 + pIDH->e_lfanew);
	pIED = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)Kernel32 + pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	Functions = (PULONG)((PUCHAR)Kernel32 + pIED->AddressOfFunctions);
	Names = (PULONG)((PUCHAR)Kernel32 + pIED->AddressOfNames);

	Ordinals = (PUSHORT)((PUCHAR)Kernel32 + pIED->AddressOfNameOrdinals);

	// Parse the export table to locate CreateProcessA

	for (i = 0; i<pIED->NumberOfFunctions; i++) {
		if (!strcmp((char*)Kernel32 + Names[i], "CreateProcessA")) {
			CreateProcess->CreateProcessA = (pCreateProcessA)((PUCHAR)Kernel32 + Functions[Ordinals[i]]);
			break;
		}
	}

	DbgPrint("CreateProcessA address: %#x", CreateProcess->CreateProcessA);
	CreateProcess->CommandLine = (LPSTR)CreateProcess + sizeof(KCREATE_PROCESS) + ApcCodeSize;

	strcpy(CreateProcess->CommandLine, CommandLine); // Copy the command line into user mode memory
	memcpy((PKCREATE_PROCESS)(CreateProcess + 1), CreateProcessApc, ApcCodeSize); // Copy the code into user mode memory

	ExFreePool(CommandLine); // Free the command line buffer
	apc = (PKAPC)ExAllocatePool(NonPagedPool, sizeof(KAPC)); // Allocate the APC object

	DbgPrint("Allocate the APC object");

	if (!apc) {
		DbgPrint("ERROR !!! Allocate the APC object");
		size = 0;

		ZwFreeVirtualMemory(NtCurrentProcess(), (PVOID*)&CreateProcess, &size, MEM_RELEASE);
		KeDetachProcess();

		ObDereferenceObject(Process);
		ObDereferenceObject(Thread);

		return FALSE;
	}

	ApcState = (PKAPC_STATE)((PUCHAR)Thread + ApcStateOffset); // Calculate the location of ApcState
	ApcState->UserApcPending = TRUE; // Force the thread to execute APC

	DbgPrint("Location of ApcState");

	// Initialize the APC
	KeInitializeApc(apc, Thread, OriginalApcEnvironment, KernelRoutine, NULL, (PKNORMAL_ROUTINE)(PKCREATE_PROCESS)(CreateProcess + 1), UserMode, CreateProcess);

	DbgPrint("Initialized the APC");

	// Insert the APC

	if (!KeInsertQueueApc(apc, NULL, NULL, IO_NO_INCREMENT)) {
		ExFreePool(apc);
		size = 0;

		DbgPrint("ERROR !!! Insert the APC");

		ZwFreeVirtualMemory(NtCurrentProcess(), (PVOID*)&CreateProcess, &size, MEM_RELEASE);
		KeDetachProcess();

		ObDereferenceObject(Process);
		ObDereferenceObject(Thread);

		return FALSE;
	}

	DbgPrint("Inserted the APC");

	delay.QuadPart = (__int64)-100 * 10000;

	DbgPrint("Start Waiting");
	while (!CreateProcess->Completed) {
		KeDelayExecutionThread(KernelMode, FALSE, &delay); // Wait for the APC to complete
	}
	DbgPrint("Waiting Finish");

	CreatedProcessID = CreateProcess->ProcessInfo.dwProcessId;

	DbgPrint("Created Process ID = %u", CreatedProcessID);

	size = 0;

	ZwFreeVirtualMemory(NtCurrentProcess(), (PVOID*)&CreateProcess, &size, MEM_RELEASE); // Free the allocated memory
	KeDetachProcess(); // Detach from the target process

	ObDereferenceObject(Process); // Dereference the process object
	ObDereferenceObject(Thread); // Dereference the thread object

	return TRUE;
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT object,
	IN PUNICODE_STRING registryPath) {

	UNICODE_STRING nameString, linkString;
	PDEVICE_OBJECT deviceObject;
	NTSTATUS status = STATUS_SUCCESS;
	PVOID driverObjectExtension;
	PEPROCESS Process;
	PETHREAD Thread;

	PKAPC_STATE ApcState;
	PULONG ptr;
	ULONG i;
	
	UNREFERENCED_PARAMETER(object);
	UNREFERENCED_PARAMETER(registryPath);

	gDriverObject = object;
	gDriverObject->DriverUnload = ProcessWatcherUnload;

	RtlInitUnicodeString(&nameString, L"\\Device\\"DRIVER_NAME);
	status = IoCreateDevice(gDriverObject, 0, &nameString, FILE_DEVICE_UNKNOWN, 0, FALSE, &deviceObject);
	ASSERT(NT_SUCCESS(status));

	deviceObject->Flags |= DO_DIRECT_IO;

	RtlInitUnicodeString(&linkString, L"\\DosDevices\\"DRIVER_NAME);
	status = IoCreateSymbolicLink(&linkString, &nameString);
	ASSERT(NT_SUCCESS(status));

	gDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = ProcessDefenderDispatchIoctl;
	gDriverObject->MajorFunction[IRP_MJ_CREATE] = ProcessDefenderDispatchCreate;
	gDriverObject->MajorFunction[IRP_MJ_CLOSE] = ProcessDefenderDispatchClose;

	status = IoAllocateDriverObjectExtension(object, (PVOID)PROCESSWATCHER_DRIVER_OBJECT_EXTENSION_ID, sizeof(PROCESS_WATCHER_OBJECT), &driverObjectExtension);
	ASSERT(NT_SUCCESS(status));

	Process = PsGetCurrentProcess();
	Thread = PsGetCurrentThread();

	ptr = (PULONG)Thread;

	// Scan for the process object's address

	for (i = 0; i<512; i++) {
		if (ptr[i] == (ULONG)Process) {
			// Get the offset of KAPC_STATE

			ApcState = CONTAINING_RECORD(&ptr[i], KAPC_STATE, Process);
			ApcStateOffset = (ULONG)ApcState - (ULONG)Thread;

			break;
		}
	}

	DbgPrint("ApcState offset: %#x", ApcStateOffset);

	InitializeProcessWatcher((PPROCESS_WATCHER_OBJECT)driverObjectExtension);
	InstallWatcherCallback();

	return status;
}

PPROCESS_WATCHER_OBJECT GetDriverData() {
	return (PPROCESS_WATCHER_OBJECT)IoGetDriverObjectExtension(gDriverObject, (PVOID)PROCESSWATCHER_DRIVER_OBJECT_EXTENSION_ID);
}

NTSTATUS InstallWatcherCallback() {
	NTSTATUS result;
	result = PsSetCreateProcessNotifyRoutine(NotifyRoutine, FALSE);
	return result;
}

NTSTATUS RemoveWatcherCallback() {
	NTSTATUS result;
	result = PsSetCreateProcessNotifyRoutine(NotifyRoutine, TRUE);
	return result;
}

char* GetProcessNameFromPid(HANDLE pid) {
	PEPROCESS Process;
	if (PsLookupProcessByProcessId(pid, &Process) == STATUS_INVALID_PARAMETER) {
		return "pid error";
	}
	return (char*)PsGetProcessImageFileName(Process);
}

//HANDLE hndlMainSafe = NULL;

VOID NotifyRoutine(
	HANDLE                 ParentId,
	HANDLE                 ProcessId,
	BOOLEAN Create
) {
	PPROCESS_WATCHER_OBJECT processWatcherObject;
	char* ProcName;
	CLIENT_ID ClientID;
	HANDLE DelProcessHandle;
	OBJECT_ATTRIBUTES Attr;
	
	UNREFERENCED_PARAMETER(ParentId);

	processWatcherObject = GetDriverData();
	if (processWatcherObject->enabled) {

		ProcName = GetProcessNameFromPid(ProcessId);

		if (strcmp(ProcName, processWatcherObject->watchedProcess) == 0) {
			if (Create) {
				if (CreatedProcessID == 0) {
					DbgPrint("Starting process creation");
					CreateProcessFromKernel(processWatcherObject->followedProcess);
				} else {
					DbgPrint("Process is already running");
				}
			} else {
				InitializeObjectAttributes(&Attr, NULL, OBJ_CASE_INSENSITIVE, NULL, NULL);
				ClientID.UniqueThread = 0;
				ClientID.UniqueProcess = (HANDLE)CreatedProcessID;
				ZwOpenProcess(&DelProcessHandle, PROCESS_ALL_ACCESS, &Attr, &ClientID);
				ZwTerminateProcess(DelProcessHandle, 0);
				CreatedProcessID = 0;
			}
		}
	}
}

VOID ProcessWatcherUnload(PDRIVER_OBJECT DriverObject) {
	UNICODE_STRING linkString;
	UNREFERENCED_PARAMETER(DriverObject);
	RtlInitUnicodeString(&linkString, L"\\DosDevices\\"DRIVER_NAME);
	IoDeleteSymbolicLink(&linkString);
	IoDeleteDevice(DriverObject->DeviceObject);
	RemoveWatcherCallback();

	DbgPrint(DBG_PREFIX"unloaded\n");
}


