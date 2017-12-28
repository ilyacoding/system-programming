#include <ntifs.h>
#include <ntddk.h>
#include "Driver.h"
#include <ntstrsafe.h>
#include <wdmsec.h>

#define MAX_ALTITUDE_BUFFER_LENGTH 10

#define REGFLTR_CONTEXT_POOL_TAG '0tfR'

#define CALLBACK_ALTITUDE  L"380010"

LARGE_INTEGER Cookie;
HANDLE MySuperFile;
IO_STATUS_BLOCK iostatus;
OBJECT_ATTRIBUTES oa;
PDRIVER_OBJECT gDriverObject = NULL;

//LPCSTR GetNotifyClassString(REG_NOTIFY_CLASS NotifyClass);

NTSTATUS DriverEntry(IN PDRIVER_OBJECT object, IN PUNICODE_STRING registryPath) {
	UNICODE_STRING nameString, linkString;
	NTSTATUS Status;
	UNICODE_STRING fullFileName;
	PDEVICE_OBJECT deviceObject;
	PVOID driverObjectExtension;

	UNREFERENCED_PARAMETER(object);
	UNREFERENCED_PARAMETER(registryPath);
	gDriverObject = object;

	RtlInitUnicodeString(&nameString, L"\\Device\\"DRIVER_NAME);
	Status = IoCreateDevice(gDriverObject, 0, &nameString, FILE_DEVICE_UNKNOWN, 0, FALSE, &deviceObject);
	ASSERT(NT_SUCCESS(Status));

	deviceObject->Flags |= DO_DIRECT_IO;

	RtlInitUnicodeString(&linkString, L"\\DosDevices\\"DRIVER_NAME);
	Status = IoCreateSymbolicLink(&linkString, &nameString);
	ASSERT(NT_SUCCESS(Status));

	gDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = ProcessLoggerDispatchIoctl;
	gDriverObject->MajorFunction[IRP_MJ_CREATE] = ProcessLoggerDispatchCreate;
	gDriverObject->MajorFunction[IRP_MJ_CLOSE] = ProcessLoggerDispatchClose;

	Status = IoAllocateDriverObjectExtension(object, (PVOID)PROCESSWATCHER_DRIVER_OBJECT_EXTENSION_ID, sizeof(PROCESS_LOGGER_OBJECT), &driverObjectExtension);
	ASSERT(NT_SUCCESS(Status));
	object->DriverUnload = UnloadRoutine;

	InstallLoggerCallback();

	RtlInitUnicodeString(&fullFileName, L"\\??\\C:\\log.txt");

	InitializeObjectAttributes(&oa,
		&fullFileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL);

	Status = ZwCreateFile(&MySuperFile, GENERIC_WRITE | SYNCHRONIZE, &oa, &iostatus,
		0, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_WRITE, FILE_OPEN_IF,
		FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

	if (!NT_SUCCESS(Status)) {
		DbgPrint("ZwCreateFile failded");
	}

	return STATUS_SUCCESS;
}

int WriteToFile(HANDLE File, char* myString) {
	NTSTATUS Status;
	FILE_STANDARD_INFORMATION fileInfo;
	ULONG len;
	LARGE_INTEGER ByteOffset;

	Status = ZwQueryInformationFile(MySuperFile,
		&iostatus,
		&fileInfo,
		sizeof(FILE_STANDARD_INFORMATION),
		FileStandardInformation
	);
	
	len = strlen(myString);
	if (!NT_SUCCESS(Status)) {
		DbgPrint("ZwQueryInformationFile failded");
		return 0;
	} else {
		ByteOffset = fileInfo.EndOfFile;
		Status = ZwWriteFile(MySuperFile,
			NULL,
			NULL,
			NULL,
			&iostatus,
			myString, len,
			&ByteOffset,
			NULL);
		if (!NT_SUCCESS(Status) || iostatus.Information != len) {
			DbgPrint("Error on writing. Status = %x.", Status);
			return 0;
		}
		return 1;
	}
}

NTSTATUS InstallLoggerCallback() {
	UNICODE_STRING Altitude;
	WCHAR AltitudeBuffer[MAX_ALTITUDE_BUFFER_LENGTH];
	NTSTATUS Status;

	Status = RtlStringCbPrintfW(AltitudeBuffer,
		MAX_ALTITUDE_BUFFER_LENGTH * sizeof(WCHAR),
		L"%s",
		CALLBACK_ALTITUDE);

	if (!NT_SUCCESS(Status)) {
		DbgPrint("RtlStringCbPrintfW in CreateCallbackContext failed. Status 0x%x", Status);
	}
	RtlInitUnicodeString(&Altitude, AltitudeBuffer);

	if (!NT_SUCCESS(CmRegisterCallback(RegistryCallback,/* &Altitude,
														(PVOID)object,*/ NULL, &Cookie/*, NULL*/))) {
		DbgPrint("Error to register Callback");
	} else {
		DbgPrint("Reged Success");
	}
	return Status;
}

PPROCESS_LOGGER_OBJECT GetDriverData() {
	return (PPROCESS_LOGGER_OBJECT)IoGetDriverObjectExtension(gDriverObject, (PVOID)PROCESSWATCHER_DRIVER_OBJECT_EXTENSION_ID);
}

NTSTATUS RemoveLoggerCallback() {
	NTSTATUS status;
	status = CmUnRegisterCallback(Cookie);
	if (!NT_SUCCESS(status)) {
		DbgPrint("Error del");
	}
	return status;
}

NTSTATUS RegistryCallback(PVOID Context, PVOID Arg1, PVOID Argument2) {
	NTSTATUS Status = STATUS_SUCCESS;
	REG_NOTIFY_CLASS NotifyClass;
	PREG_SET_VALUE_KEY_INFORMATION PreSetValueInfo;
	PREG_DELETE_VALUE_KEY_INFORMATION PreDeleteValueInfo;
	KEY_NAME_INFORMATION info;
	WCHAR Buff[1000] = { 0 };
	char strBuff[1000];
	ULONG RezLen;
	HANDLE RootKey = NULL;
	PVOID Data = NULL;
	PPROCESS_LOGGER_OBJECT processLoggerObject;
	LARGE_INTEGER currentTime;
	ULONG seconds;
	TIME_FIELDS time;
	processLoggerObject = GetDriverData();

	if (processLoggerObject->enabled) {
		KeQuerySystemTime(&currentTime);
		RtlTimeToSecondsSince1970(&currentTime, &seconds);
		if (seconds < GetIntervalEndTimeSeconds(processLoggerObject)) {
			NotifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Arg1;
			switch (NotifyClass) {
			case RegNtPreSetValueKey:
				PreSetValueInfo = (PREG_SET_VALUE_KEY_INFORMATION)Argument2;

				Status = ObOpenObjectByPointer(PreSetValueInfo->Object, OBJ_KERNEL_HANDLE, NULL,
					KEY_ALL_ACCESS, NULL, KernelMode, &RootKey);

				if (!NT_SUCCESS(Status)) {
					DbgPrint("ObObjectByPointer failed. Status 0x%x", Status);
					break;
				}

				Status = ZwQueryKey(RootKey, KeyNameInformation, (PVOID)&info, sizeof(KEY_NAME_INFORMATION), &RezLen);
				if (!NT_SUCCESS(Status)) {

					Status = ZwQueryKey(RootKey, KeyNameInformation, (PVOID)&info, RezLen, &RezLen);

					if (!NT_SUCCESS(Status)) {
						DbgPrint("ZwQueryKey failed. Status 0x%x", Status);
						break;
					}
				}
				ExSystemTimeToLocalTime(&currentTime, &currentTime);
				RtlTimeToTimeFields(&currentTime, &time);
				sprintf(strBuff, "Time: %d:%d:%d\r\n\0", time.Hour, time.Minute, time.Second);
				WriteToFile(MySuperFile, strBuff);

				sprintf(strBuff, "Path: %S \r\n\0", info.Name);

				WriteToFile(MySuperFile, strBuff);

				sprintf(strBuff, "Set value %wZ bypassed.\r\n\0", PreSetValueInfo->ValueName);

				WriteToFile(MySuperFile, strBuff);

				break;

			case RegNtPreDeleteValueKey:

				PreDeleteValueInfo = (PREG_DELETE_VALUE_KEY_INFORMATION)Argument2;

				Status = ObOpenObjectByPointer(PreDeleteValueInfo->Object, OBJ_KERNEL_HANDLE, NULL,
					KEY_ALL_ACCESS, NULL, KernelMode, &RootKey);

				if (!NT_SUCCESS(Status)) {
					DbgPrint("ObObjectByPointer failed. Status 0x%x", Status);
					break;
				}

				Status = ZwQueryKey(RootKey, KeyNameInformation, (PVOID)&info, sizeof(KEY_NAME_INFORMATION), &RezLen);
				if (!NT_SUCCESS(Status)) {

					Status = ZwQueryKey(RootKey, KeyNameInformation, (PVOID)&info, RezLen, &RezLen);

					if (!NT_SUCCESS(Status)) {
						DbgPrint("ZwQueryKey failed. Status 0x%x", Status);
						break;
					}
				}
				ExSystemTimeToLocalTime(&currentTime, &currentTime);
				RtlTimeToTimeFields(&currentTime, &time);
				sprintf(strBuff, "Time: %d:%d:%d\r\n\0", time.Hour, time.Minute, time.Second);
				WriteToFile(MySuperFile, strBuff);

				sprintf(strBuff, "Path: %S \r\n\0", info.Name);

				WriteToFile(MySuperFile, strBuff);

				sprintf(strBuff, "Delete value %wZ bypassed.\r\n\0", PreDeleteValueInfo->ValueName);

				WriteToFile(MySuperFile, strBuff);

				break;
			default:
				break;

			}
		}
	}
	return STATUS_SUCCESS;
}

VOID UnloadRoutine(IN PDRIVER_OBJECT DriverObject) {
	UNICODE_STRING linkString;
	UNREFERENCED_PARAMETER(DriverObject);
	RtlInitUnicodeString(&linkString, L"\\DosDevices\\"DRIVER_NAME);
	IoDeleteSymbolicLink(&linkString);
	IoDeleteDevice(DriverObject->DeviceObject);
	RemoveLoggerCallback();
	ZwClose(MySuperFile);
	DbgPrint(DBG_PREFIX"unloaded\n");
}


/*LPCSTR GetNotifyClassString(REG_NOTIFY_CLASS NotifyClass) {
	switch (NotifyClass) {
	case RegNtPreDeleteKey:                 return "RegNtPreDeleteKey";
	case RegNtPreSetValueKey:               return "RegNtPreSetValueKey";
	case RegNtPreDeleteValueKey:            return "RegNtPreDeleteValueKey";
	case RegNtPreSetInformationKey:         return "RegNtPreSetInformationKey";
	case RegNtPreRenameKey:                 return "RegNtPreRenameKey";
	case RegNtPreEnumerateKey:              return "RegNtPreEnumerateKey";
	case RegNtPreEnumerateValueKey:         return "RegNtPreEnumerateValueKey";
	case RegNtPreQueryKey:                  return "RegNtPreQueryKey";
	case RegNtPreQueryValueKey:             return "RegNtPreQueryValueKey";
	case RegNtPreQueryMultipleValueKey:     return "RegNtPreQueryMultipleValueKey";
	case RegNtPreKeyHandleClose:            return "RegNtPreKeyHandleClose";
	case RegNtPreCreateKeyEx:               return "RegNtPreCreateKeyEx";
	case RegNtPreOpenKeyEx:                 return "RegNtPreOpenKeyEx";
	case RegNtPreFlushKey:                  return "RegNtPreFlushKey";
	case RegNtPreLoadKey:                   return "RegNtPreLoadKey";
	case RegNtPreUnLoadKey:                 return "RegNtPreUnLoadKey";
	case RegNtPreQueryKeySecurity:          return "RegNtPreQueryKeySecurity";
	case RegNtPreSetKeySecurity:            return "RegNtPreSetKeySecurity";
	case RegNtPreRestoreKey:                return "RegNtPreRestoreKey";
	case RegNtPreSaveKey:                   return "RegNtPreSaveKey";
	case RegNtPreReplaceKey:                return "RegNtPreReplaceKey";
	case RegNtPostDeleteKey:                return "RegNtPostDeleteKey";
	case RegNtPostSetValueKey:              return "RegNtPostSetValueKey";
	case RegNtPostDeleteValueKey:           return "RegNtPostDeleteValueKey";
	case RegNtPostSetInformationKey:        return "RegNtPostSetInformationKey";
	case RegNtPostRenameKey:                return "RegNtPostRenameKey";
	case RegNtPostEnumerateKey:             return "RegNtPostEnumerateKey";
	case RegNtPostEnumerateValueKey:        return "RegNtPostEnumerateValueKey";
	case RegNtPostQueryKey:                 return "RegNtPostQueryKey";
	case RegNtPostQueryValueKey:            return "RegNtPostQueryValueKey";
	case RegNtPostQueryMultipleValueKey:    return "RegNtPostQueryMultipleValueKey";
	case RegNtPostKeyHandleClose:           return "RegNtPostKeyHandleClose";
	case RegNtPostCreateKeyEx:              return "RegNtPostCreateKeyEx";
	case RegNtPostOpenKeyEx:                return "RegNtPostOpenKeyEx";
	case RegNtPostFlushKey:                 return "RegNtPostFlushKey";
	case RegNtPostLoadKey:                  return "RegNtPostLoadKey";
	case RegNtPostUnLoadKey:                return "RegNtPostUnLoadKey";
	case RegNtPostQueryKeySecurity:         return "RegNtPostQueryKeySecurity";
	case RegNtPostSetKeySecurity:           return "RegNtPostSetKeySecurity";
	case RegNtPostRestoreKey:               return "RegNtPostRestoreKey";
	case RegNtPostSaveKey:                  return "RegNtPostSaveKey";
	case RegNtPostReplaceKey:               return "RegNtPostReplaceKey";
	case RegNtCallbackObjectContextCleanup: return "RegNtCallbackObjectContextCleanup";
	default:
		return L"Unsupported REG_NOTIFY_CLASS";
	}
}*/