#pragma once

#include "ProcessLogger.h"
#include "Common.h"
#include "DriverFunctions.h"

#define PROCESSWATCHER_DRIVER_OBJECT_EXTENSION_ID 1
#define DBG_PREFIX "ProcessLogger: "

NTSTATUS DriverEntry(IN PDRIVER_OBJECT object, IN PUNICODE_STRING registryPath);
VOID UnloadRoutine(IN PDRIVER_OBJECT DriverObject);
NTSTATUS RegistryCallback(PVOID Context, PVOID Arg1, PVOID Arg2);
int WriteToFile(HANDLE File, char* myString);

PPROCESS_LOGGER_OBJECT GetDriverData();

NTSTATUS InstallLoggerCallback();
NTSTATUS RemoveLoggerCallback();
