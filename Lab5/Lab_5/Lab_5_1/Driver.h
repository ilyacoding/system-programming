#pragma once

#include <ntddk.h>
#include "ProcessWatcher.h"

#define PROCESSWATCHER_DRIVER_OBJECT_EXTENSION_ID 1
#define DBG_PREFIX "ProcessWatcher: "

NTSTATUS DriverEntry(IN PDRIVER_OBJECT object, IN PUNICODE_STRING registryPath);
VOID ProcessWatcherUnload(PDRIVER_OBJECT DriverObject);

PPROCESS_WATCHER_OBJECT GetDriverData();

NTSTATUS InstallWatcherCallback();
NTSTATUS RemoveWatcherCallback();
