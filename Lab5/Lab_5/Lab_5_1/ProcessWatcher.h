#pragma once

#include <ntddk.h>
#include "Common.h"

VOID InitializeProcessWatcher(PPROCESS_WATCHER_OBJECT ProcessWatcherObject);
VOID EnableProcessWatcher(PPROCESS_WATCHER_OBJECT ProcessWatcherObject);
VOID DisableProcessWatcher(PPROCESS_WATCHER_OBJECT ProcessWatcherObject);
VOID SetFollowedProcessName(PPROCESS_WATCHER_OBJECT ProcessWatcherObject, const CHAR processName[MAX_PATH]);
VOID SetWatchedProcessName(PPROCESS_WATCHER_OBJECT ProcessWatcherObject, const CHAR processName[MAX_PATH]);