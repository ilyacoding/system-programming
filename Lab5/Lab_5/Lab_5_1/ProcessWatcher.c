#include <ntddk.h>
#include "ProcessWatcher.h"
#include "Common.h"

VOID InitializeProcessWatcher(PPROCESS_WATCHER_OBJECT ProcessWatcherObject)
{
	RtlZeroMemory(ProcessWatcherObject, sizeof(ProcessWatcherObject));
}

VOID EnableProcessWatcher(PPROCESS_WATCHER_OBJECT ProcessWatcherObject)
{
	ProcessWatcherObject->enabled = TRUE;
}

VOID DisableProcessWatcher(PPROCESS_WATCHER_OBJECT ProcessWatcherObject)
{
	ProcessWatcherObject->enabled = FALSE;
}

VOID SetWatchedProcessName( PPROCESS_WATCHER_OBJECT ProcessWatcherObject, const CHAR processName[MAX_PATH])
{
	RtlCopyMemory(ProcessWatcherObject->watchedProcess, processName, sizeof(ProcessWatcherObject->watchedProcess));
}

VOID SetFollowedProcessName( PPROCESS_WATCHER_OBJECT ProcessWatcherObject, const CHAR processName[MAX_PATH])
{
	RtlCopyMemory(ProcessWatcherObject->followedProcess, processName, sizeof(ProcessWatcherObject->followedProcess));
}
