#include <ntifs.h>
#include <ntddk.h>
#include "ProcessLogger.h"
#include "Common.h"

VOID InitializeProcessLogger(PPROCESS_LOGGER_OBJECT ProcessLoggerObject)
{
	RtlZeroMemory(ProcessLoggerObject, sizeof(ProcessLoggerObject));
}

VOID EnableProcessLogger(PPROCESS_LOGGER_OBJECT ProcessLoggerObject)
{
	ProcessLoggerObject->enabled = TRUE;
}

VOID DisableProcessLogger(PPROCESS_LOGGER_OBJECT ProcessLoggerObject)
{
	ProcessLoggerObject->enabled = FALSE;
}

VOID SetProcessLoggerStart(PPROCESS_LOGGER_OBJECT ProcessLoggerObject, LARGE_INTEGER start) 
{
	RtlCopyMemory(&(ProcessLoggerObject->start), &start, sizeof(start));
}

ULONG GetIntervalEndTimeSeconds(PPROCESS_LOGGER_OBJECT ProcessLoggerObject) {
	ULONG seconds;
	RtlTimeToSecondsSince1970(&(ProcessLoggerObject->start), &seconds);
	return seconds + ProcessLoggerObject->seconds;
}
