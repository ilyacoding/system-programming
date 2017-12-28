#pragma once

#include <ntddk.h>
#include "Common.h"

VOID InitializeProcessLogger(PPROCESS_LOGGER_OBJECT ProcessLoggerObject);
VOID EnableProcessLogger(PPROCESS_LOGGER_OBJECT ProcessLoggerObject);
VOID DisableProcessLogger(PPROCESS_LOGGER_OBJECT ProcessLoggerObject);
VOID SetProcessLoggerStart(PPROCESS_LOGGER_OBJECT ProcessLoggerObject, LARGE_INTEGER start);
ULONG GetIntervalEndTimeSeconds(PPROCESS_LOGGER_OBJECT);