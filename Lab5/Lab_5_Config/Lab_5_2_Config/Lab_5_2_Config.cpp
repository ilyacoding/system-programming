#include "stdafx.h"
#include <Windows.h>
#include <stdio.h>
#include <cstdbool>
#include "Common.h"

#define MAX_PARAMS_COUNT 3
#define MIN_PARAMS_COUNT 2

#define ENABLE_PARAM "-e"
#define DISABLE_PARAM "-d"

#define DRIVER_NAME L"\\\\.\\Lab_5_2"

void DisplayHelp();
int ProcessEnableParam(int argc, char * argv[]);
int ProcessDisableParam(int argc, char * argv[]);
bool EnableProcessDefender(int seconds);
bool DisableProcessDefender();
bool SendToDriver(PPROCESS_LOGGER_OBJECT pProcessDefenderObject);

int main(int argc, char *argv[]) {
	int result = 0;
	if ((argc > MAX_PARAMS_COUNT) || (argc < MIN_PARAMS_COUNT)) {
		DisplayHelp();
		result = 1;
	} else {
		char* commandParam = argv[1];
		if (strcmp(commandParam, ENABLE_PARAM) == 0) {
			result = ProcessEnableParam(argc, argv);

		} else if (strcmp(commandParam, DISABLE_PARAM) == 0) {
			result = ProcessDisableParam(argc, argv);
		} else {
			DisplayHelp();
			result = 1;
		}
	}

	return result;
}

void DisplayHelp() {
	puts("Usage:");
	printf("\t%s <seconds count> - enable defender for time interval\n", ENABLE_PARAM);
	printf("\t%s - disable defender\n", DISABLE_PARAM);
}

int ProcessEnableParam(int argc, char *argv[]) {
	int result = 0;
	int seconds;

	if (argc == MAX_PARAMS_COUNT) {
		seconds = atoi(argv[2]);
		if (EnableProcessDefender(seconds)) {
			puts("Enable request sent.");
		} else {
			result = 1;
		}
	} else {
		DisplayHelp();
		result = 1;
	}

	return result;
}

int ProcessDisableParam(int argc, char *argv[]) {
	int result = 0;
	if (argc == MIN_PARAMS_COUNT) {
		if (DisableProcessDefender()) {
			puts("Disable request sent.");
		} else {
			result = 1;
		}
	} else {
		DisplayHelp();
		result = 1;
	}

	return result;
}

bool EnableProcessDefender(int seconds) {
	PROCESS_LOGGER_OBJECT processDefenderObject;
	memset(&processDefenderObject, 0, sizeof(PROCESS_LOGGER_OBJECT));
	processDefenderObject.enabled = TRUE;
	processDefenderObject.seconds = seconds;
	return SendToDriver(&processDefenderObject);
}

bool DisableProcessDefender() {
	PROCESS_LOGGER_OBJECT processDefenderObject;
	memset(&processDefenderObject, 0, sizeof(PROCESS_LOGGER_OBJECT));
	processDefenderObject.enabled = FALSE;

	return SendToDriver(&processDefenderObject);
}

bool SendToDriver(PPROCESS_LOGGER_OBJECT pProcessDefenderObject) {
	bool result = true;
	HANDLE controlDriver = CreateFile(DRIVER_NAME,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	puts("driver created");
	if (controlDriver != INVALID_HANDLE_VALUE) {
		DWORD bytesReturned;
		if (!DeviceIoControl(controlDriver, IOCTL_UPDATE_PROCESS_LOGGER, pProcessDefenderObject, sizeof(*pProcessDefenderObject), NULL, 0, &bytesReturned, NULL)) {
			fprintf(stderr, "DeviceIoControl failed. Error %d\n", GetLastError());
			result = false;
		}

		CloseHandle(controlDriver);
	} else {
		fprintf(stderr, "CreateFile failed. Error %d\n", GetLastError());
		result = false;
	}

	return result;
}
