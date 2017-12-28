#include <ntddk.h>
#include "DriverFunctions.h"
#include "ProcessLogger.h"
#include "Common.h"
#include "Driver.h"

NTSTATUS ProcessLoggerDispatchIoctl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	NTSTATUS result;
	PPROCESS_LOGGER_OBJECT processLoggerObject;
	PIO_STACK_LOCATION stack;
	ULONG controlCode;
	ULONG inputBufferLength;
	PPROCESS_LOGGER_OBJECT receivedProcessLoggerObject;
	LARGE_INTEGER currentTime;

	UNREFERENCED_PARAMETER(DeviceObject);

	DbgPrint(DBG_PREFIX"IOCTL received\n");
	result = STATUS_SUCCESS;
	processLoggerObject = GetDriverData();

	stack = IoGetCurrentIrpStackLocation(Irp);
	inputBufferLength = stack->Parameters.DeviceIoControl.InputBufferLength;
	controlCode = stack->Parameters.DeviceIoControl.IoControlCode;
	if (controlCode == IOCTL_UPDATE_PROCESS_LOGGER)
	{
		if (inputBufferLength == sizeof(PROCESS_LOGGER_OBJECT))
		{
			receivedProcessLoggerObject = (PPROCESS_LOGGER_OBJECT)(Irp->AssociatedIrp.SystemBuffer);
			if (receivedProcessLoggerObject->enabled) {
				DbgPrint(DBG_PREFIX"enable defender\n");
				EnableProcessLogger(processLoggerObject);
				KeQuerySystemTime(&currentTime);
				SetProcessLoggerStart(processLoggerObject, currentTime);
				processLoggerObject->seconds = receivedProcessLoggerObject->seconds;
			}
			else {
				DbgPrint(DBG_PREFIX"disable defender\n");
				DisableProcessLogger(processLoggerObject);
			}
		}
	}
	else {
		result = STATUS_NOT_SUPPORTED;
	}
	
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return result;
}

NTSTATUS ProcessLoggerDispatchCreate(PDEVICE_OBJECT DeviceObject,PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	DbgPrint(DBG_PREFIX"create\n");

	Irp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS ProcessLoggerDispatchClose(PDEVICE_OBJECT DeviceObject,PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	DbgPrint(DBG_PREFIX"close\n");

	Irp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}