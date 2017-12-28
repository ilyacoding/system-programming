#include <ntddk.h>
#include "DriverFunctions.h"
#include "ProcessWatcher.h"
#include "Common.h"
#include "Driver.h"

NTSTATUS ProcessDefenderDispatchIoctl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	NTSTATUS result;
	PPROCESS_WATCHER_OBJECT processWatcherObject;
	PIO_STACK_LOCATION stack;
	ULONG controlCode;
	ULONG inputBufferLength;
	PPROCESS_WATCHER_OBJECT receivedProcessWatcherObject;

	UNREFERENCED_PARAMETER(DeviceObject);

	DbgPrint(DBG_PREFIX"IOCTL received\n");
	result = STATUS_SUCCESS;
	processWatcherObject = GetDriverData();

	stack = IoGetCurrentIrpStackLocation(Irp);
	inputBufferLength = stack->Parameters.DeviceIoControl.InputBufferLength;
	controlCode = stack->Parameters.DeviceIoControl.IoControlCode;
	if (controlCode == IOCTL_UPDATE_PROCESS_WATCHER)
	{
		if (inputBufferLength == sizeof(PROCESS_WATCHER_OBJECT))
		{
			receivedProcessWatcherObject = (PPROCESS_WATCHER_OBJECT)(Irp->AssociatedIrp.SystemBuffer);
			if (receivedProcessWatcherObject->enabled) {
				DbgPrint(DBG_PREFIX"enable defender\n");
				EnableProcessWatcher(processWatcherObject);
				SetFollowedProcessName(processWatcherObject, receivedProcessWatcherObject->followedProcess);
				SetWatchedProcessName(processWatcherObject, receivedProcessWatcherObject->watchedProcess);
			}
			else {
				DbgPrint(DBG_PREFIX"disable defender\n");
				DisableProcessWatcher(processWatcherObject);
			}
		}
	}
	else {
		result = STATUS_NOT_SUPPORTED;
	}
	
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return result;
}

NTSTATUS ProcessDefenderDispatchCreate(PDEVICE_OBJECT DeviceObject,PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	DbgPrint(DBG_PREFIX"create\n");

	Irp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS ProcessDefenderDispatchClose(PDEVICE_OBJECT DeviceObject,PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	DbgPrint(DBG_PREFIX"close\n");

	Irp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}