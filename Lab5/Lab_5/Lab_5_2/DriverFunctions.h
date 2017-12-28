#pragma once

#include <ntddk.h>

NTSTATUS ProcessLoggerDispatchIoctl(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS ProcessLoggerDispatchCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp);

NTSTATUS ProcessLoggerDispatchClose(PDEVICE_OBJECT DeviceObject, PIRP Irp);
