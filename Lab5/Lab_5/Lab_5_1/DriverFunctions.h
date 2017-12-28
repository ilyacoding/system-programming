#pragma once

#include <ntddk.h>

NTSTATUS ProcessDefenderDispatchIoctl(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS ProcessDefenderDispatchCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp);

NTSTATUS ProcessDefenderDispatchClose(PDEVICE_OBJECT DeviceObject, PIRP Irp);
