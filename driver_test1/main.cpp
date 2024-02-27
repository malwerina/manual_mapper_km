#include <ntifs.h>
#include <ntddk.h>
#include <wdm.h>

#include <stdio.h>
#include <stdlib.h>

#include "common.h"
#include "peloader.h"
#include "undoc_api.h"

#define DRIVER_TAG 'dcba'
#define PAYL_FUNC_NAME "RunMain"
//---


typedef struct _KLDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	PVOID ExceptionTable;
	ULONG ExceptionTableSize;
	//ULONG padding1;
	PVOID GpValue;
	PVOID NonPagedDebugInfo;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT __Unused5;
	PVOID SectionPointer;
	ULONG CheckSum;
	//ULONG Padding2;
	PVOID LoadedImports;
	PVOID PatchInformation;
} KLDR_DATA_TABLE_ENTRY, * PKLDR_DATA_TABLE_ENTRY;


KLDR_DATA_TABLE_ENTRY* g_Ntoskrnl = nullptr;
NTSTATUS(NTAPI* IoCreateDriver)(PUNICODE_STRING Uni, PDRIVER_INITIALIZE DriverEntry) = nullptr;

struct payl_data
{
	void* buf;
	SIZE_T buf_size;
	void* entry_point;
	void* param;
};

void enum_processes()
{
	ULONG buffer_size = 1000 * sizeof(SYSTEM_PROCESS_INFORMATION);
	void* buffer = ExAllocatePoolWithTag(NonPagedPool, buffer_size, DRIVER_TAG);

	NTSTATUS status = STATUS_SUCCESS;

	while (true) {
		if (!buffer) {
			return;
		}
		ULONG retSize = 0;
		status = ZwQuerySystemInformation(SystemProcessInformation, buffer, buffer_size, &retSize);
		if (status == STATUS_SUCCESS) {
			break;
		}
		// not successful:
		ExFreePoolWithTag(buffer, DRIVER_TAG);

		//try again:
		if (status == STATUS_INFO_LENGTH_MISMATCH)
		{
			buffer_size = retSize;
			buffer = ExAllocatePoolWithTag(NonPagedPool, buffer_size, DRIVER_TAG);
			continue;
		}
		break;
	}

	if (status != STATUS_SUCCESS) {
		ExFreePoolWithTag(buffer, DRIVER_TAG);
		DbgPrint(DRIVER_PREFIX " ZwQuerySystemInformation failed: %X\n", status);
		return;
	}

	SYSTEM_PROCESS_INFORMATION* pInfo = (SYSTEM_PROCESS_INFORMATION*)buffer;
	while (pInfo)
	{
		DbgPrint(DRIVER_PREFIX " Next process: PID: %p", pInfo->UniqueProcessId);
		if (pInfo->ImageName.Length) {
			DbgPrint(DRIVER_PREFIX " name: %S ", pInfo->ImageName.Buffer);
		}

		if (!pInfo->NextEntryOffset) break;
		pInfo = (SYSTEM_PROCESS_INFORMATION*)((PUCHAR)pInfo + pInfo->NextEntryOffset);
	}

	ExFreePoolWithTag(buffer, DRIVER_TAG);
}

DRIVER_OBJECT* open_and_dereference_systemroot()
{
	DRIVER_OBJECT* driver = nullptr;

	UNICODE_STRING SystemRootStr = RTL_CONSTANT_STRING(L"\\Systemroot");

	OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
	InitializeObjectAttributes(&ObjectAttributes,
		&SystemRootStr,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL);
	IO_STATUS_BLOCK IoStatusBlock;
	HANDLE FileHandle;
	NTSTATUS openStatus = ZwOpenFile(&FileHandle, GENERIC_READ | SYNCHRONIZE, &ObjectAttributes, &IoStatusBlock, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_SYNCHRONOUS_IO_NONALERT);
	if (openStatus == STATUS_SUCCESS)
	{
		PFILE_OBJECT Object;
		NTSTATUS refStatus = ObReferenceObjectByHandle(FileHandle, 0, *IoFileObjectType, 0, (PVOID*)&Object, 0);
		if (refStatus == STATUS_SUCCESS)
		{
			PDEVICE_OBJECT dev = Object->DeviceObject;
			if (dev) {
				driver = dev->DriverObject;
			}
			ObfDereferenceObject(Object);
		}
		else {
			DbgPrint(DRIVER_PREFIX " Failed to dereference object by handle: %X\n", refStatus);
		}
		ZwClose(FileHandle);
	}
	else {
		STATUS_INVALID_PARAMETER;
		DbgPrint(DRIVER_PREFIX " Failed to open Systemroot! Status: %X\n", openStatus);
	}
	return driver;
}


bool fetch_ntoskrnl()
{
	g_Ntoskrnl = nullptr;
	DRIVER_OBJECT* driver = open_and_dereference_systemroot();
	if (!driver) return false;

	KLDR_DATA_TABLE_ENTRY* DriverSection = (KLDR_DATA_TABLE_ENTRY*)driver->DriverSection;
	if (!DriverSection) return false;

	UNICODE_STRING NtoskrnlStr = RTL_CONSTANT_STRING(L"ntoskrnl.exe");

	KIRQL NewIrql = KeRaiseIrqlToDpcLevel();

	KLDR_DATA_TABLE_ENTRY* next = (KLDR_DATA_TABLE_ENTRY*)DriverSection->InLoadOrderLinks.Flink;
	while (next != DriverSection)
	{
		if (!next) break;

		if (next->BaseDllName.Length) {
			DbgPrint(DRIVER_PREFIX " Next device: %S\n", next->BaseDllName.Buffer);
		}

		if (RtlEqualUnicodeString(&(next->BaseDllName), &NtoskrnlStr, TRUE))// 'ntoskrnl.exe'
		{
			g_Ntoskrnl = next;
			break;
		}
		next = (KLDR_DATA_TABLE_ENTRY*)next->InLoadOrderLinks.Flink;
	}
	KeLowerIrql(NewIrql);
	if (g_Ntoskrnl) {
		DbgPrint(DRIVER_PREFIX " Found!");
		return true;
	}
	return false;
}

PVOID get_driver_by_name(LPCSTR SearchedDriverName)
{
	if (!g_Ntoskrnl) {
		return nullptr;
	}

	PVOID base = nullptr;

	//convert cstring to STRING structure
	STRING SearchedDriverNameStr;
	RtlInitString(&SearchedDriverNameStr, SearchedDriverName);

	//convert STRING to UNICODE_STRING
	UNICODE_STRING SearchedDriverNameU;
	if (RtlAnsiStringToUnicodeString(&SearchedDriverNameU, &SearchedDriverNameStr, 1u) != STATUS_SUCCESS) {
		return nullptr;
	}

	KIRQL prevIrql = KeRaiseIrqlToDpcLevel();

	KLDR_DATA_TABLE_ENTRY* next = g_Ntoskrnl;
	do {
		if (RtlEqualUnicodeString(&next->BaseDllName, &SearchedDriverNameU, TRUE)) {
			base = next->DllBase;
			break; // found matching
		}
		next = (KLDR_DATA_TABLE_ENTRY*)next->InLoadOrderLinks.Flink;

	} while (next && next != g_Ntoskrnl);

	KeLowerIrql(prevIrql);

	RtlFreeUnicodeString(&SearchedDriverNameU);
	return base;
}

//---

void SampleUnload(_In_ PDRIVER_OBJECT DriverObject)
{
	UNICODE_STRING symLink = RTL_CONSTANT_STRING(MY_DRIVER_LINK);
	// delete symbolic link
	IoDeleteSymbolicLink(&symLink);

	// delete device object
	IoDeleteDevice(DriverObject->DeviceObject);

	DbgPrint(DRIVER_PREFIX " driver unloaded!\n");
}

NTSTATUS HandleCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS _fetch_payl_buffer(IN PIRP Irp, kloader_input** inp)
{
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
	const ULONG buf_size = stack->Parameters.DeviceIoControl.InputBufferLength;
	if (buf_size < sizeof(kloader_input)) {
		return STATUS_BUFFER_TOO_SMALL;
	}
	kloader_input* data = (kloader_input*)Irp->AssociatedIrp.SystemBuffer;
	if (!data || data->magic != KL_MAGIC) {
		return STATUS_INVALID_PARAMETER;
	}
	if (data->payl_size > buf_size) {
		return STATUS_BUFFER_TOO_SMALL;
	}
	*inp = data;
	return STATUS_SUCCESS;
}


VOID* alloc_image(PMDL& PagesForMdl, SIZE_T Count)
{
	LARGE_INTEGER LowAddress = { 0 };
	LARGE_INTEGER HighAddress = { 0 };
	LARGE_INTEGER SkipBytes = { 0 };

	HighAddress.QuadPart = ~0ull;

	PagesForMdl = MmAllocatePagesForMdl(LowAddress, HighAddress, SkipBytes, Count);
	if (!PagesForMdl) {
		DbgPrint(DRIVER_PREFIX " Payload allocation failed!");
		return nullptr;
	}
	VOID* buf = nullptr;
	if ((PagesForMdl->MdlFlags & 5) != 0)
		buf = (VOID*)PagesForMdl->MappedSystemVa;
	else
		buf = (VOID*)MmMapLockedPagesSpecifyCache(PagesForMdl, 0, MmCached, 0, 0, 0x10u);
	return buf;
}

NTSTATUS _load_payload(kloader_input* data, payl_data& payload)
{
	if (!data) return STATUS_INVALID_PARAMETER;
	if (data->magic != KL_MAGIC) {
		DbgPrint(DRIVER_PREFIX " Structure has invalid magic\n");
		return STATUS_INVALID_PARAMETER;
	}
	DbgPrint(DRIVER_PREFIX " Requested loading %s\n", data->file_name);
	DbgPrint(DRIVER_PREFIX " Payload size: %ld\n", data->payl_size);
	void* raw = &data->payl_buf;
	PIMAGE_NT_HEADERS nt = get_nt_hdr(&data->payl_buf);
	if (!nt) {
		DbgPrint(DRIVER_PREFIX " Payload is NOT a valid PE!");
		return STATUS_INVALID_PARAMETER;
	}
	if (nt->OptionalHeader.Subsystem != 1) {
		DbgPrint(DRIVER_PREFIX " Payload is not a driver! Subsystem: %X", nt->OptionalHeader.Subsystem);
		return STATUS_INVALID_PARAMETER;
	}
#ifdef _WIN64
	if (nt->OptionalHeader.Magic != 0x20b) {
		DbgPrint(DRIVER_PREFIX " Payload is not a 64 bit PE: %X", nt->OptionalHeader.Magic);
		return STATUS_INVALID_PARAMETER;
	}
#else
	if (nt->OptionalHeader.Magic != 0x10b) {
		DbgPrint(DRIVER_PREFIX " Payload is not a 32 bit PE: %X", nt->OptionalHeader.Magic);
		return STATUS_INVALID_PARAMETER;
	}
#endif
	DbgPrint(DRIVER_PREFIX " Payload is a valid PE! Virtual Size: %X", nt->OptionalHeader.SizeOfImage);
	PMDL PagesForMdl = nullptr;
	const SIZE_T ImgSize = nt->OptionalHeader.SizeOfImage;
	SIZE_T Count = ImgSize + sizeof(data->file_name);
	VOID* image = alloc_image(PagesForMdl, Count);
	if (!image) {
		return STATUS_MEMORY_NOT_ALLOCATED;
	}

	DbgPrint(DRIVER_PREFIX " Buffer for payload was allocated: %p", image);
	MmProtectMdlSystemAddress(PagesForMdl, PAGE_EXECUTE_READWRITE);

	bool loadOk = false;
	map_sections(image, raw, nt);

	if (relocate(image, nt, image)) {
		if (load_imports(image, nt, get_driver_by_name, get_func_by_name)) {
			loadOk = true;
		}
	}

	void* run_func = get_func_by_name(image, PAYL_FUNC_NAME);
	if (!run_func) {
		DbgPrint(DRIVER_PREFIX " The required function %s is missing. Cannot run the payload.", PAYL_FUNC_NAME);
	}
	if (!loadOk || !run_func) {
		//Free the memory if loading the payload has failed:
		MmFreePagesFromMdl(PagesForMdl);
		ExFreePool(PagesForMdl);
		return STATUS_MEMORY_NOT_ALLOCATED;
	}
	DbgPrint(DRIVER_PREFIX " image: %p", image);


	payload.buf = image;
	payload.buf_size = Count;
	payload.entry_point = (void*)run_func;
	payload.param = (void*)((ULONG_PTR)image + ImgSize);
	::memcpy(payload.param, data->file_name, sizeof(data->file_name));

	return STATUS_SUCCESS;
}

NTSTATUS HandleDeviceControl(PDEVICE_OBJECT, PIRP Irp)
{
	payl_data payload = { 0 } ;
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
	NTSTATUS status = STATUS_SUCCESS;

	switch (stack->Parameters.DeviceIoControl.IoControlCode) {
		case IOCTL_PASS_PAYLOAD:
		{
			DbgPrint(DRIVER_PREFIX " Received IOCTL: IOCTL_PASS_PAYLOAD \n");
			kloader_input* data = nullptr;
			status = _fetch_payl_buffer(Irp, &data);
			if (status != STATUS_SUCCESS) {
				DbgPrint(DRIVER_PREFIX " Received IOCTL: IOCTL_PASS_PAYLOAD: buffer is invalid\n");
				break;
			}
			status = _load_payload(data, payload);
			break;
		}
		default:
			status = STATUS_INVALID_DEVICE_REQUEST;
			break;
	}

	if (status == STATUS_SUCCESS && payload.buf)
	{
		HANDLE thread;
		CLIENT_ID threadid;
		status = PsCreateSystemThread(&thread, STANDARD_RIGHTS_ALL, NULL, NULL, &threadid, (PKSTART_ROUTINE)payload.entry_point, (PVOID)payload.param);
		DbgPrint(DRIVER_PREFIX " PsCreateSystemThread status: %X ThreadID: %p\n", status, threadid.UniqueThread);
	}
	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}


extern "C"
NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(RegistryPath);

	DriverObject->DriverUnload = SampleUnload;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = HandleCreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = HandleCreateClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = HandleDeviceControl;

	DbgPrint(DRIVER_PREFIX " loaded\n");

	RTL_OSVERSIONINFOW version = { 0 };
	RtlGetVersion(&version);
	DbgPrint(DRIVER_PREFIX " OS Version: %d.%d.%d\n", version.dwMajorVersion, version.dwMinorVersion, version.dwBuildNumber);

	if (!fetch_ntoskrnl()) {
		DbgPrint(DRIVER_PREFIX " Failed fetching Ntoskrnl\n");
		return STATUS_INVALID_PARAMETER;
	}
	enum_processes();
	UNICODE_STRING devName = RTL_CONSTANT_STRING(MY_DEVICE);

	PDEVICE_OBJECT DeviceObject;
	NTSTATUS status = IoCreateDevice(DriverObject, 0, &devName, FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceObject);
	if (!NT_SUCCESS(status)) {
		DbgPrint(DRIVER_PREFIX " Failed to create device (0x%08X)\n", status);
		return status;
	}

	UNICODE_STRING symLink = RTL_CONSTANT_STRING(MY_DRIVER_LINK);
	status = IoCreateSymbolicLink(&symLink, &devName);
	if (!NT_SUCCESS(status)) {
		DbgPrint(DRIVER_PREFIX " Failed to create symbolic link (0x%08X)\n", status);
		IoDeleteDevice(DeviceObject);
		return status;
	}
	DbgPrint(DRIVER_PREFIX " DriverEntry completed successfully\n");
	return STATUS_SUCCESS;
}
