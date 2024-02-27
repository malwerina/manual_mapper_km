#pragma once

#include <ntddk.h>

extern "C" NTSTATUS ZwQueryInformationProcess(
	_In_      HANDLE           ProcessHandle,
	_In_      PROCESSINFOCLASS ProcessInformationClass,
	_Out_     PVOID            ProcessInformation,
	_In_      ULONG            ProcessInformationLength,
	_Out_opt_ PULONG           ReturnLength
);

extern "C" NTSTATUS ZwSetInformationProcess(
	_In_      HANDLE           ProcessHandle,
	_In_      PROCESSINFOCLASS ProcessInformationClass,
	_Out_     PVOID            ProcessInformation,
	_In_      ULONG            ProcessInformationLength
);

typedef ULONG SYSTEM_INFORMATION_CLASS;

extern "C" NTSTATUS ZwQuerySystemInformation(
	_In_      SYSTEM_INFORMATION_CLASS SystemInformationClass,
	_Inout_   PVOID                    SystemInformation,
	_In_      ULONG                    SystemInformationLength,
	_Out_opt_ PULONG                   ReturnLength
);

//---

#define  SystemProcessInformation 0x05 

typedef VOID*  SYSTEM_THREAD_INFORMATION ;

// System Information Class 5 : from ProcessHacker
typedef struct _SYSTEM_PROCESS_INFORMATION
{
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER WorkingSetPrivateSize; // since VISTA
	ULONG HardFaultCount; // since WIN7
	ULONG NumberOfThreadsHighWatermark; // since WIN7
	ULONGLONG CycleTime; // since WIN7
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	ULONG_PTR UniqueProcessKey; // since VISTA (requires SystemExtendedProcessInformation)
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER ReadOperationCount;
	LARGE_INTEGER WriteOperationCount;
	LARGE_INTEGER OtherOperationCount;
	LARGE_INTEGER ReadTransferCount;
	LARGE_INTEGER WriteTransferCount;
	LARGE_INTEGER OtherTransferCount;
	SYSTEM_THREAD_INFORMATION Threads[1]; // SystemProcessInformation
	// SYSTEM_EXTENDED_THREAD_INFORMATION Threads[1]; // SystemExtendedProcessinformation
	// SYSTEM_EXTENDED_THREAD_INFORMATION + SYSTEM_PROCESS_INFORMATION_EXTENSION // SystemFullProcessInformation
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;



typedef struct _EX_FAST_REF
{
    union
    {
        PVOID Object;
        ULONG RefCnt : 3;
        ULONG Value;
    };
} EX_FAST_REF, * PEX_FAST_REF;

/*
typedef struct _EPROCESS
{
    VOID* Pcb;
    EX_PUSH_LOCK ProcessLock;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER ExitTime;
    EX_RUNDOWN_REF RundownProtect;
    PVOID UniqueProcessId;
    LIST_ENTRY ActiveProcessLinks;
    ULONG QuotaUsage[3];
    ULONG QuotaPeak[3];
    ULONG CommitCharge;
    ULONG PeakVirtualSize;
    ULONG VirtualSize;
    LIST_ENTRY SessionProcessLinks;
    PVOID DebugPort;
    union
    {
        PVOID ExceptionPortData;
        ULONG ExceptionPortValue;
        ULONG ExceptionPortState : 3;
    };
    VOID* ObjectTable;
    EX_FAST_REF Token;
    ULONG WorkingSetPage;
    EX_PUSH_LOCK AddressCreationLock;
    PETHREAD RotateInProgress;
    PETHREAD ForkInProgress;
    ULONG HardwareTrigger;
    PMM_AVL_TABLE PhysicalVadRoot;
    PVOID CloneRoot;
    ULONG NumberOfPrivatePages;
    ULONG NumberOfLockedPages;
    PVOID Win32Process;
    PEJOB Job;
    PVOID SectionObject;
    PVOID SectionBaseAddress;
    _EPROCESS_QUOTA_BLOCK* QuotaBlock;
    _PAGEFAULT_HISTORY* WorkingSetWatch;
    PVOID Win32WindowStation;
    PVOID InheritedFromUniqueProcessId;
    PVOID LdtInformation;
    PVOID VadFreeHint;
    PVOID VdmObjects;
    PVOID DeviceMap;
    PVOID EtwDataSource;
    PVOID FreeTebHint;
    union
    {
        HARDWARE_PTE PageDirectoryPte;
        UINT64 Filler;
    };
    PVOID Session;
    UCHAR ImageFileName[16];
    LIST_ENTRY JobLinks;
    PVOID LockedPagesList;
    LIST_ENTRY ThreadListHead;
    PVOID SecurityPort;
    PVOID PaeTop;
    ULONG ActiveThreads;
    ULONG ImagePathHash;
    ULONG DefaultHardErrorProcessing;
    LONG LastThreadExitStatus;
    PPEB Peb;
    EX_FAST_REF PrefetchTrace;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
    ULONG CommitChargeLimit;
    ULONG CommitChargePeak;
    PVOID AweInfo;
    SE_AUDIT_PROCESS_CREATION_INFO SeAuditProcessCreationInfo;
    MMSUPPORT Vm;
    LIST_ENTRY MmProcessLinks;
    ULONG ModifiedPageCount;
    ULONG Flags2;
    ULONG JobNotReallyActive : 1;
    ULONG AccountingFolded : 1;
    ULONG NewProcessReported : 1;
    ULONG ExitProcessReported : 1;
    ULONG ReportCommitChanges : 1;
    ULONG LastReportMemory : 1;
    ULONG ReportPhysicalPageChanges : 1;
    ULONG HandleTableRundown : 1;
    ULONG NeedsHandleRundown : 1;
    ULONG RefTraceEnabled : 1;
    ULONG NumaAware : 1;
    ULONG ProtectedProcess : 1;
    ULONG DefaultPagePriority : 3;
    ULONG PrimaryTokenFrozen : 1;
    ULONG ProcessVerifierTarget : 1;
    ULONG StackRandomizationDisabled : 1;
    ULONG Flags;
    ULONG CreateReported : 1;
    ULONG NoDebugInherit : 1;
    ULONG ProcessExiting : 1;
    ULONG ProcessDelete : 1;
    ULONG Wow64SplitPages : 1;
    ULONG VmDeleted : 1;
    ULONG OutswapEnabled : 1;
    ULONG Outswapped : 1;
    ULONG ForkFailed : 1;
    ULONG Wow64VaSpace4Gb : 1;
    ULONG AddressSpaceInitialized : 2;
    ULONG SetTimerResolution : 1;
    ULONG BreakOnTermination : 1;
    ULONG DeprioritizeViews : 1;
    ULONG WriteWatch : 1;
    ULONG ProcessInSession : 1;
    ULONG OverrideAddressSpace : 1;
    ULONG HasAddressSpace : 1;
    ULONG LaunchPrefetched : 1;
    ULONG InjectInpageErrors : 1;
    ULONG VmTopDown : 1;
    ULONG ImageNotifyDone : 1;
    ULONG PdeUpdateNeeded : 1;
    ULONG VdmAllowed : 1;
    ULONG SmapAllowed : 1;
    ULONG ProcessInserted : 1;
    ULONG DefaultIoPriority : 3;
    ULONG SparePsFlags1 : 2;
    LONG ExitStatus;
    WORD Spare7;
    union
    {
        struct
        {
            UCHAR SubSystemMinorVersion;
            UCHAR SubSystemMajorVersion;
        };
        WORD SubSystemVersion;
    };
    UCHAR PriorityClass;
//...
} EPROCESS, * PEPROCESS;

*/