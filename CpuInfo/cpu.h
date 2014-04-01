#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <windows.h>
#include <psapi.h>
#include <time.h>
#include <string.h>
#pragma comment(lib, "Psapi.lib")
 

#define STATUS_INFO_LENGTH_MISMATCH      ((NTSTATUS)0xC0000004)
typedef LONG NTSTATUS;
#define Li2Double(x) ((double)((x).HighPart) * 4.294967296E9 + (double)((x).LowPart))

//记录的进程数
#define TOP_NUM 5
//查询间隔事件,单位ms
#define QUERT_TIME 5000



//self def struct.
typedef struct CpuData 
{
 DWORD dwPID;
 UINT cpuusage;
 __int64  lastidle;
 __int64  lastsys;
 LARGE_INTEGER  cputime;
 LARGE_INTEGER  KernelTime;
 LARGE_INTEGER  UserTime;
} *pCpuData;

typedef struct
{
    LARGE_INTEGER IdleProcessTime;
    LARGE_INTEGER IoReadTransferCount;
    LARGE_INTEGER IoWriteTransferCount;
    LARGE_INTEGER IoOtherTransferCount;
    ULONG IoReadOperationCount;
    ULONG IoWriteOperationCount;
    ULONG IoOtherOperationCount;
    ULONG AvailablePages;
    ULONG CommittedPages;
    ULONG CommitLimit;
    ULONG PeakCommitment;
    ULONG PageFaultCount;
    ULONG CopyOnWriteCount;
    ULONG TransitionCount;
    ULONG CacheTransitionCount;
    ULONG DemandZeroCount;
    ULONG PageReadCount;
    ULONG PageReadIoCount;
    ULONG CacheReadCount;
    ULONG CacheIoCount;
    ULONG DirtyPagesWriteCount;
    ULONG DirtyWriteIoCount;
    ULONG MappedPagesWriteCount;
    ULONG MappedWriteIoCount;
    ULONG PagedPoolPages;
    ULONG NonPagedPoolPages;
    ULONG PagedPoolAllocs;
    ULONG PagedPoolFrees;
    ULONG NonPagedPoolAllocs;
    ULONG NonPagedPoolFrees;
    ULONG FreeSystemPtes;
    ULONG ResidentSystemCodePage;
    ULONG TotalSystemDriverPages;
    ULONG TotalSystemCodePages;
    ULONG NonPagedPoolLookasideHits;
    ULONG PagedPoolLookasideHits;
    ULONG Spare3Count;
    ULONG ResidentSystemCachePage;
    ULONG ResidentPagedPoolPage;
    ULONG ResidentSystemDriverPage;
    ULONG CcFastReadNoWait;
    ULONG CcFastReadWait;
    ULONG CcFastReadResourceMiss;
    ULONG CcFastReadNotPossible;
    ULONG CcFastMdlReadNoWait;
    ULONG CcFastMdlReadWait;
    ULONG CcFastMdlReadResourceMiss;
    ULONG CcFastMdlReadNotPossible;
    ULONG CcMapDataNoWait;
    ULONG CcMapDataWait;
    ULONG CcMapDataNoWaitMiss;
    ULONG CcMapDataWaitMiss;
    ULONG CcPinMappedDataCount;
    ULONG CcPinReadNoWait;
    ULONG CcPinReadWait;
    ULONG CcPinReadNoWaitMiss;
    ULONG CcPinReadWaitMiss;
    ULONG CcCopyReadNoWait;
    ULONG CcCopyReadWait;
    ULONG CcCopyReadNoWaitMiss;
    ULONG CcCopyReadWaitMiss;
    ULONG CcMdlReadNoWait;
    ULONG CcMdlReadWait;
    ULONG CcMdlReadNoWaitMiss;
    ULONG CcMdlReadWaitMiss;
    ULONG CcReadAheadIos;
    ULONG CcLazyWriteIos;
    ULONG CcLazyWritePages;
    ULONG CcDataFlushes;
    ULONG CcDataPages;
    ULONG ContextSwitches;
    ULONG FirstLevelTbFills;
    ULONG SecondLevelTbFills;
    ULONG SystemCalls;
} SYSTEM_PERFORMANCE_INFORMATION;

typedef struct _SYSTEM_TIMEOFDAY_INFORMATION
{
    LARGE_INTEGER BootTime;
    LARGE_INTEGER CurrentTime;
    LARGE_INTEGER TimeZoneBias;
    ULONG TimeZoneId;
    ULONG Reserved;
} SYSTEM_TIMEOFDAY_INFORMATION, *PSYSTEM_TIMEOFDAY_INFORMATION;

//include sys header
typedef struct _THREAD_INFO
{
 LARGE_INTEGER CreateTime;
 DWORD dwUnknown1;
 DWORD dwStartAddress;
 DWORD StartEIP;
 DWORD dwOwnerPID;
 DWORD dwThreadId;
 DWORD dwCurrentPriority;
 DWORD dwBasePriority;
 DWORD dwContextSwitches;
 DWORD Unknown;
 DWORD WaitReason;
 
}THREADINFO, *PTHREADINFO;

typedef struct _UNICODE_STRING
{
 USHORT Length;
 USHORT MaxLength;
 PWSTR Buffer;
} UNICODE_STRING;

typedef struct _SYSTEM_PROCESS_INFORMATION
{
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER SpareLi1;
    LARGE_INTEGER SpareLi2;
    LARGE_INTEGER SpareLi3;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    DWORD BasePriority;
    DWORD UniqueProcessId;
    DWORD InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG PageDirectoryFrame;

    //
    // This part corresponds to VM_COUNTERS_EX.
    // NOTE: *NOT* THE SAME AS VM_COUNTERS!
    //
    ULONG PeakVirtualSize;
    ULONG VirtualSize;
    ULONG PageFaultCount;
    ULONG PeakWorkingSetSize;
    ULONG WorkingSetSize;
    ULONG QuotaPeakPagedPoolUsage;
    ULONG QuotaPagedPoolUsage;
    ULONG QuotaPeakNonPagedPoolUsage;
    ULONG QuotaNonPagedPoolUsage;
    ULONG PagefileUsage;
    ULONG PeakPagefileUsage;
    ULONG PrivateUsage;

    //
    // This part corresponds to IO_COUNTERS
    //
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;

    THREADINFO TH[1];
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;


typedef struct _SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION {
    LARGE_INTEGER IdleTime;
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER DpcTime;
    LARGE_INTEGER InterruptTime;
    ULONG InterruptCount;
} SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION, *PSYSTEM_PROCESSOR_PERFORMANCE_INFORMATION;


typedef struct _SYSTEM_BASIC_INFORMATION
{
    ULONG Reserved;
    ULONG TimerResolution;
    ULONG PageSize;
    ULONG NumberOfPhysicalPages;
    ULONG LowestPhysicalPageNumber;
    ULONG HighestPhysicalPageNumber;
    ULONG AllocationGranularity;
    ULONG MinimumUserModeAddress;
    ULONG MaximumUserModeAddress;
    ULONG ActiveProcessorsAffinityMask;
    CCHAR NumberOfProcessors;
} SYSTEM_BASIC_INFORMATION, *PSYSTEM_BASIC_INFORMATION;

//void Button2Click();//参数是进程ID

//需要保存的进程信息
typedef struct SF_CPU_INFO
{
	DWORD dwPID;
	LPTSTR lpBaseName;
	UINT cpuusage;
	PROCESS_MEMORY_COUNTERS mem;
	DWORD handleCount;
	LPTSTR lpImage;
	//wchar_t lpImage[MAX_PATH];
}SF_CPU_INFO;


