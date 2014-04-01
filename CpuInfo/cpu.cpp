#include "cpu.h"

CRITICAL_SECTION    PerfDataCriticalSection;
CpuData             *pPerfDataOld = NULL; /* Older perf data (saved to establish delta values) */
CpuData             *pPerfData = NULL;    /* Most recent copy of perf data */
ULONG               ProcessCountOld = 0;
ULONG               ProcessCount = 0;
SYSTEM_BASIC_INFORMATION        SystemBasicInfo;
SYSTEM_PERFORMANCE_INFORMATION    SystemPerfInfo;
PSYSTEM_PROCESSOR_PERFORMANCE_INFORMATION SystemProcessorTimeInfo = NULL;
LARGE_INTEGER                    liOldIdleTime = {{0,0}};
double                            dbIdleTime;
double                            dbKernelTime;
double                            dbSystemTime;
double                            OldKernelTime = 0;
LARGE_INTEGER                    liOldSystemTime = {{0,0}};
long ( __stdcall *NtQuerySystemInformation )( DWORD, PVOID, DWORD, DWORD* );

//保存5个进程的进程信息
SF_CPU_INFO *sfTopCpu;

//保存指向pPerfData的指针，用于排序
CpuData **ppSortData = NULL;

//日志信息
//time_t newTime;
//struct tm *sysTime;
SYSTEMTIME systemTime;


char logName[] = "CPU消耗前5进程信息数据.csv";
FILE *fp = NULL;



//为进程信息的存储分配内存
void initSFStruct()
{
	sfTopCpu = (SF_CPU_INFO *)calloc(sizeof(SF_CPU_INFO), TOP_NUM);

	for (int i = 0; i < TOP_NUM; i++)
	{
		sfTopCpu[i].lpImage = (LPTSTR)calloc(sizeof(TCHAR), MAX_PATH);
		sfTopCpu[i].lpBaseName = (LPTSTR)calloc(sizeof(TCHAR), MAX_PATH);
	}
}


//根据cpu占用率排序,貌似排反了...
void quickSort(CpuData **ppSortData, int l, int r)
{
	if (l < r)
	{
		int i = l, j = r;
		CpuData *x = ppSortData[l];
		while (i < j)
		{
			while(i < j && ppSortData[j]->cpuusage >= x->cpuusage)
			{
				j--;
			}
			if (i < j)
			{
				ppSortData[i++] = ppSortData[j];
			}
			while (i < j && ppSortData[j]->cpuusage < x->cpuusage)
			{
				i++;
			}
			if (i < j)
			{
				ppSortData[j--] = ppSortData[i];
			}
			ppSortData[i] = x;
			quickSort(ppSortData, l, i - 1);
			quickSort(ppSortData, i + 1, r);
		}
	}
}

//提升本程序权限,否则一些进程的OpenProcess()会失败
BOOL EnableDebugPrivilege()
{
	HANDLE hToken = NULL;
	LUID luid = {0};
	TOKEN_PRIVILEGES tp = {0};
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		return FALSE;
	}
	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid))
	{
		CloseHandle(hToken);
		return FALSE;
	}
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL))
	{
		CloseHandle(hToken);
		return FALSE;
	}
	return TRUE;
}

//网上的代码
BOOL PerfDataInitialize(void)
{
	
    SID_IDENTIFIER_AUTHORITY NtSidAuthority = {SECURITY_NT_AUTHORITY};
    NTSTATUS status;
	//(__stdcall*)
	//typedef long(__stdcall *MYSYSINFO)(DWORD, PVOID, DWORD, DWORD*);
	typedef long(__stdcall *NtQuerySystemInformationTT)(DWORD, PVOID, DWORD, DWORD*);
	//wprintf(L"Debugger!\n");
	
    InitializeCriticalSection(&PerfDataCriticalSection);
	HMODULE hDll = GetModuleHandle(TEXT("ntdll.dll"));
	//wprintf(L"hDll = %p, eror:%d\n", hDll, GetLastError());
	NtQuerySystemInformation = (NtQuerySystemInformationTT)GetProcAddress(hDll, "NtQuerySystemInformation");

	//wprintf(L"address = %p\n", NtQuerySystemInformation);
	//Get number of processors in the system
    status = NtQuerySystemInformation(0, &SystemBasicInfo, sizeof(SystemBasicInfo), NULL);
	//printf("Ntqueryfunc_status = %d\n");
    if (status != NO_ERROR)
	{
		printf("NtQuery Fail!\n");
		return FALSE;
	}
      
    //Create the SYSTEM Sid

    return TRUE;
}
//网上的代码
void PerfDataUninitialize(void)
{
    DeleteCriticalSection(&PerfDataCriticalSection);
}

//网上的代码
void GetAllProcCPUUsage()
{
    ULONG										ulSize;
    LONG										status;
    LPBYTE										pBuffer;
    ULONG										BufferSize;
    PSYSTEM_PROCESS_INFORMATION					pSPI;
    pCpuData									pPDOld;
    ULONG										Idx, Idx2;
    HANDLE										hProcess;
    HANDLE										hProcessToken;
    double										CurrentKernelTime;
    SYSTEM_PERFORMANCE_INFORMATION				SysPerfInfo;
    SYSTEM_TIMEOFDAY_INFORMATION				SysTimeInfo;
 PSYSTEM_PROCESSOR_PERFORMANCE_INFORMATION		SysProcessorTimeInfo;
    ULONG										Buffer[64]; /* must be 4 bytes aligned! */

 

    //Get new system time 
    status = NtQuerySystemInformation(3, &SysTimeInfo, sizeof(SysTimeInfo), 0);
    if (status != NO_ERROR)
        return;

    //Get new CPU's idle time 
    status = NtQuerySystemInformation(2, &SysPerfInfo, sizeof(SysPerfInfo), NULL);
    if (status != NO_ERROR)
        return;

    //Get processor time information 
    SysProcessorTimeInfo = (PSYSTEM_PROCESSOR_PERFORMANCE_INFORMATION)HeapAlloc(GetProcessHeap(), 0, sizeof(SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION) * SystemBasicInfo.NumberOfProcessors);
    status = NtQuerySystemInformation(8, SysProcessorTimeInfo, sizeof(SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION) * SystemBasicInfo.NumberOfProcessors, &ulSize);
    if (status != NO_ERROR)
        return;

    /* Get process information
     * We don't know how much data there is so just keep
     * increasing the buffer size until the call succeeds
     */
    BufferSize = 0;
    do
    {
        BufferSize += 0x10000;
        pBuffer = (LPBYTE)HeapAlloc(GetProcessHeap(), 0, BufferSize);

        status = NtQuerySystemInformation(5, pBuffer, BufferSize, &ulSize);

        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            HeapFree(GetProcessHeap(), 0, pBuffer);
        }

    } while (status == STATUS_INFO_LENGTH_MISMATCH);

    EnterCriticalSection(&PerfDataCriticalSection);

    /*
     * Save system performance info
     */
    memcpy(&SystemPerfInfo, &SysPerfInfo, sizeof(SYSTEM_PERFORMANCE_INFORMATION));

    /*
     * Save system processor time info
     */
    if (SystemProcessorTimeInfo)
	{
        HeapFree(GetProcessHeap(), 0, SystemProcessorTimeInfo);
    }
    SystemProcessorTimeInfo = SysProcessorTimeInfo;

    /*
     * Save system handle info
     */

    for (CurrentKernelTime=0, Idx=0; Idx<(ULONG)SystemBasicInfo.NumberOfProcessors; Idx++) {
        CurrentKernelTime += Li2Double(SystemProcessorTimeInfo[Idx].KernelTime);
        CurrentKernelTime += Li2Double(SystemProcessorTimeInfo[Idx].DpcTime);
        CurrentKernelTime += Li2Double(SystemProcessorTimeInfo[Idx].InterruptTime);
    }

    /* If it's a first call - skip idle time calcs */
    if (liOldIdleTime.QuadPart != 0) {
        /*  CurrentValue = NewValue - OldValue */
        dbIdleTime = Li2Double(SysPerfInfo.IdleProcessTime) - Li2Double(liOldIdleTime);
        dbKernelTime = CurrentKernelTime - OldKernelTime;
        dbSystemTime = Li2Double(SysTimeInfo.CurrentTime) - Li2Double(liOldSystemTime);

        /*  CurrentCpuIdle = IdleTime / SystemTime */
        dbIdleTime = dbIdleTime / dbSystemTime;
        dbKernelTime = dbKernelTime / dbSystemTime;

        /*  CurrentCpuUsage% = 100 - (CurrentCpuIdle * 100) / NumberOfProcessors */
        dbIdleTime = 100.0 - dbIdleTime * 100.0 / (double)SystemBasicInfo.NumberOfProcessors; /* + 0.5; */
        dbKernelTime = 100.0 - dbKernelTime * 100.0 / (double)SystemBasicInfo.NumberOfProcessors; /* + 0.5; */
    }

    /* Store new CPU's idle and system time */
    liOldIdleTime = SysPerfInfo.IdleProcessTime;
    liOldSystemTime = SysTimeInfo.CurrentTime;
    OldKernelTime = CurrentKernelTime;

    /* Determine the process count
     * We loop through the data we got from NtQuerySystemInformation
     * and count how many structures there are (until RelativeOffset is 0)
     */
    ProcessCountOld = ProcessCount;
    ProcessCount = 0;
    pSPI = (PSYSTEM_PROCESS_INFORMATION)pBuffer;
    while (pSPI) 
	{
        ProcessCount++;
        if (pSPI->NextEntryOffset == 0)
            break;
        pSPI = (PSYSTEM_PROCESS_INFORMATION)((LPBYTE)pSPI + pSPI->NextEntryOffset);
    }

    /* Now alloc a new PERFDATA array and fill in the data */
    if (pPerfDataOld) {
        HeapFree(GetProcessHeap(), 0, pPerfDataOld);
    }
    pPerfDataOld = pPerfData;
    pPerfData = (pCpuData)HeapAlloc(GetProcessHeap(), 0, sizeof(CpuData) * ProcessCount);
    pSPI = (PSYSTEM_PROCESS_INFORMATION)pBuffer;
    for (Idx=0; Idx<ProcessCount; Idx++) 
	{
        /* Get the old perf data for this process (if any) */
        /* so that we can establish delta values */
        pPDOld = NULL;
        for (Idx2=0; Idx2<ProcessCountOld; Idx2++) 
		{
            if (pPerfDataOld[Idx2].dwPID == pSPI->UniqueProcessId) 
			{
                pPDOld = &pPerfDataOld[Idx2];
                break;
            }
        }

        /* Clear out process perf data structure */
        memset(&pPerfData[Idx], 0, sizeof(CpuData));

        pPerfData[Idx].dwPID = pSPI->UniqueProcessId;

        if (pPDOld)   
		{
            double    CurTime = Li2Double(pSPI->KernelTime) + Li2Double(pSPI->UserTime);
            double    OldTime = Li2Double(pPDOld->KernelTime) + Li2Double(pPDOld->UserTime);
            double    CpuTime = (CurTime - OldTime) / dbSystemTime;
            CpuTime = CpuTime * 100.0 / (double)SystemBasicInfo.NumberOfProcessors; /* + 0.5; */
            pPerfData[Idx].cpuusage = (ULONG)CpuTime;
        }
        pPerfData[Idx].cputime.QuadPart = pSPI->UserTime.QuadPart + pSPI->KernelTime.QuadPart;

        if (pSPI->UniqueProcessId != NULL)
		{
            hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | READ_CONTROL, FALSE, PtrToUlong(pSPI->UniqueProcessId));
            if (hProcess)
			{
                /* don't query the information of the system process. It's possible but
                   returns Administrators as the owner of the process instead of SYSTEM */
                if (pSPI->UniqueProcessId != 0x4)
                {
                    if (OpenProcessToken(hProcess, TOKEN_QUERY, &hProcessToken))
                    {
                        DWORD RetLen = 0;
                        BOOL Ret;

                        Ret = GetTokenInformation(hProcessToken, TokenUser, (LPVOID)Buffer, sizeof(Buffer), &RetLen);
                        CloseHandle(hProcessToken);
					}

                 }

                CloseHandle(hProcess);
            }
        }
        pPerfData[Idx].UserTime.QuadPart = pSPI->UserTime.QuadPart;
        pPerfData[Idx].KernelTime.QuadPart = pSPI->KernelTime.QuadPart;
        pSPI = (PSYSTEM_PROCESS_INFORMATION)((LPBYTE)pSPI + pSPI->NextEntryOffset);
    }
    HeapFree(GetProcessHeap(), 0, pBuffer);
    LeaveCriticalSection(&PerfDataCriticalSection);
}

int PerfGetIndexByProcessId(DWORD dwProcessId)
{
    int Index, FoundIndex = -1;

    EnterCriticalSection(&PerfDataCriticalSection);

    for (Index = 0; Index < (int)ProcessCount; Index++)
    {
        if ((DWORD)pPerfData[Index].dwPID == dwProcessId)
        {
            FoundIndex = Index;
            break;
        }
    }

    LeaveCriticalSection(&PerfDataCriticalSection);

    return FoundIndex;
}

 

ULONG GetTopCpuProcess(DWORD dwProcessId)
{
    ULONG    CpuUsage;
    int Index, FoundIndex = -1;

    EnterCriticalSection(&PerfDataCriticalSection);


	//ppSortData保存指向pPerfData中CpuData的指针
	ppSortData = (pCpuData *)malloc(sizeof(pCpuData)*(int)ProcessCount);
	for (Index = 0; Index < (int)ProcessCount; Index++)
	{
		ppSortData[Index] = &pPerfData[Index];
	}

	//按cpu占有率大小排序,第一次排序的结果无效
	quickSort(ppSortData, 0, (int)ProcessCount - 1);

	//printf("mark\n");
	//保存cpu占用率最大的前5个进程id和cpuusage到sfTopCpu中
	for (int tmp = 0, Index = (int)ProcessCount - 1; Index > (int)ProcessCount - 1 - TOP_NUM; Index--, tmp++)
	{
		printf("tmp=%d,Index=%d,pscount=%d\n", tmp, Index, ProcessCount);
		if (ProcessCount == 0)
		{
			continue;
		}
		//printf("sfTopCpu[%d].dwPID = ppSortData[%d]->dwPID = %d\n", tmp, Index, ppSortData[Index]->dwPID);
		sfTopCpu[tmp].dwPID = ppSortData[Index]->dwPID;
		sfTopCpu[tmp].cpuusage = ppSortData[Index]->cpuusage;
	}


	//获取系统时间
	//time(&newTime);
	//sysTime = localtime(&newTime);
	GetLocalTime(&systemTime);

	//保存到日志文件
	if ((fp = fopen(logName, "a")) == NULL)
	{
		printf("打开日志文件失败！\n");
		return 1;
	}

	//获取并保存前5个进程的相关信息
	for (Index = 0; Index < TOP_NUM; Index++)
	{
		
		HANDLE hProcess;
		//打开进程
		hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, sfTopCpu[Index].dwPID);
		
		//获取进程占用内存
		int rrr = GetProcessMemoryInfo(hProcess, &sfTopCpu[Index].mem, sizeof(sfTopCpu[Index].mem));

		//获取进程打开句柄数
		rrr = GetProcessHandleCount(hProcess, &(sfTopCpu[Index].handleCount));

		//获取文件名称和进程文件路径时对pid=0的进程特殊处理
		if (sfTopCpu[Index].dwPID == 0)
		{
			sfTopCpu[Index].lpBaseName = TEXT("SystemIdleProcess");
			sfTopCpu[Index].lpImage = TEXT("SystemIdleProcess");
		}
		else
		{
			//获取进程文件名称char *tmp1 = strrchr(bigImgName, '\\'); tmp1 == 0 ? tmp1 = bigImgName : tmp1 = tmp1 + 1;
			//rrr = GetModuleBaseName(hProcess, NULL, sfTopCpu[Index].lpBaseName, MAX_PATH + 1);
			rrr = GetProcessImageFileName(hProcess, sfTopCpu[Index].lpImage, MAX_PATH + 1);
			if (rrr == 0)//如果获取到的进程名称长度为0,则认为是获取失败
			{
				sfTopCpu[Index].lpBaseName = TEXT("无权限");
				sfTopCpu[Index].lpImage = TEXT("无权限");
			}
			else
			{
				//获取进程文件路径
				//rrr = GetModuleFileNameEx(hProcess, NULL, sfTopCpu[Index].lpImage, MAX_PATH + 1);
				if (sizeof(TCHAR) == sizeof(char))
				{
					char *tmp1 = strrchr((char*)sfTopCpu[Index].lpImage, '\\'); tmp1 == 0 ? tmp1 = (char*)sfTopCpu[Index].lpImage : tmp1 = tmp1 + 1;
					sfTopCpu[Index].lpBaseName = (LPTSTR)tmp1;
				}
				else
				{
					wchar_t *tmp2 = wcsrchr((wchar_t*)sfTopCpu[Index].lpImage, L'\\'); tmp2 == 0 ? tmp2 = (wchar_t*)sfTopCpu[Index].lpImage : tmp2 = tmp2 + 1;
					sfTopCpu[Index].lpBaseName = (LPTSTR)tmp2;
				}
				
			}	
		}
		//printf("Index=%d, pid=%d,name=%ls, path=%ls\n", Index, sfTopCpu[Index].dwPID, sfTopCpu[Index].lpBaseName, sfTopCpu[Index].lpImage);

		//关闭句柄
		CloseHandle(hProcess);

		//保存进程信息
		/*printf("%d-%02d-%02d,%02d:%02d:%02d,%d,%d,%ls,%d,%d,%d,%ls\n", systemTime.wYear, systemTime.wMonth, systemTime.wDay, systemTime.wHour, systemTime.wMinute, systemTime.wSecond,
			Index + 1, sfTopCpu[Index].dwPID, sfTopCpu[Index].lpBaseName, sfTopCpu[Index].cpuusage, sfTopCpu[Index].mem.WorkingSetSize / 1024,
			sfTopCpu[Index].handleCount, sfTopCpu[Index].lpImage);*/
		fprintf(fp, "%d-%02d-%02d,%02d:%02d:%02d,%d,%d,%ls,%d,%d,%d,%ls\n",
			systemTime.wYear, systemTime.wMonth, systemTime.wDay, systemTime.wHour, systemTime.wMinute, systemTime.wSecond,
			Index + 1, sfTopCpu[Index].dwPID, sfTopCpu[Index].lpBaseName, sfTopCpu[Index].cpuusage, sfTopCpu[Index].mem.WorkingSetSize/1024,
			sfTopCpu[Index].handleCount, sfTopCpu[Index].lpImage
			);
	}
	
    LeaveCriticalSection(&PerfDataCriticalSection);
	fclose(fp);

	return 0;
}





int main(void)
{
	//保存到日志文件
	if ((fp = fopen(logName, "a")) == NULL)
	{
		printf("打开日志文件《%s》失败！\n", logName);
		return 1;
	}
	else
	{
		fprintf(fp, "Date,Time,Top,进程id,进程名,CPU占有率(%%),占用内存(KB),句柄数,文件路径\n");
	 	fclose(fp);
	}

	//提升本程序权限
	BOOL x = EnableDebugPrivilege();
	if (!x)
	{
		printf("权限不足,部分进程信息无法获取！\n");
	}
	
	//wprintf(L"1\n");
	initSFStruct();
	//wprintf(L"2\n");
	PerfDataInitialize();
	
	printf("正在记录进程信息...\n\n信息保存在《%s》中\n\n(按Ctrl+C结束程序)\n",logName ); 
	//循环获取进程信息
	while(1)
	{
		GetAllProcCPUUsage();
		GetTopCpuProcess(0);
		//间隔事件
		Sleep(QUERT_TIME);
	}
	fclose(fp);
 return 0;
}


