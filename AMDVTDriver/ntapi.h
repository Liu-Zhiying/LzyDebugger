#ifndef NTAPI_H
#define NTAPI_H

#pragma warning(disable : 4201)

typedef struct _KAPC_STATE {
	LIST_ENTRY ApcListHead[MaximumMode];
	struct _KPROCESS* Process;
	union {
		UCHAR InProgressFlags;
		struct {
			BOOLEAN KernelApcInProgress : 1;
			BOOLEAN SpecialApcInProgress : 1;
		};
	};

	BOOLEAN KernelApcPending;
	union {
		BOOLEAN UserApcPendingAll;
		struct {
			BOOLEAN SpecialUserApcPending : 1;
			BOOLEAN UserApcPending : 1;
		};
	};
} KAPC_STATE, * PKAPC_STATE, * PRKAPC_STATE;

#ifdef __cplusplus
extern "C" {
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
	_IRQL_requires_max_(APC_LEVEL)
		NTKERNELAPI
		VOID
		KeStackAttachProcess(
			_Inout_ PRKPROCESS PROCESS,
			_Out_ PRKAPC_STATE ApcState
		);
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
	_IRQL_requires_max_(APC_LEVEL)
		NTKERNELAPI
		VOID
		KeUnstackDetachProcess(
			_In_ PRKAPC_STATE ApcState
		);
#endif

_Must_inspect_result_
_IRQL_requires_max_(APC_LEVEL)
NTKERNELAPI
NTSTATUS
PsLookupProcessByProcessId(
	_In_ HANDLE ProcessId,
	_Outptr_ PEPROCESS* Process
);

#ifdef __cplusplus
}
#endif

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation = 0,
	SystemPerformanceInformation = 2,
	SystemTimeOfDayInformation = 3,
	SystemProcessInformation = 5,
	SystemProcessorPerformanceInformation = 8,
	SystemInterruptInformation = 23,
	SystemExceptionInformation = 33,
	SystemCrashDumpStateInformation = 34,
	SystemKernelDebuggerInformation = 35, // 用于检测内核调试器
	SystemContextSwitchInformation = 36,
	SystemRegistryQuotaInformation = 37,
	SystemLookasideInformation = 45,
	SystemCodeIntegrityInformation = 103
} SYSTEM_INFORMATION_CLASS;

typedef enum _SYSDBG_COMMAND {
	SysDbgQueryMemory,                    // 0
	SysDbgQuerySpecialMemory,             // 1
	SysDbgReadMemory,                     // 2  读内核虚拟内存
	SysDbgWriteMemory,                    // 3  写内核虚拟内存
	SysDbgReadPhysicalMemory,             // 4  读物理内存
	SysDbgWritePhysicalMemory,            // 5  写物理内存
	SysDbgReadControlSpace,               // 6  读控制空间（kd 数据块）
	SysDbgWriteControlSpace,              // 7
	SysDbgReadIoSpace,                    // 8  读 I/O 端口空间
	SysDbgWriteIoSpace,                   // 9
	SysDbgReadMsr,                        // 10 读 MSR
	SysDbgWriteMsr,                       // 11
	SysDbgReadBusData,                    // 12
	SysDbgWriteBusData,                   // 13
	SysDbgCheckLowMemory,                 // 14
	SysDbgEnableKernelDebugger,           // 15 运行时启用 kd
	SysDbgDisableKernelDebugger,          // 16 运行时禁用 kd
	SysDbgGetAutoKdEnable,                // 17
	SysDbgSetAutoKdEnable,                // 18
	SysDbgGetPrintBufferSize,             // 19
	SysDbgSetPrintBufferSize,             // 20
	SysDbgGetKdUmExceptionEnable,         // 21
	SysDbgSetKdUmExceptionEnable,         // 22
	SysDbgGetTriageDump,                  // 23
	SysDbgGetKdBlockEnable,               // 24
	SysDbgSetKdBlockEnable,               // 25
	SysDbgRegisterForUmBreakInfo,         // 26
	SysDbgGetUmBreakPid,                  // 27
	SysDbgClearUmBreakPid,                // 28
	SysDbgGetUmAttachPid,                 // 29
	SysDbgClearUmAttachPid,               // 30
	SysDbgGetLiveKernelDump,              // 31 Win10+ 触发 live dump
	SysDbgGetKdPullModeEnable,            // 32 较新版本
	SysDbgSetKdPullModeEnable,            // 33
	SysDbgMaxCommand
} SYSDBG_COMMAND;

typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION {
	BOOLEAN KernelDebuggerEnabled;      // 偏移 0x00
	BOOLEAN KernelDebuggerNotPresent;   // 偏移 0x01
} SYSTEM_KERNEL_DEBUGGER_INFORMATION, * PSYSTEM_KERNEL_DEBUGGER_INFORMATION;

typedef struct _SYSTEM_CODEINTEGRITY_INFORMATION {
	ULONG Length;
	ULONG CodeIntegrityOptions;
} SYSTEM_CODEINTEGRITY_INFORMATION, * PSYSTEM_CODEINTEGRITY_INFORMATION;

// 标志位
static constexpr UINT64 CODEINTEGRITY_OPTION_TESTSIGN = 0x02;

typedef NTSTATUS(NTAPI* PNtCreateProcess)(
	_Out_ PHANDLE				ProcessHandle,
	_In_  ACCESS_MASK			DesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_  HANDLE				ParentProcess,
	_In_  BOOLEAN				InheritObjectTable,
	_In_opt_ HANDLE				SectionHandle,
	_In_opt_ HANDLE				DebugPort,
	_In_opt_ HANDLE				ExceptionPort);

typedef NTSTATUS(NTAPI* PNtCreateFile)(
	_Out_ PHANDLE FileHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_Out_ PIO_STATUS_BLOCK IoStatusBlock,
	_In_opt_ PLARGE_INTEGER AllocationSize,
	_In_ ULONG FileAttributes,
	_In_ ULONG ShareAccess,
	_In_ ULONG CreateDisposition,
	_In_ ULONG CreateOptions,
	_In_reads_bytes_opt_(EaLength) PVOID EaBuffer,
	_In_ ULONG EaLength);

typedef NTSTATUS(NTAPI* PNtQuerySystemInformation)(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID                    SystemInformation,
	ULONG                    SystemInformationLength,
	PULONG                   ReturnLength);

typedef NTSTATUS(NTAPI* PNtSystemDebugControl)(
	__in SYSDBG_COMMAND Command,          // 要执行的操作
	__in_opt PVOID InputBuffer,           // 输入参数（结构体，视命令而定）
	__in ULONG InputBufferLength,
	__out_opt PVOID OutputBuffer,
	__in ULONG OutputBufferLength,
	__out_opt PULONG ReturnLength);

typedef NTSTATUS(NTAPI* PNtLockVirtualMemory)(
	_In_ HANDLE ProcessHandle,        // 目标进程，NtCurrentProcess()
	_Inout_ PVOID* BaseAddress,       // 区域基址，按页向下对齐
	_Inout_ PSIZE_T RegionSize,       // 大小，会被向上取整到页边界
	_In_ ULONG MapType);              // MAP_PROCESS(1) 或 MAP_SYSTEM(2

typedef NTSTATUS(NTAPI* PNtUnlockVirtualMemory)(
	_In_ HANDLE ProcessHandle,        // 目标进程，NtCurrentProcess()
	_Inout_ PVOID* BaseAddress,       // 区域基址，按页向下对齐
	_Inout_ PSIZE_T RegionSize,       // 大小，会被向上取整到页边界
	_In_ ULONG MapType);              // MAP_PROCESS(1) 或 MAP_SYSTEM(2)

typedef NTSTATUS(NTAPI* PMmCopyVirtualMemory)(
	_In_  PEPROCESS       SourceProcess,
	_In_  PVOID           SourceAddress,
	_In_  PEPROCESS       TargetProcess,
	_Out_ PVOID           TargetAddress,
	_In_  SIZE_T          BufferSize,
	_In_  KPROCESSOR_MODE PreviousMode,
	_Out_ PSIZE_T         ReturnSize);

#endif
