#ifndef DBG_STATUS_H
#define DBG_STATUS_H

#ifndef KERNEL_USE
#include <Windows.h>
typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;
#else
#include <ntddk.h>
#endif


typedef enum _DBG_STATE {
    DbgIdle,                        // 无待处理事件
    DbgReplyPending,                // 等待调试器回复
    DbgCreateThreadStateChange,     // 线程创建
    DbgCreateProcessStateChange,    // 进程创建
    DbgExitThreadStateChange,       // 线程退出
    DbgExitProcessStateChange,      // 进程退出
    DbgExceptionStateChange,        // 异常发生
    DbgBreakpointStateChange,       // 断点命中
    DbgSingleStepStateChange,       // 单步陷阱
    DbgLoadDllStateChange,          // DLL 加载
    DbgUnloadDllStateChange         // DLL 卸载
} DBG_STATE, * PDBG_STATE;

typedef struct _DBGKM_EXCEPTION {
    EXCEPTION_RECORD ExceptionRecord;
    ULONG FirstChance;
} DBGKM_EXCEPTION, * PDBGKM_EXCEPTION;

typedef struct _DBGKM_CREATE_THREAD {
    ULONG SubSystemKey;
    PVOID StartAddress;
} DBGKM_CREATE_THREAD, * PDBGKM_CREATE_THREAD;

typedef struct _DBGUI_CREATE_THREAD {
    HANDLE HandleToThread;
    DBGKM_CREATE_THREAD NewThread;
} DBGUI_CREATE_THREAD, * PDBGUI_CREATE_THREAD;

typedef struct _DBGKM_CREATE_PROCESS {
    ULONG SubSystemKey;
    HANDLE FileHandle;
    PVOID BaseOfImage;
    ULONG DebugInfoFileOffset;
    ULONG DebugInfoSize;
    DBGKM_CREATE_THREAD InitialThread;
} DBGKM_CREATE_PROCESS, * PDBGKM_CREATE_PROCESS;

typedef struct _DBGUI_CREATE_PROCESS {
    HANDLE HandleToProcess;
    HANDLE HandleToThread;
    DBGKM_CREATE_PROCESS NewProcess;
} DBGUI_CREATE_PROCESS, * PDBGUI_CREATE_PROCESS;

typedef struct _DBGKM_EXIT_THREAD {
    NTSTATUS ExitStatus;
} DBGKM_EXIT_THREAD, * PDBGKM_EXIT_THREAD;

typedef struct _DBGKM_EXIT_PROCESS {
    NTSTATUS ExitStatus;
} DBGKM_EXIT_PROCESS, * PDBGKM_EXIT_PROCESS;

typedef struct _DBGKM_LOAD_DLL {
    HANDLE FileHandle;
    PVOID BaseOfDll;
    ULONG DebugInfoFileOffset;
    ULONG DebugInfoSize;
    PVOID NamePointer;
} DBGKM_LOAD_DLL, * PDBGKM_LOAD_DLL;

typedef struct _DBGKM_UNLOAD_DLL {
    PVOID BaseAddress;
} DBGKM_UNLOAD_DLL, * PDBGKM_UNLOAD_DLL;

typedef struct _DBGUI_WAIT_STATE_CHANGE {
    DBG_STATE NewState;           // 指示当前调试状态，决定下方联合体使用哪个成员
    CLIENT_ID AppClientId;        // 发生事件的进程/线程 ID
    union {
        DBGKM_EXCEPTION Exception;
        DBGUI_CREATE_THREAD CreateThread;
        DBGUI_CREATE_PROCESS CreateProcessInfo;
        DBGKM_EXIT_THREAD ExitThread;
        DBGKM_EXIT_PROCESS ExitProcess;
        DBGKM_LOAD_DLL LoadDll;
        DBGKM_UNLOAD_DLL UnloadDll;
    } StateInfo;
} DBGUI_WAIT_STATE_CHANGE, * PDBGUI_WAIT_STATE_CHANGE;

#endif
