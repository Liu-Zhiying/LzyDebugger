#include "debugger_hook.h"
#include "Cpu.h"
#include "init.h"
#include "CtrlDefine.h"
#include "DllApiHook.h"
#include "dbgstatus.h"
#include <string>
#include <Windows.h>
#include <detours.h>
#include <tlhelp32.h>
#include <vector>

#ifdef _WIN64
#define HookDllApi HookDllApiX64
#else
#define HookDllApi HookDllApiX86
#endif

#define STATUS_UNSUCCESSFUL 0xC0000001;
#define STATUS_ACCESS_DENIED 0xC0000022;
#define STATUS_PARTIAL_COPY 0x8000000D;
#define STATUS_SUCCESS 0

#ifdef _WIN64
#define CmpAndExchange _InterlockedCompareExchange64
typedef volatile long long* PDEST;
typedef volatile long long DEST;
#else
#define CmpAndExchange _InterlockedCompareExchange
typedef volatile long* PDEST;
typedef volatile long DEST;
#endif

constexpr LPCWSTR pDriverDeviceNameIntel = L"\\\\.\\VTXDriver";

constexpr LPCWSTR pDriverDeviceNameAMD = L"\\\\.\\AMDVTDriver";

HANDLE hProcess = NULL;

bool hookEnabled = false;

#pragma unmanaged
std::string GetMainModuleName()
{
    CHAR szFileName[MAX_PATH] = {};
    DWORD length = GetModuleFileNameA(GetModuleHandleA(NULL), szFileName, MAX_PATH);

    if (GetLastError() != ERROR_SUCCESS)
        return "";

    while (szFileName[length] != '\\') --length;

    std::string result = &szFileName[++length];

    return result;
}

#pragma unmanaged
HANDLE GetDriverHandle()
{
    if (CmpAndExchange((PDEST)&hProcess, NULL, NULL) == NULL)
    {
        if (IsIntelCPU())
        {
            HANDLE hProcessCopy = CreateFileW(pDriverDeviceNameIntel, FILE_ALL_ACCESS, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            CmpAndExchange((PDEST)&hProcess, (DEST)hProcessCopy, 0);
            return hProcessCopy;
        }
        else if (IsAMDCPU())
        {
            HANDLE hProcessCopy = CreateFileW(pDriverDeviceNameAMD, FILE_ALL_ACCESS, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            CmpAndExchange((PDEST)&hProcess, (DEST)hProcessCopy, 0);
            return hProcessCopy;
        }
        else
        {
            return NULL;
        }
    }
    else
    {
        return (HANDLE)CmpAndExchange((PDEST)&hProcess, NULL, NULL);
    }
}

#pragma unmanaged
void CleanDriverHandle()
{
    if (CmpAndExchange((PDEST)&hProcess, NULL, NULL) != NULL)
    {
        HANDLE hProcessCopy = (HANDLE)CmpAndExchange((PDEST)&hProcess, NULL, NULL);
        CmpAndExchange((PDEST)&hProcess, NULL, (DEST)CmpAndExchange((PDEST)&hProcess, NULL, NULL));
        CloseHandle(hProcessCopy);
    }
}

#pragma unmanaged
bool InVirtualization()
{
    if (IsIntelCPU() && !IntelCpuIsInVirtualization()) return false;
    if (IsAMDCPU() && !AMDCpuIsInVirtualization()) return false;
    if (!IsIntelCPU() && !IsAMDCPU()) return false;
    return true;
}

#pragma unmanaged
void ShowDriverNotInitError(LPCSTR apiName)
{
    std::string messageText = "API";
    messageText += " \"";
    messageText += apiName;
    messageText += "\" ";
    messageText += "已经被接管，需要调试器内该API正常，需要启动LzyDebugger对应驱动，或者直接退出调试器重新启动！";
    MessageBoxA(NULL, messageText.c_str(), "错误", MB_OK | MB_ICONERROR);
}
typedef NTSTATUS(WINAPI* PNtReadVirtualMemory)(
    _In_ HANDLE hProcess,
    _In_ LPCVOID lpBaseAddress,
    _Out_writes_bytes_to_(nSize, *lpNumberOfBytesRead) LPVOID lpBuffer,
    _In_ SIZE_T nSize,
    _Out_opt_ SIZE_T* lpNumberOfBytesRead);

PNtReadVirtualMemory pOriginNtReadVirtualMemory = NULL;

#pragma unmanaged
NTSTATUS
WINAPI
NtReadVirtualMemoryHandler(
    _In_ HANDLE hProcess,
    _In_ LPCVOID lpBaseAddress,
    _Out_writes_bytes_to_(nSize, *lpNumberOfBytesRead) LPVOID lpBuffer,
    _In_ SIZE_T nSize,
    _Out_opt_ SIZE_T* lpNumberOfBytesRead)
{
    HANDLE hDevice = GetDriverHandle();
    if (hDevice == INVALID_HANDLE_VALUE)
    {
        ShowDriverNotInitError("NtReadVirtualMemory");
        CleanDriverHandle();
        return STATUS_ACCESS_DENIED;
    }

    RwProcessMemoryIn  info = {};
    RwProcessMemoryIn outInfo = {};
    info.pBaseAddress = (PVOID)lpBaseAddress;
    info.pBuffer = lpBuffer;
    info.nSize = nSize;
    info.processId1 = GetCurrentProcessId();
    info.processId2 = GetProcessId(hProcess);

    BOOL ok = DeviceIoControl(hDevice, IOCTL_READ_PROCESS_MEMORY,
        &info, sizeof info,
        &outInfo, sizeof outInfo,
        NULL, NULL);

    SetLastError(ERROR_SUCCESS);

    if (!ok)
    {    
        if (lpNumberOfBytesRead != NULL)
            *lpNumberOfBytesRead = 0;
        SetLastError(ERROR_PARTIAL_COPY);
        return STATUS_PARTIAL_COPY;
    }
    else
    {
        SIZE_T bytesRead = outInfo.nSizeRW;
        if (bytesRead > info.nSize) bytesRead = info.nSize;   // 截断越界值

        if (lpNumberOfBytesRead != NULL)
            *lpNumberOfBytesRead = bytesRead;

        if (bytesRead == info.nSize)
            return STATUS_SUCCESS;                             // 全部读到

        SetLastError(ERROR_PARTIAL_COPY);
        return STATUS_PARTIAL_COPY;                            // 部分读到，字节数已写回
    }
}

typedef NTSTATUS(WINAPI* PNtWriteVirtualMemory)(
    _In_ HANDLE hProcess,
    _In_ LPVOID lpBaseAddress,
    _In_reads_bytes_(nSize) LPCVOID lpBuffer,
    _In_ SIZE_T nSize,
    _Out_opt_ SIZE_T* lpNumberOfBytesWritten);

PNtWriteVirtualMemory pOriginNtWriteVirtualMemory = NULL;

#pragma unmanaged
NTSTATUS
WINAPI
NtWriteVirtualMemoryHandler(
    _In_ HANDLE hProcess,
    _In_ LPVOID lpBaseAddress,
    _In_reads_bytes_(nSize) LPCVOID lpBuffer,
    _In_ SIZE_T nSize,
    _Out_opt_ SIZE_T* lpNumberOfBytesWritten)
{
    HANDLE hDevice = GetDriverHandle();
    if (hDevice == INVALID_HANDLE_VALUE)
    {
        ShowDriverNotInitError("NtWriteVirtualMemory");
        CleanDriverHandle();
        return STATUS_ACCESS_DENIED;
    }

    RwProcessMemoryIn  info = {};
    RwProcessMemoryIn outInfo = {};
    info.pBaseAddress = lpBaseAddress;
    info.pBuffer = (PVOID)lpBuffer;
    info.nSize = nSize;
    info.processId1 = GetCurrentProcessId();
    info.processId2 = GetProcessId(hProcess);

    if (!DeviceIoControl(hDevice, IOCTL_WRITE_PROCESS_MEMORY, &info, sizeof info, &outInfo, sizeof outInfo, NULL, NULL))
    {
        if (lpNumberOfBytesWritten != NULL)
            *lpNumberOfBytesWritten = 0;
        return STATUS_ACCESS_DENIED;
    }
    else
    {
        SIZE_T bytesWritten = outInfo.nSizeRW;
        if (bytesWritten > info.nSize) bytesWritten = info.nSize;   // 截断越界值

        if (lpNumberOfBytesWritten != NULL)
            *lpNumberOfBytesWritten = bytesWritten;

        if (bytesWritten == info.nSize)
            return STATUS_SUCCESS;                             // 全部读到

        return STATUS_PARTIAL_COPY;                            // 部分读到，字节数已写回
    }
}

LONG debugEventsLock;
std::vector<DBGUI_WAIT_STATE_CHANGE> debugEvents;

#define LOCK_DEBUG_EVENTS() while (!InterlockedCompareExchange(&debugEventsLock, 1, 0)) continue;
#define UNLOCK_DEBUG_EVENTS() InterlockedCompareExchange(&debugEventsLock, 0, 1);

unsigned __stdcall AddNewDebugEvent(IN PDBGUI_WAIT_STATE_CHANGE pDebugEvent)
{
    LOCK_DEBUG_EVENTS();
    debugEvents.push_back(*pDebugEvent);
    UNLOCK_DEBUG_EVENTS();
    return 0;
}

typedef BOOL(WINAPI* PDebugBreakProcess)(
    IN HANDLE Process);

PDebugBreakProcess pOriginDebugBreakProcess = NULL;

BOOL DLL WINAPI DebugBreakProcessHandler(
    IN HANDLE Process)
{
    HANDLE hDevice = GetDriverHandle();
    if (hDevice == INVALID_HANDLE_VALUE)
    {
        ShowDriverNotInitError("NtDebugActiveProcess");
        CleanDriverHandle();
        return STATUS_ACCESS_DENIED;
    }

    UINT64 processId = GetProcessId(Process);

    if (!DeviceIoControl(hDevice, IOCTL_DEBUG_BREAK_PROCESS, &processId, sizeof processId, NULL, 0, NULL, NULL))
        return FALSE;

    return TRUE;
}

typedef NTSTATUS(NTAPI* PNtDebugActiveProcess)(
    _In_ HANDLE ProcessHandle,
    _In_ HANDLE DebugObjectHandle);

PNtDebugActiveProcess pOriginNtDebugActiveProcess = NULL;

NTSTATUS NTAPI NtDebugActiveProcessHandler(
    _In_ HANDLE ProcessHandle,
    _In_ HANDLE DebugObjectHandle)
{
    HANDLE hDevice = GetDriverHandle();
    if (hDevice == INVALID_HANDLE_VALUE)
    {
        ShowDriverNotInitError("NtDebugActiveProcess");
        CleanDriverHandle();
        return STATUS_ACCESS_DENIED;
    }

    BindDebugProcess info = {};

    info.DebuggeeProcess = GetProcessId(ProcessHandle);
    info.DebuggerProcess = GetCurrentProcessId();
    info.debugEventAddFunction = AddNewDebugEvent;

    if (info.DebuggeeProcess == info.DebuggerProcess) return STATUS_UNSUCCESSFUL;

    if (!DeviceIoControl(hDevice, IOCTL_DEBUG_ACTVIE_PROCESS, &info, sizeof info, NULL, 0, NULL, NULL))
        return STATUS_ACCESS_DENIED;

    DebugBreakProcessHandler(ProcessHandle);

    return STATUS_SUCCESS;
}

typedef NTSTATUS (NTAPI *PNtRemoveProcessDebug)(
    _In_ HANDLE ProcessHandle,
    _In_ HANDLE DebugObjectHandle);

PNtRemoveProcessDebug pOriginNtRemoveProcessDebug = NULL;

NTSTATUS NTAPI NtRemoveProcessDebugHandler(
    _In_ HANDLE ProcessHandle,
    _In_ HANDLE DebugObjectHandle)
{
    HANDLE hDevice = GetDriverHandle();
    if (hDevice == INVALID_HANDLE_VALUE)
    {
        ShowDriverNotInitError("NtDebugActiveProcess");
        CleanDriverHandle();
        return STATUS_ACCESS_DENIED;
    }

    BindDebugProcess info = {};

    info.DebuggeeProcess = GetProcessId(ProcessHandle);
    info.DebuggerProcess = GetCurrentProcessId();

    if (!DeviceIoControl(hDevice, IOCTL_REMOVE_DEBUG_PROCESS, &info, sizeof info, NULL, 0, NULL, NULL))
        return STATUS_ACCESS_DENIED;

    return STATUS_SUCCESS;
}

typedef NTSTATUS(NTAPI *PNtWaitForDebugEvent)(
    IN HANDLE DebugHandle,
    IN BOOLEAN Alertable,
    IN PLARGE_INTEGER Timeout OPTIONAL,
    OUT PDBGUI_WAIT_STATE_CHANGE StateChange);

PNtWaitForDebugEvent pOriginNtWaitForDebugEvent = NULL;

NTSTATUS NTAPI NtWaitForDebugEventHandler(
    IN HANDLE DebugHandle,
    IN BOOLEAN Alertable,
    IN PLARGE_INTEGER Timeout OPTIONAL,
    OUT PDBGUI_WAIT_STATE_CHANGE StateChange)
{
    if (Timeout == NULL)
    {
        while (debugEvents.size() == 0) continue;
        LOCK_DEBUG_EVENTS();
        *StateChange = debugEvents.front();
        debugEvents.erase(debugEvents.begin());
        UNLOCK_DEBUG_EVENTS();

        SetLastError(ERROR_SUCCESS);
        return STATUS_SUCCESS;
    }
    else
    {
        LARGE_INTEGER beginTime = {};

        LARGE_INTEGER frequency = {};
        LARGE_INTEGER endTime = {};
        LARGE_INTEGER msElapsed = {};

        QueryPerformanceFrequency(&frequency);
        QueryPerformanceCounter(&beginTime);

        while (debugEvents.size() == 0 && msElapsed.QuadPart < Timeout->QuadPart)
        {
            QueryPerformanceCounter(&endTime);
            msElapsed.QuadPart = (endTime.QuadPart - beginTime.QuadPart) * 1000 / frequency.QuadPart;
        }
        if (debugEvents.size() != 0)
        {
            LOCK_DEBUG_EVENTS();
            *StateChange = debugEvents.front();
            debugEvents.erase(debugEvents.begin());
            UNLOCK_DEBUG_EVENTS();

            SetLastError(ERROR_SUCCESS);
            return STATUS_SUCCESS;
        }
        else
        {
            SetLastError(ERROR_TIMEOUT);
            return STATUS_TIMEOUT;
        }
    }
}

BOOL __declspec(dllexport) WINAPI DllMain(
    HINSTANCE hinstDLL,
    DWORD     fdwReason,
    LPVOID    lpvReserved
)
{
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
    {
        
        //白名单
        if (GetMainModuleName() == "LzyDebugger.exe")
            break;

        if (GetMainModuleName() == "LzyDebuggerConsole.exe")
            break;

        SetConsoleReady();
        hookEnabled = true;

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        pOriginNtReadVirtualMemory = (PNtReadVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtReadVirtualMemory");
        DetourAttach(&(PVOID&)pOriginNtReadVirtualMemory, NtReadVirtualMemoryHandler);
        pOriginNtWriteVirtualMemory = (PNtWriteVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory");
        DetourAttach(&(PVOID&)pOriginNtWriteVirtualMemory, NtWriteVirtualMemoryHandler);

        pOriginNtDebugActiveProcess = (PNtDebugActiveProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtDebugActiveProcess");
        DetourAttach(&(PVOID&)pOriginNtDebugActiveProcess, NtDebugActiveProcessHandler);
        pOriginNtRemoveProcessDebug = (PNtRemoveProcessDebug)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtRemoveProcessDebug");
        DetourAttach(&(PVOID&)pOriginNtRemoveProcessDebug, NtRemoveProcessDebugHandler);

        pOriginNtWaitForDebugEvent = (PNtWaitForDebugEvent)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWaitForDebugEvent");
        DetourAttach(&(PVOID&)pOriginNtWaitForDebugEvent, NtWaitForDebugEventHandler);

        pOriginDebugBreakProcess = (PDebugBreakProcess)GetProcAddress(GetModuleHandleA("kernel32.dll"), "DebugBreakProcess");
        DetourAttach(&(PVOID&)pOriginDebugBreakProcess, DebugBreakProcessHandler);

        DetourTransactionCommit();

        //HookDllApi(GetModuleHandleA("ntdll.dll"), "NtReadVirtualMemory", (PVOID&)pOriginNtReadVirtualMemory, NtReadVirtualMemoryHandler);
        //HookDllApi(GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory", (PVOID&)pOriginNtWriteVirtualMemory, NtWriteVirtualMemoryHandler);

        break;
    }
    case DLL_PROCESS_DETACH:
    {
        //白名单
        if (!hookEnabled)
            break;
        CleanDriverHandle();

        break;
    }
    }

    return TRUE;
}