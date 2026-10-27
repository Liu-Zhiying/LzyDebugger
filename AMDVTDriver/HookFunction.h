#ifndef HOOK_FUNCTION_H
#define HOOK_FUNCTION_H

#include "main.h"

constexpr ULONG HOOK_FUNCTION_TAG = MAKE_TAG('h', 'f', '_', ' ');

class HookFunctionManager
{
private:

	static NTSTATUS NTAPI NtCreateProcessHandler(
		_Out_ PHANDLE				ProcessHandle,
		_In_  ACCESS_MASK			DesiredAccess,
		_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
		_In_  HANDLE				ParentProcess,
		_In_  BOOLEAN				InheritObjectTable,
		_In_opt_ HANDLE				SectionHandle,
		_In_opt_ HANDLE				DebugPort,
		_In_opt_ HANDLE				ExceptionPort);

	static NTSTATUS NTAPI NtCreateFileHandler(
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

	static NTSTATUS NTAPI NtQuerySystemInformationHandler(
		SYSTEM_INFORMATION_CLASS SystemInformationClass,
		PVOID                    SystemInformation,
		ULONG                    SystemInformationLength,
		PULONG                   ReturnLength);

	static NTSTATUS NTAPI NtSystemDebugControlHandler(
		__in SYSDBG_COMMAND Command,          // 要执行的操作
		__in_opt PVOID InputBuffer,           // 输入参数（结构体，视命令而定）
		__in ULONG InputBufferLength,
		__out_opt PVOID OutputBuffer,
		__in ULONG OutputBufferLength,
		__out_opt PULONG ReturnLength);

#pragma data_seg()
	inline static bool isInited = false;
	inline static PNtCreateProcess pOldNtCreateProcess = NULL;
	inline static PNtCreateProcess pNtCreateProcessCaller = NULL;

	inline static PNtCreateFile pOldNtCreateFile = NULL;
	inline static PNtCreateFile pNtCreateFileCaller = NULL;

	inline static PNtQuerySystemInformation pOldNtQuerySystemInformation = NULL;
	inline static PNtQuerySystemInformation pNtQuerySystemInformationCaller = NULL;

	inline static PNtSystemDebugControl pOldNtSystemDebugControl = NULL;
	inline static PNtSystemDebugControl pNtSystemDebugControlCaller = NULL;

	inline static unsigned char buffer[sizeof(KernelVector<SyscallIndexIn, HOOK_FUNCTION_TAG, NonPaged>)];
#pragma data_seg()
public:

#pragma code_seg("PAGE")
	static NTSTATUS Init()
	{
		if (!isInited)
		{
			CallConstructor((KernelVector<SyscallIndexIn, HOOK_FUNCTION_TAG, NonPaged>*)buffer);
			isInited = true;
		}
		return STATUS_SUCCESS;
	}
#pragma code_seg("PAGE")
	static void Deinit()
	{
		if (isInited)
		{
			CallDestroyer((KernelVector<SyscallIndexIn, HOOK_FUNCTION_TAG, NonPaged>*)buffer);
			isInited = false;
		}
	}
	static void SetSyscallIndex(char* pFunctionName, UINT32 index);
	static UINT32 GetSyscallIndex(char* pFunctionName);
#pragma code_seg("PAGE")
	static void HookSSDT(PVOID pSSDT, GlobalManager* pGlobalManager)
	{
		UNREFERENCED_PARAMETER(pSSDT);
		UNREFERENCED_PARAMETER(pGlobalManager);

		NptHookRecord record = {};

		UINT32 index = GetSyscallIndex("NtCreateProcess");

		pOldNtCreateProcess = (PNtCreateProcess)GetSubFunctionInSSDTByIndex(pSSDT, index);
		pNtCreateProcessCaller = (PNtCreateProcess)pGlobalManager->functionCallerManager.GetFunctionCaller(pOldNtCreateProcess);

		record.pOriginVirtAddr = pOldNtCreateProcess;
		record.pGotoVirtAddr = NtCreateProcessHandler;

		pGlobalManager->nptHookManager.AddHook(record);

		index = GetSyscallIndex("NtCreateFile");

		pOldNtCreateFile = (PNtCreateFile)GetSubFunctionInSSDTByIndex(pSSDT, index);
		pNtCreateFileCaller = (PNtCreateFile)pGlobalManager->functionCallerManager.GetFunctionCaller(pOldNtCreateFile);

		record.pOriginVirtAddr = pOldNtCreateFile;
		record.pGotoVirtAddr = NtCreateFileHandler;

		pGlobalManager->nptHookManager.AddHook(record);

		// IOCTL 派发时当前就是用户进程上下文
		PHYSICAL_ADDRESS pa = MmGetPhysicalAddress((PVOID)0x7FFE0000);
		if (!pa.QuadPart) return;

		PKUSER_SHARED_DATA pUserData = (PKUSER_SHARED_DATA)MmMapIoSpace(pa, PAGE_SIZE, MmNonCached);
		if (pUserData == NULL) return;

		pUserData->KdDebuggerEnabled = FALSE;

		MmUnmapIoSpace(pUserData, PAGE_SIZE);

		index = GetSyscallIndex("NtQuerySystemInformation");

		pOldNtQuerySystemInformation = (PNtQuerySystemInformation)GetSubFunctionInSSDTByIndex(pSSDT, index);
		pNtQuerySystemInformationCaller = (PNtQuerySystemInformation)pGlobalManager->functionCallerManager.GetFunctionCaller(pOldNtQuerySystemInformation);

		record.pOriginVirtAddr = pOldNtQuerySystemInformation;
		record.pGotoVirtAddr = NtQuerySystemInformationHandler;

		pGlobalManager->nptHookManager.AddHook(record);

		index = GetSyscallIndex("NtSystemDebugControl");

		pOldNtSystemDebugControl = (PNtSystemDebugControl)GetSubFunctionInSSDTByIndex(pSSDT, index);
		pNtSystemDebugControlCaller = (PNtSystemDebugControl)pGlobalManager->functionCallerManager.GetFunctionCaller(pOldNtSystemDebugControl);

		record.pOriginVirtAddr = pOldNtSystemDebugControl;
		record.pGotoVirtAddr = NtSystemDebugControlHandler;

		pGlobalManager->nptHookManager.AddHook(record);
	}
#pragma code_seg("PAGE")
	static void UnhookSSDT(GlobalManager* pGlobalManager)
	{
		pGlobalManager->nptHookManager.RemoveHook(pOldNtCreateProcess);
		pGlobalManager->functionCallerManager.RemoveFunctionCaller(pOldNtCreateProcess);

		pGlobalManager->nptHookManager.RemoveHook(pOldNtCreateFile);
		pGlobalManager->functionCallerManager.RemoveFunctionCaller(pOldNtCreateFile);

		pGlobalManager->nptHookManager.RemoveHook(pOldNtQuerySystemInformation);
		pGlobalManager->functionCallerManager.RemoveFunctionCaller(pOldNtQuerySystemInformation);

		pGlobalManager->nptHookManager.RemoveHook(pOldNtSystemDebugControl);
		pGlobalManager->functionCallerManager.RemoveFunctionCaller(pOldNtSystemDebugControl);
	}
};

#endif
