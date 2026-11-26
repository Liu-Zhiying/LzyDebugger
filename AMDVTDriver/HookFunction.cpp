#include "HookFunction.h"
#include "DebugEvent.h"
#include "VirtualMemoryHelper.h"
#include "ProcessThreadHelper.h"

#pragma warning(disable : 4302)
#pragma warning(disable : 4311)

#pragma code_seg()
NTSTATUS NTAPI HookFunctionManager::NtCreateProcessHandler(
	_Out_ PHANDLE				ProcessHandle,
	_In_  ACCESS_MASK			DesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_  HANDLE				ParentProcess,
	_In_  BOOLEAN				InheritObjectTable,
	_In_opt_ HANDLE				SectionHandle,
	_In_opt_ HANDLE				DebugPort,
	_In_opt_ HANDLE				ExceptionPort)
{
	NTSTATUS status = pNtCreateProcessCaller(
		ProcessHandle,
		DesiredAccess,
		ObjectAttributes,
		ParentProcess,
		InheritObjectTable,
		SectionHandle,
		DebugPort,
		ExceptionPort);

	KdPrint(("NtCreateProcess called!\n"));

	return status;
}

#pragma code_seg()
NTSTATUS NTAPI HookFunctionManager::NtCreateFileHandler(
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
	_In_ ULONG EaLength)
{
	NTSTATUS status = pNtCreateFileCaller(
		FileHandle,
		DesiredAccess,
		ObjectAttributes,
		IoStatusBlock,
		AllocationSize,
		FileAttributes,
		ShareAccess,
		CreateDisposition,
		CreateOptions,
		EaBuffer,
		EaLength);

	KdPrint(("NtCreateFile called!\n"));

	return status;
}

#pragma code_seg()
NTSTATUS NTAPI HookFunctionManager::NtQuerySystemInformationHandler(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID                    SystemInformation,
	ULONG                    SystemInformationLength,
	PULONG                   ReturnLength)
{
	NTSTATUS status = pNtQuerySystemInformationCaller(
		SystemInformationClass,
		SystemInformation,
		SystemInformationLength,
		ReturnLength);

	//KdPrint(("NtQuerySystemInformation called!\n"));

	if (SystemInformationClass == SystemCodeIntegrityInformation) {
		KdPrint(("有程序检测测试模式, pid = %llu！\n", PsGetCurrentProcessId()));
		if (SystemInformation != NULL &&
			SystemInformationLength >= sizeof(SYSTEM_CODEINTEGRITY_INFORMATION) &&
			NT_SUCCESS(status)) {

			KdPrint(("测试模式检测已经HOOK！\n"));

			PSYSTEM_CODEINTEGRITY_INFORMATION pInfo =
				(PSYSTEM_CODEINTEGRITY_INFORMATION)SystemInformation;

			// 3. 清除 TESTSIGNING 标志位，伪装测试模式未启用
			pInfo->CodeIntegrityOptions &= ~CODEINTEGRITY_OPTION_TESTSIGN;
		}
	}

	if (SystemInformationClass == SystemKernelDebuggerInformation)
	{
		KdPrint(("有程序检测内核调试, pid = %llu！\n", PsGetCurrentProcessId()));

		if (SystemInformation != NULL &&
			SystemInformationLength >= sizeof(SYSTEM_KERNEL_DEBUGGER_INFORMATION) &&
			NT_SUCCESS(status)) {

			KdPrint(("内核调试检测已经HOOK！\n"));

			PSYSTEM_KERNEL_DEBUGGER_INFORMATION debuggerInfo =
				(PSYSTEM_KERNEL_DEBUGGER_INFORMATION)SystemInformation;

			// 3. 篡改返回值：伪装成没有调试器
			debuggerInfo->KernelDebuggerEnabled = FALSE;   // 调试器未启用
			debuggerInfo->KernelDebuggerNotPresent = TRUE; // 调试器不存在

			// 如果 ReturnLength 有效，也可以修正它
			if (ReturnLength) {
				*ReturnLength = sizeof(SYSTEM_KERNEL_DEBUGGER_INFORMATION);
			}
		}
	}

	return status;
}

#pragma code_seg()
NTSTATUS NTAPI HookFunctionManager::NtSystemDebugControlHandler(
	__in SYSDBG_COMMAND Command,          // 要执行的操作
	__in_opt PVOID InputBuffer,           // 输入参数（结构体，视命令而定）
	__in ULONG InputBufferLength,
	__out_opt PVOID OutputBuffer,
	__in ULONG OutputBufferLength,
	__out_opt PULONG ReturnLength)
{
	//KdPrint(("有程序使用内核调试服务, pid = %llu！\n", PsGetCurrentProcessId()));
	//KdPrint(("内核调试服务已经HOOK！\n"));
	UNREFERENCED_PARAMETER(Command);
	UNREFERENCED_PARAMETER(InputBuffer);
	UNREFERENCED_PARAMETER(InputBufferLength);
	UNREFERENCED_PARAMETER(OutputBuffer);
	UNREFERENCED_PARAMETER(OutputBufferLength);
	UNREFERENCED_PARAMETER(ReturnLength);
	return STATUS_DEBUGGER_INACTIVE;
}

#pragma code_seg()
VOID HookFunctionManager::KiDispatchExceptionHandler(IN PEXCEPTION_RECORD ExceptionRecord, IN PKEXCEPTION_FRAME ExceptionFrame, IN PKTRAP_FRAME TrapFrame, IN KPROCESSOR_MODE PreviousMode, IN BOOLEAN FirstChance)
{
	/*
	if (PreviousMode != KernelMode)
	{
		KdPrint(("aaa\n"));

		BindDebugProcess info = {};
		UINT64 debuggeeProcessId = (UINT64)PsGetCurrentProcessId();
		bool isDebug = SearchDebuggeeProcessId(debuggeeProcessId, info);

		if (isDebug)
		{
			DEBUG_EVENT event = {};

			event.dwDebugEventCode = 0x1;

			event.dwProcessId = (DWORD)PsGetCurrentProcessId();
			event.dwThreadId = (DWORD)PsGetCurrentThreadId();

			event.u.Exception.ExceptionRecord = *ExceptionRecord;
			event.u.Exception.dwFirstChance = FirstChance;

			PVOID pVirtualMemory = NULL;
			PEPROCESS pProcess = NULL;
			HANDLE hUserThread = NULL;
			HANDLE userThreadId = {};

			do
			{
				if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)info.DebuggerProcess, &pProcess)))
					break;

				AllocVirtualMemory(sizeof event, pProcess, &pVirtualMemory);

				if (pVirtualMemory == NULL)
					break;

				WriteVirtualMemory(sizeof event, pProcess, pVirtualMemory, &event);

				CreateUserThread(pProcess, (PUSER_THREAD_START_ROUTINE)info.debugEventAddFunction, pVirtualMemory, &hUserThread, &userThreadId);

				if (hUserThread != NULL)
				{
					PETHREAD pUserThread = NULL;
					ObReferenceObjectByHandle(hUserThread, THREAD_ALL_ACCESS, *PsThreadType, KernelMode, (PVOID*)&pUserThread, NULL);

					if (pUserThread != NULL)
					{
						while (PsGetThreadExitStatus(pUserThread) == STATUS_PENDING) continue;
						ObDereferenceObject(pUserThread);
					}
				}

			} while (false);

			if (hUserThread != NULL)
				ZwClose(hUserThread);

			if (pVirtualMemory != NULL)
				FreeVirtualMemory(pProcess, pVirtualMemory);

			if (pProcess != NULL)
				ObDereferenceObject(pProcess);

			return;
		}
	}
	*/

	return pKiDispatchExceptionCaller(ExceptionRecord, ExceptionFrame, TrapFrame, PreviousMode, FirstChance);
}

#pragma code_seg()
NTSTATUS HookFunctionManager::DbgkpPostFakeThreadMessagesHandler(PEPROCESS Process, PDEBUG_OBJECT DebugObject, PETHREAD StartThread, PETHREAD* pFirstThread, PETHREAD* pLastThread)
{
	return pDbgkpPostFakeThreadMessagesCaller(Process, DebugObject, StartThread, pFirstThread, pLastThread);
}


#pragma code_seg("PAGE")
void HookFunctionManager::SetSyscallIndex(char* pFunctionName, UINT32 index)
{
	KernelVector<SyscallIndexIn, MAIN_TAG, NonPaged>* pContainer = (KernelVector<SyscallIndexIn, MAIN_TAG, NonPaged>*)buffer;
	for (SIZE_TYPE idx = 0; idx < pContainer->Length(); ++idx)
	{
		//如果字符串匹配
		if (!strncmp(&(*pContainer)[idx].functionName[0], pFunctionName, sizeof(*pContainer)[idx].functionName))
		{
			(*pContainer)[idx].index = index;
			return;
		}
	}

	SyscallIndexIn item = { {}, index };
	strncpy_s(item.functionName, sizeof item.functionName, pFunctionName, strlen(pFunctionName));
	pContainer->PushBack(item);
}

#pragma code_seg("PAGE")
UINT32 HookFunctionManager::GetSyscallIndex(char* pFunctionName)
{
	KernelVector<SyscallIndexIn, MAIN_TAG, NonPaged>* pContainer = (KernelVector<SyscallIndexIn, MAIN_TAG, NonPaged>*)buffer;
	for (SIZE_TYPE idx = 0; idx < pContainer->Length(); ++idx)
	{
		//如果字符串匹配
		if (!strncmp(&(*pContainer)[idx].functionName[0], pFunctionName, sizeof(*pContainer)[idx].functionName))
			return (*pContainer)[idx].index;
	}

	return (UINT32)-1;
}
