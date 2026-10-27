#include "HookFunction.h"

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

	//KdPrint(("NtCreateProcess called!\n"));

	return status;
}

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

	//KdPrint(("NtCreateFile called!\n"));

	return status;
}

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

	if (SystemInformationClass == SystemCodeIntegrityInformation) {
		//KdPrint(("有程序检测测试模式, pid = %llu！\n", PsGetCurrentProcessId()));
		if (SystemInformation != NULL &&
			SystemInformationLength >= sizeof(SYSTEM_CODEINTEGRITY_INFORMATION) &&
			NT_SUCCESS(status)) {

			//KdPrint(("测试模式检测已经HOOK！\n"));

			PSYSTEM_CODEINTEGRITY_INFORMATION pInfo =
				(PSYSTEM_CODEINTEGRITY_INFORMATION)SystemInformation;

			// 3. 清除 TESTSIGNING 标志位，伪装测试模式未启用
			pInfo->CodeIntegrityOptions &= ~CODEINTEGRITY_OPTION_TESTSIGN;
		}
	}

	if (SystemInformationClass == SystemKernelDebuggerInformation)
	{
		//KdPrint(("有程序检测内核调试, pid = %llu！\n", PsGetCurrentProcessId()));

		if (SystemInformation != NULL &&
			SystemInformationLength >= sizeof(SYSTEM_KERNEL_DEBUGGER_INFORMATION) &&
			NT_SUCCESS(status)) {

			//KdPrint(("内核调试检测已经HOOK！\n"));

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