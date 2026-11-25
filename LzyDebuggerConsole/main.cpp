#include <init.h>
#include <DllInject.h>
#include <debugger_hook.h>
#include <string>

HANDLE CreateSuspendedProcess2(LPCSTR cmdLine, HANDLE& hProcess)
{
	std::string cmdLineCopy = cmdLine;
	PROCESS_INFORMATION info = {};
	STARTUPINFOA si = { sizeof si };
	if (CreateProcessA(NULL, (LPSTR)cmdLineCopy.data(), NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &info))
	{
		hProcess = info.hProcess;
		return info.hThread;
	}
	return NULL;
}

bool InjectDbgBreak2(UINT64 processId)
{
	HANDLE hProcess = NULL;
	HANDLE hThread = NULL;
	SIZE_T writtenSize = 0;
	LPVOID pDbgBreakPoint = NULL;
	bool result = false;

	do
	{
		pDbgBreakPoint = GetProcAddress(GetModuleHandleA("ntdll.dll"), "DbgBreakPoint");
		if (pDbgBreakPoint == NULL)
			break;

		hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
		if (hProcess == NULL)
			break;

		hThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)pDbgBreakPoint, NULL, 0, NULL);
		if (hThread == NULL)
			break;

		WaitForSingleObject(hThread, INFINITE);

		DWORD exitCode = 0;
		GetExitCodeThread(hThread, &exitCode);
		if (exitCode == 0)
			break;

		result = true;
	} while (false);

	if (hThread != NULL)
		CloseHandle(hThread);

	if (hProcess != NULL)
		CloseHandle(hProcess);

	return result;
}

int main()
{
	InitDebuggerDriver();

	HANDLE hThread = CreateSuspendedProcess("windbg.exe");

	InjectDllByRemoteThread(GetProcessIdOfThread(hThread), "LzyDebuggerDll.dll");

	ResumeThread(hThread);

	CloseHandle(hThread);

	system("pause");

	DeinitDebuggerDriver();
}