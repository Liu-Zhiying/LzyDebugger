#include <init.h>
#include <DllInject.h>

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