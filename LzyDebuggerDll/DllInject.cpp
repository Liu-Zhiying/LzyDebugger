#include "DllInject.h"
#include <string>

bool DLL InjectDllByRemoteThread(UINT64 processId, LPCSTR dllPath)
{
	HANDLE hProcess = NULL;
	HANDLE hThread = NULL;
	PVOID pParameter = NULL;
	SIZE_T writtenSize = 0;
	bool result = false;
	PVOID pLoadLibraryA = NULL;

	do
	{
		pLoadLibraryA = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
		if (pLoadLibraryA == NULL)
			break;

		hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
		if (hProcess == NULL)
			break;

		pParameter = VirtualAllocEx(hProcess, NULL, (strlen(dllPath) + 1) * sizeof(char), MEM_COMMIT, PAGE_READWRITE);
		
		if (pParameter == NULL)
			break;

		WriteProcessMemory(hProcess, pParameter, dllPath, (strlen(dllPath) + 1) * sizeof(char), &writtenSize);
		if (writtenSize != (strlen(dllPath) + 1) * sizeof(char))
			break;

		hThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)pLoadLibraryA, pParameter, 0, NULL);
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

	if (pParameter != NULL)
		VirtualFreeEx(hProcess, pParameter, 0, MEM_FREE);

	if (hProcess != NULL)
		CloseHandle(hProcess);

	return result;
}

HANDLE DLL CreateSuspendedProcess(LPCSTR cmdLine)
{
	std::string cmdLineCopy = cmdLine;
	PROCESS_INFORMATION info = {};
	STARTUPINFOA si = { sizeof si };
	if (CreateProcessA(NULL, (LPSTR)cmdLineCopy.data(), NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &info))
	{
		CloseHandle(info.hProcess);
		return info.hThread;
	}
	return NULL;
}
