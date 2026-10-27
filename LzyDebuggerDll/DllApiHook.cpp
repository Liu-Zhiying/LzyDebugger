#include "DllApiHook.h"
#include <TlHelp32.h>
#include <stdio.h>

#pragma warning(disable : 6031)

// 使用NtProtectVirtualMemory（需要声明函数指针）
typedef NTSTATUS(NTAPI* pNtProtectVirtualMemory)(
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	PSIZE_T RegionSize,
	ULONG NewProtect,
	PULONG OldProtect);

PIMAGE_EXPORT_DIRECTORY FindExportTableX86(HMODULE hModule, DWORD& dwErrorCode, SIZE_T& exportTableSize)
{
	PIMAGE_EXPORT_DIRECTORY result = NULL;

	do
	{
		exportTableSize = 0;
		dwErrorCode = ERROR_SUCCESS;

		PUCHAR pModuleBegin = (PUCHAR)hModule;

		PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pModuleBegin;
		if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		{
			dwErrorCode = ERROR_FILE_CORRUPT;
			break;
		}

		PIMAGE_NT_HEADERS32 pNtHeader64 = reinterpret_cast<PIMAGE_NT_HEADERS32>(pModuleBegin + pDosHeader->e_lfanew);
		if (pNtHeader64->Signature != IMAGE_NT_SIGNATURE)
		{
			dwErrorCode = ERROR_FILE_CORRUPT;
			break;
		}
		if (pNtHeader64->FileHeader.Machine != IMAGE_FILE_MACHINE_I386)
		{
			dwErrorCode = ERROR_FILE_CORRUPT;
			break;
		}

		ULONG_PTR exportTableAddress = pNtHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
		exportTableSize = pNtHeader64->OptionalHeader.DataDirectory[0].Size;
		result = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(pModuleBegin + exportTableAddress);

	} while (false);

	return result;
}

PIMAGE_EXPORT_DIRECTORY FindExportTableX64(HMODULE hModule, DWORD& dwErrorCode, SIZE_T& exportTableSize)
{
	PIMAGE_EXPORT_DIRECTORY result = NULL;

	do
	{
		exportTableSize = 0;
		dwErrorCode = ERROR_SUCCESS;

		PUCHAR pModuleBegin = (PUCHAR)hModule;

		PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pModuleBegin;
		if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		{
			dwErrorCode = ERROR_FILE_CORRUPT;
			break;
		}

		PIMAGE_NT_HEADERS64 pNtHeader64 = reinterpret_cast<PIMAGE_NT_HEADERS64>(pModuleBegin + pDosHeader->e_lfanew);
		if (pNtHeader64->Signature != IMAGE_NT_SIGNATURE)
		{
			dwErrorCode = ERROR_FILE_CORRUPT;
			break;
		}
		if (pNtHeader64->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
		{
			dwErrorCode = ERROR_FILE_CORRUPT;
			break;
		}

		ULONG_PTR exportTableAddress = pNtHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
		exportTableSize = pNtHeader64->OptionalHeader.DataDirectory[0].Size;
		result = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(pModuleBegin + exportTableAddress);

	} while (false);

	return result;
}

PIMAGE_IMPORT_DESCRIPTOR FindImportTableX86(HMODULE hModule, DWORD& dwErrorCode, SIZE_T& importTableSize)
{
	PIMAGE_IMPORT_DESCRIPTOR result = NULL;

	do
	{
		importTableSize = 0;
		dwErrorCode = ERROR_SUCCESS;

		PUCHAR pModuleBegin = (PUCHAR)hModule;

		PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pModuleBegin;
		if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		{
			dwErrorCode = ERROR_FILE_CORRUPT;
			break;
		}

		PIMAGE_NT_HEADERS32 pNtHeader64 = reinterpret_cast<PIMAGE_NT_HEADERS32>(pModuleBegin + pDosHeader->e_lfanew);
		if (pNtHeader64->Signature != IMAGE_NT_SIGNATURE)
		{
			dwErrorCode = ERROR_FILE_CORRUPT;
			break;
		}
		if (pNtHeader64->FileHeader.Machine != IMAGE_FILE_MACHINE_I386)
		{
			dwErrorCode = ERROR_FILE_CORRUPT;
			break;
		}

		ULONG_PTR exportTableAddress = pNtHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
		importTableSize = pNtHeader64->OptionalHeader.DataDirectory[0].Size;
		result = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(pModuleBegin + exportTableAddress);

	} while (false);

	return result;
}

PIMAGE_IMPORT_DESCRIPTOR FindImportTableX64(HMODULE hModule, DWORD& dwErrorCode, SIZE_T& importTableSize)
{
	PIMAGE_IMPORT_DESCRIPTOR result = NULL;

	do
	{
		importTableSize = 0;
		dwErrorCode = ERROR_SUCCESS;

		PUCHAR pModuleBegin = (PUCHAR)hModule;

		PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pModuleBegin;
		if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		{
			dwErrorCode = ERROR_FILE_CORRUPT;
			break;
		}

		PIMAGE_NT_HEADERS64 pNtHeader64 = reinterpret_cast<PIMAGE_NT_HEADERS64>(pModuleBegin + pDosHeader->e_lfanew);
		if (pNtHeader64->Signature != IMAGE_NT_SIGNATURE)
		{
			dwErrorCode = ERROR_FILE_CORRUPT;
			break;
		}
		if (pNtHeader64->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
		{
			dwErrorCode = ERROR_FILE_CORRUPT;
			break;
		}

		ULONG_PTR exportTableAddress = pNtHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
		importTableSize = pNtHeader64->OptionalHeader.DataDirectory[0].Size;
		result = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(pModuleBegin + exportTableAddress);

	} while (false);

	return result;
}

PVOID FindDllApiX86(HMODULE hModule, LPCSTR functionName, DWORD& dwErrorCode)
{
	PVOID result = NULL;

	do
	{
		SIZE_T exportTableSize = 0;
		PIMAGE_EXPORT_DIRECTORY pExportTable = FindExportTableX86(hModule, dwErrorCode, exportTableSize);

		if (pExportTable == NULL)
			break;

		PDWORD pFunctionNameRvas = reinterpret_cast<PDWORD>(pExportTable->AddressOfNames + (ULONG_PTR)hModule);
		PUSHORT pFunctionNameOrdinals = reinterpret_cast<PUSHORT>(pExportTable->AddressOfNameOrdinals + (ULONG_PTR)hModule);
		PDWORD pFunctionRvas = reinterpret_cast<PDWORD>(pExportTable->AddressOfFunctions + (ULONG_PTR)hModule);

		for (SIZE_T idx = 0; idx < pExportTable->AddressOfNames; ++idx)
		{
			PCSTR pFunctionName = reinterpret_cast<PCSTR>(pFunctionNameRvas[idx] + (ULONG_PTR)hModule);

			if (!strcmp(pFunctionName, functionName))
			{
				result = (PUCHAR)hModule + pFunctionRvas[pFunctionNameOrdinals[idx]];
				break;
			}
		}

	} while (false);

	return result;
}

PVOID FindDllApiX64(HMODULE hModule, LPCSTR functionName, DWORD& dwErrorCode)
{
	PVOID result = NULL;

	do
	{
		SIZE_T exportTableSize = 0;
		PIMAGE_EXPORT_DIRECTORY pExportTable = FindExportTableX64(hModule, dwErrorCode, exportTableSize);

		if (pExportTable == NULL)
			break;

		PDWORD pFunctionNameRvas = reinterpret_cast<PDWORD>(pExportTable->AddressOfNames + (ULONG_PTR)hModule);
		PUSHORT pFunctionNameOrdinals = reinterpret_cast<PUSHORT>(pExportTable->AddressOfNameOrdinals + (ULONG_PTR)hModule);
		PDWORD pFunctionRvas = reinterpret_cast<PDWORD>(pExportTable->AddressOfFunctions + (ULONG_PTR)hModule);

		for (SIZE_T idx = 0; idx < pExportTable->AddressOfNames; ++idx)
		{
			PCSTR pFunctionName = reinterpret_cast<PCSTR>(pFunctionNameRvas[idx] + (ULONG_PTR)hModule);

			if (!strcmp(pFunctionName, functionName))
			{
				result = (PUCHAR)hModule + pFunctionRvas[pFunctionNameOrdinals[idx]];
				break;
			}
		}

	} while (false);

	return result;
}

DWORD HookDllApiX86(HMODULE hModule, LPCSTR functionName, PVOID& pOldFunctionPtr, PVOID pNewFunctionPtr)
{
	SIZE_T exportTableSize = 0;
	LPCSTR pHookModuleName = NULL;
	DWORD dwErrCode = ERROR_SUCCESS;
	HANDLE hSnapshot = NULL;
	pNtProtectVirtualMemory NtProtectVirtualMemory = NULL;
	PIMAGE_EXPORT_DIRECTORY pExportTable = NULL;
	MODULEENTRY32W info = {};
	info.dwSize = sizeof info;

	do
	{
		//获取函数地址
		NtProtectVirtualMemory = (pNtProtectVirtualMemory)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtProtectVirtualMemory");

		if (NtProtectVirtualMemory == NULL)
			break;

		pExportTable = FindExportTableX86(hModule, dwErrCode, exportTableSize);

		if (pExportTable == NULL)
			break;

		pHookModuleName = (LPCSTR)hModule + pExportTable->Name;

		hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());

		if (hSnapshot == NULL)
		{
			dwErrCode = GetLastError();
			break;
		}

		auto ChangeImportTableFunctionAddress = [&NtProtectVirtualMemory](HMODULE hModule, LPCSTR pHookModuleName, LPCSTR functionName, DWORD& dwErrCode, PVOID newFunctionAddr) -> bool
			{
				dwErrCode = ERROR_SUCCESS;

				do
				{
					SIZE_T importTableSize = 0;

					PIMAGE_IMPORT_DESCRIPTOR pImportTable = FindImportTableX86(hModule, dwErrCode, importTableSize);

					if (pImportTable == NULL)
						break;

					for (SIZE_T idx1 = 0; pImportTable[idx1].Name; ++idx1)
					{
						LPCSTR pModuleName = (LPCSTR)hModule + pImportTable[idx1].Name;

						if (!strcmp(pModuleName, pHookModuleName))
						{
							PIMAGE_THUNK_DATA32 pOriginThunkData = reinterpret_cast<PIMAGE_THUNK_DATA32>(reinterpret_cast<LPSTR>(hModule) + pImportTable[idx1].OriginalFirstThunk);

							PIMAGE_THUNK_DATA32 pThunkData = reinterpret_cast<PIMAGE_THUNK_DATA32>(reinterpret_cast<LPSTR>(hModule) + pImportTable[idx1].FirstThunk);

							for (size_t idx2 = 0; pOriginThunkData[idx2].u1.AddressOfData; ++idx2)
							{
								__try
								{
									PIMAGE_IMPORT_BY_NAME pImportByName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(reinterpret_cast<LPSTR>(hModule) + pOriginThunkData[idx2].u1.AddressOfData);
									if (!strcmp(pImportByName->Name, functionName))
									{
										// 使用更低级的API修改权限
										ULONG oldProt;
										PVOID base = &((pThunkData + idx2)->u1.Function);
										SIZE_T size = sizeof(PVOID);
										NTSTATUS status = NtProtectVirtualMemory(GetCurrentProcess(), &base, &size, PAGE_EXECUTE_READWRITE, &oldProt);

										if (status != 0)
										{
											dwErrCode = ERROR_ACCESS_DENIED;
											break;
										}

										pThunkData[idx2].u1.Function = (ULONG_PTR)newFunctionAddr;

										NtProtectVirtualMemory(GetCurrentProcess(), &base, &size, oldProt, NULL);

										return true;
									}
								}
								__except (GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH)
								{
									return false;
								}
							}
						}
					}

				} while (false);

				return false;
			};

		if (Module32FirstW(hSnapshot, &info))
		{
			ChangeImportTableFunctionAddress(info.hModule, pHookModuleName, functionName, dwErrCode, pNewFunctionPtr);

			if (dwErrCode != ERROR_SUCCESS)
				break;

			while (Module32NextW(hSnapshot, &info))
			{
				ChangeImportTableFunctionAddress(info.hModule, pHookModuleName, functionName, dwErrCode, pNewFunctionPtr);

				if (dwErrCode != ERROR_SUCCESS)
					break;
			}
		}

	} while (false);

	if (hSnapshot != NULL)
		CloseHandle(hSnapshot);

	return dwErrCode;
}

DWORD HookDllApiX64(HMODULE hModule, LPCSTR functionName, PVOID& pOldFunctionPtr, PVOID pNewFunctionPtr)
{
	SIZE_T exportTableSize = 0;
	LPCSTR pHookModuleName = NULL;
	DWORD dwErrCode = ERROR_SUCCESS;
	HANDLE hSnapshot = NULL;
	pNtProtectVirtualMemory NtProtectVirtualMemory = NULL;
	PIMAGE_EXPORT_DIRECTORY pExportTable = NULL;
	MODULEENTRY32W info = {};
	info.dwSize = sizeof info;

	do
	{
		//获取函数地址
		NtProtectVirtualMemory = (pNtProtectVirtualMemory)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtProtectVirtualMemory");

		if (NtProtectVirtualMemory == NULL)
			break;

		pExportTable = FindExportTableX64(hModule, dwErrCode, exportTableSize);

		if (pExportTable == NULL)
			break;

		pHookModuleName = (LPCSTR)hModule + pExportTable->Name;

		hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());

		if (hSnapshot == NULL)
		{
			dwErrCode = GetLastError();
			break;
		}

		auto ChangeImportTableFunctionAddress = [&NtProtectVirtualMemory](HMODULE hModule, LPCSTR pHookModuleName, LPCSTR functionName, DWORD& dwErrCode, PVOID newFunctionAddr) -> bool
			{
				dwErrCode = ERROR_SUCCESS;

				do
				{
					SIZE_T importTableSize = 0;

					PIMAGE_IMPORT_DESCRIPTOR pImportTable = FindImportTableX64(hModule, dwErrCode, importTableSize);

					if (pImportTable == NULL)
						break;

					for (SIZE_T idx1 = 0; pImportTable[idx1].Name; ++idx1)
					{
						__try
						{
							LPCSTR pModuleName = (LPCSTR)hModule + pImportTable[idx1].Name;

							if (!strcmp(pModuleName, pHookModuleName))
							{
								PIMAGE_THUNK_DATA64 pOriginThunkData = reinterpret_cast<PIMAGE_THUNK_DATA64>(reinterpret_cast<LPSTR>(hModule) + pImportTable[idx1].OriginalFirstThunk);

								PIMAGE_THUNK_DATA64 pThunkData = reinterpret_cast<PIMAGE_THUNK_DATA64>(reinterpret_cast<LPSTR>(hModule) + pImportTable[idx1].FirstThunk);

								for (size_t idx2 = 0; pOriginThunkData[idx2].u1.AddressOfData; ++idx2)
								{
									PIMAGE_IMPORT_BY_NAME pImportByName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(reinterpret_cast<LPSTR>(hModule) + pOriginThunkData[idx2].u1.AddressOfData);
									if (!strcmp(pImportByName->Name, functionName))
									{
										
										// 使用更低级的API修改权限
										ULONG oldProt;
										PVOID base = &((pThunkData + idx2)->u1.Function);
										SIZE_T size = sizeof(PVOID);
										NTSTATUS status = NtProtectVirtualMemory(GetCurrentProcess(), &base, &size, PAGE_EXECUTE_READWRITE, &oldProt);

										if (status != 0)
										{
											dwErrCode = ERROR_ACCESS_DENIED;
											break;
										}

										pThunkData[idx2].u1.Function = (ULONGLONG)newFunctionAddr;

										NtProtectVirtualMemory(GetCurrentProcess(), &base, &size, oldProt, NULL);

										return true;
									}
								}
							}
						}
						__except (GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH)
						{
							return false;
						}
					}

				} while (false);

				return false;
			};

		if (Module32FirstW(hSnapshot, &info))
		{
			ChangeImportTableFunctionAddress(info.hModule, pHookModuleName, functionName, dwErrCode, pNewFunctionPtr);

			if (dwErrCode != ERROR_SUCCESS)
				break;

			while (Module32NextW(hSnapshot, &info))
			{
				ChangeImportTableFunctionAddress(info.hModule, pHookModuleName, functionName, dwErrCode, pNewFunctionPtr);

				if (dwErrCode != ERROR_SUCCESS)
					break;
			}
		}

	} while (false);

	if (hSnapshot != NULL)
		CloseHandle(hSnapshot);

	return dwErrCode;
}