#define WIN32_LEAN_AND_MEAN

#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <fstream>
#include <cstdint>
#include <experimental/filesystem>
#include <string>
#include <regex>


DWORD GetPIDByName(const std::wstring& name) {
	PROCESSENTRY32 pt;
	HANDLE hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	pt.dwSize = sizeof(PROCESSENTRY32);
	if (Process32First(hsnap, &pt)) {
		do {
			if (!lstrcmpi(pt.szExeFile, name.c_str())) {
				CloseHandle(hsnap);
				return pt.th32ProcessID;
			}
		} while (Process32Next(hsnap, &pt));
	}

	CloseHandle(hsnap);
	return 0;
};


bool inject(HANDLE pProcessHandle, const char* path)
{
	HMODULE pModuleHandle = GetModuleHandleW(L"kernel32.dll");

	if (!pModuleHandle)
		return false;

	void* fpLoadLibraryA = GetProcAddress(pModuleHandle, "LoadLibraryA");

	if (!fpLoadLibraryA)
		return false;

	void* memory = VirtualAllocEx(pProcessHandle, NULL, strlen(path),
		MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	if (!memory)
		return false;

	if (!WriteProcessMemory(pProcessHandle, memory, path, strlen(path), NULL))
		return false;

	HANDLE pThreadHandle = CreateRemoteThread(pProcessHandle, NULL, NULL,
		reinterpret_cast<LPTHREAD_START_ROUTINE>(fpLoadLibraryA), memory, NULL, NULL);

	if (!pThreadHandle)
		return false;

	WaitForSingleObject(pThreadHandle, INFINITE);

	CloseHandle(pThreadHandle);
	return true;
}

int main()
{
	PROCESS_INFORMATION ProcInfo;
	STARTUPINFOA StartupInfo;
	char pInjectDLLPath[MAX_PATH];
	char pCurrentPath[MAX_PATH];

	ZeroMemory(&ProcInfo, sizeof(ProcInfo));
	ZeroMemory(&StartupInfo, sizeof(StartupInfo));

	GetCurrentDirectoryA(MAX_PATH, pCurrentPath);
	sprintf_s(pInjectDLLPath, "%s\\%s", pCurrentPath, "streamer.dll");

	if (!std::experimental::filesystem::exists(pInjectDLLPath))	{
		ExitProcess;
	}

	const DWORD processID = GetPIDByName(L"streamer.exe");
	if (processID == 0)	{
		ExitProcess;
	}
	else {
		ProcInfo.hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
		ProcInfo.dwProcessId = processID;
	}

	const char* ppInjectDLLPath = pInjectDLLPath;
	const size_t dwInjectDLLLength = strlen(ppInjectDLLPath);

	if (inject(ProcInfo.hProcess, 0)) {

	}

}