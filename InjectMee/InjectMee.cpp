#define WIN32_LEAN_AND_MEAN

#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <fstream>
#include <cstdint>
#include <experimental/filesystem>
#include <string>
#include <regex>

UCHAR Shellcode[] =
{
	0x55, 0x89, 0xE5, 0x83, 0xEC, 0x08, 0x53, 0x56, 0x57, 0xE8, 0x00, 0x00,
	0x00, 0x00, 0x5B, 0x81, 0xEB, 0x0E, 0x00, 0x00, 0x00, 0x64, 0xA1, 0x30,
	0x00, 0x00, 0x00, 0x8B, 0x40, 0x0C, 0x8B, 0x40, 0x14, 0x8B, 0x00, 0x8B,
	0x00, 0x8B, 0x40, 0x10, 0x89, 0x45, 0xFC, 0x03, 0x40, 0x3C, 0x8B, 0x40,
	0x78, 0x03, 0x45, 0xFC, 0x89, 0x45, 0xF8, 0x31, 0xF6, 0x8B, 0x50, 0x20,
	0x03, 0x55, 0xFC, 0x56, 0xB9, 0x04, 0x00, 0x00, 0x00, 0x8B, 0x34, 0xB2,
	0x03, 0x75, 0xFC, 0x8D, 0xBB, 0x8D, 0x00, 0x00, 0x00, 0xF3, 0xA6, 0x74,
	0x09, 0x5E, 0x46, 0x3B, 0x70, 0x14, 0x7C, 0xE3, 0xEB, 0x23, 0x5E, 0x8B,
	0x48, 0x1C, 0x03, 0x4D, 0xFC, 0x8B, 0x50, 0x24, 0x03, 0x55, 0xFC, 0x0F,
	0xB7, 0x04, 0x72, 0x8B, 0x04, 0x81, 0x03, 0x45, 0xFC, 0x68, 0xE8, 0x03,
	0x00, 0x00, 0x68, 0xE8, 0x03, 0x00, 0x00, 0xFF, 0xD0, 0xE8, 0x78, 0x56,
	0x34, 0x12, 0x5F, 0x5E, 0x5B, 0x89, 0xEC, 0x5D, 0xC3, 0x42, 0x65, 0x65,
	0x70
};

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
	const char* pPath = path;
	const size_t dwpPathLength = strlen(pPath);

	HMODULE pModuleHandle = GetModuleHandleW(L"kernel32.dll");

	if (!pModuleHandle)
		return false;

	void* fpLoadLibraryA = GetProcAddress(pModuleHandle, "LoadLibraryA");

	if (!fpLoadLibraryA)
		return false;

	void* memory = VirtualAllocEx(pProcessHandle, NULL, dwpPathLength,
		MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	if (!memory)
		return false;

	if (!WriteProcessMemory(pProcessHandle, memory, pPath, dwpPathLength + 1, NULL))
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

	if (inject(ProcInfo.hProcess, pInjectDLLPath)) {

	}

}