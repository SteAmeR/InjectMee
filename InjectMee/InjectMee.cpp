// InjectMee.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>

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

	const DWORD processID = GetPIDByName(L"streamer.exe");
	if (processID == 0)	{
		ExitProcess;
	}
	else {
		ProcInfo.hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
		ProcInfo.dwProcessId = processID;
	}

	if (inject(ProcInfo.hProcess, 0)) {

	}

}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
