// HeaderLessGuiPE.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <Windows.h>

#include "../HeaderLessPE.h"
#include <string>
#include <string.h>

bool FsReadFile(__in const std::string& fpath, __out std::string& fdata)
{
	bool result = false;
	DWORD fsize = 0;
	HANDLE handle = CreateFileA(fpath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (handle == INVALID_HANDLE_VALUE) {
		return false;
	}
	fsize = GetFileSize(handle, NULL);
	if (fsize == INVALID_FILE_SIZE) {
		return false;
	}
	if (fsize == 0) {
		return true;
	}
	char* buffer = new char[fsize];
	if (buffer == NULL) {
		return false;
	}
	DWORD readlen;
	if (ReadFile(handle, buffer, fsize, &readlen, NULL)) {
		if (readlen == fsize) {
			try {
				fdata.assign(buffer, fsize);
				result = true;
			}
			catch (std::exception&) {
				fdata.clear();
			}
			catch (...) {
				fdata.clear();
			}
		}
	}

	CloseHandle(handle);
	delete[] buffer;
	return result;
}

bool FsWriteFile(__in const std::string& fpath, __in const std::string& fdata)
{
	bool result = false;
	bool read_only = false;
	DWORD saved_attr = ::GetFileAttributesA(fpath.c_str());
	if (saved_attr != INVALID_FILE_ATTRIBUTES) {
		if (saved_attr & FILE_ATTRIBUTE_READONLY) {
			read_only = true;
			::SetFileAttributesA(fpath.c_str(), saved_attr & (~FILE_ATTRIBUTE_READONLY));
		}
	}

	HANDLE handle = CreateFileA(fpath.c_str(), GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (handle != INVALID_HANDLE_VALUE) {
		DWORD writelen;
		::SetEndOfFile(handle);
		if (WriteFile(handle, fdata.data(), (DWORD)fdata.length(), &writelen, NULL)) {
			if (fdata.length() == writelen) {
				result = true;
			}
		}
	}

	if (read_only)
		::SetFileAttributesA(fpath.c_str(), saved_attr);
	return result;
}

void SpawnCreateProcess(LPSTR desktop, LPSTR path, LPSTR targetpath, PHeaderLessPE loader, PVOID payload, DWORD size)
{
	STARTUPINFOA si = { 0 };
	PROCESS_INFORMATION pi = { 0 };
	CONTEXT context = { 0 };

	si.cb = sizeof(si);
	if (desktop && strlen(desktop))
	{
		si.lpDesktop = desktop;
		// 创建桌面
		auto sk = CreateDesktopA(desktop, 0, 0, 0, GENERIC_ALL, 0);
		SetThreadDesktop(sk);
	}

	if (CreateProcessA(path, targetpath, NULL, NULL, 0, CREATE_SUSPENDED, NULL, 0, &si, &pi))
	{
		FARPROC entry = SpawnHeaderLessPE(loader, pi.hProcess, NULL);
		if (entry)
		{
			PVOID payload_buf = VirtualAllocEx(pi.hProcess, NULL, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
			SIZE_T write;
			WriteProcessMemory(pi.hProcess, payload_buf, payload, size, &write);
			context.ContextFlags = CONTEXT_FULL;
			GetThreadContext(pi.hThread, &context);

#ifdef _WIN64
			context.Rip = (DWORD64)entry;
			context.Rcx = (DWORD64)payload_buf;		// 传递将GUI程序地址
			context.Rdx = (DWORD64)size;
#else
			context.Eip = (DWORD)entryPoint;
			// args

#endif // _WIN64

			SetThreadContext(pi.hThread, &context);
			ResumeThread(pi.hThread);
		}
	}

	// 切换桌面
	//SwitchDesktop(sk);
}

int main(int argc, char** argv)
{
	if (argc == 4 && _stricmp(argv[1], "-s") == 0)
	{
		char* peFilepath = argv[2];
		char* savePath = argv[3];

		std::string filedata;
		if (FsReadFile(peFilepath, filedata))
		{
			PHeaderLessPE headerless;
			SIZE_T size;
			if (pe2headerless((BYTE*)filedata.data(), &headerless, &size))
			{
				std::string savedata;
				savedata.assign((char*)headerless, size);
				FsWriteFile(savePath, savedata);

				free(headerless);
			}
		}
	}
	else if (argc == 3 && _stricmp(argv[1], "-r") == 0)
	{
		char* filepath = argv[2];

		std::string filedata;
		if (FsReadFile(filepath, filedata))
		{
			PHeaderLessPE payload;
			SIZE_T size;
			pe2headerless((BYTE*)filedata.data(), &payload, &size);

			HINSTANCE instance;
			pfnWinMain winmain = (pfnWinMain)LoadHeaderLessPE((BYTE*)payload, NULL, &instance);
			winmain(0,0, 0, 0);
		}
	}
	else if (argc == 6 && _stricmp(argv[1], "-i") == 0)
	{
		char* desktop = argv[2];
		char* processpath = argv[3];
		char* loaderFilePath = argv[4];
		char* payloadFilePath = argv[5];

		std::string loader;
		std::string payload;
		if (FsReadFile(loaderFilePath, loader) && FsReadFile(payloadFilePath, payload))
		{
			PHeaderLessPE loaderPE;
			PHeaderLessPE payloadPE;

			SIZE_T size;
			pe2headerless((BYTE*)loader.data(), &loaderPE, &size);

			pe2headerless((BYTE*)payload.data(), &payloadPE, &size);

			SpawnCreateProcess(desktop, processpath, NULL, loaderPE, payloadPE, size);
		}
	}

	return 0;
}

