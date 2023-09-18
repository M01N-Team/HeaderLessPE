// Payload.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#pragma comment(linker, "/entry:main")

#include "../HeaderLessPE.h"
#include "hook.h"

DWORD FsGetSize(LPSTR fpath) {
	DWORD fsize = 0;
	HANDLE handle = CreateFileA(fpath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (handle != INVALID_HANDLE_VALUE) {
		fsize = GetFileSize(handle, NULL);
		CloseHandle(handle);
	}
	return fsize;
}

BOOL FsReadFile(LPSTR fpath, __out PVOID fdata, DWORD size)
{
	BOOL result = FALSE;
	DWORD fsize = 0;
	HANDLE handle = CreateFileA(fpath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (handle != INVALID_HANDLE_VALUE)
	{
		fsize = GetFileSize(handle, NULL);
		if (fsize == size) {
			DWORD readlen;
			if (ReadFile(handle, fdata, fsize, &readlen, NULL)) {
				if (readlen != size)
				{
					result = FALSE;
				}
			}
		}

		CloseHandle(handle);
	}

	return result;
}

VOID main(PVOID data, DWORD datalen)
{ 
	if (data && datalen > 0)
	{
		//LPCSTR str = "adc.bin";
		//DWORD size = FsGetSize((LPSTR)str);

		//PVOID buffer = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		//FsReadFile((LPSTR)str, buffer, size);

		HINSTANCE instance;
		pfnWinMain winmain = (pfnWinMain)LoadHeaderLessPE((BYTE*)data, NULL, &instance);
		HookResource(instance, (PHeaderLessPE)data);
		winmain(instance, 0, GetCommandLineA(), SW_SHOW);
	}
}
