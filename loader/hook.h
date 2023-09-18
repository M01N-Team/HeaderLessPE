#pragma once
#include "../HeaderLessPE.h"
#include <Windows.h>

typedef size_t (__cdecl *pfnwcslen)(
	_In_z_ wchar_t const* _String
);

typedef int(__cdecl* pfn_wcsnicmp)(
	_In_reads_or_z_(_MaxCount) wchar_t const* _String1,
	_In_reads_or_z_(_MaxCount) wchar_t const* _String2,
	_In_                       size_t         _MaxCount
);

typedef wchar_t* (__cdecl* pfn_wcsupr)(
	wchar_t
); // C++ only

typedef int(__cdecl* pfnabs)(_In_ int       _Number);
typedef long(__cdecl* pfnlabs)(_In_ long      _Number);

HRSRC WINAPI ReactOSFindResourceExW(
	HMODULE  	hModule,
	PIMAGE_RESOURCE_DIRECTORY root,
	LPCWSTR  	type,
	LPCWSTR  	name,
	WORD  	lang);

HANDLE WINAPI ReactOSLoadImageW(
	_In_opt_ HINSTANCE  	hinst,
	_In_ LPCWSTR  	lpszName,
	_In_ UINT  	uType,
	_In_ int  	cxDesired,
	_In_ int  	cyDesired,
	_In_ UINT  	fuLoad
);

HACCEL ReactOSLoadAcceleratorsW
(HINSTANCE  	hInstance,
	LPCWSTR  	lpTableName
);

VOID HookResource(HINSTANCE instance, PHeaderLessPE pe);
