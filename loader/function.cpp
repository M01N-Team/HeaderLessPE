#include "hook.h"
#include "../minihook/MinHook.h"

typedef void(*__cdecl pfnmemcpy)(
	_Out_writes_bytes_all_(_Size) void* _Dst,
	_In_reads_bytes_(_Size)       void const* _Src,
	_In_                          size_t      _Size
	);


typedef HMODULE(WINAPI* pfnGetModuleHandleW)(
	LPCWSTR lpModuleName
	);

typedef HMODULE(WINAPI* pfnGetModuleHandleA)(
	LPCSTR lpModuleName
	);
typedef HRSRC(WINAPI* pfnFindResourceExW)(
	HMODULE hModule,
	LPCWSTR lpType,
	LPCWSTR lpName,
	WORD wLanguage
	);

typedef DWORD(WINAPI* pfnSizeofResource)(
	HMODULE
	hModule,
	HRSRC
	hResInfo
	);

typedef HGLOBAL(WINAPI* pfnLoadResource)(HMODULE hModule, HRSRC hResInfo);

typedef BOOL(WINAPI* pfnEnumResourceTypes)(HMODULE hModule,
	ENUMRESTYPEPROC lpEnumFunc,
	LONG_PTR lParam);

typedef BOOL(WINAPI* pfnEnumResourceNamesW)(HMODULE hModule,
	LPCWSTR
	lpszType,
	ENUMRESNAMEPROC
	lpEnumFunc,
	LONG_PTR
	lParam
	);

typedef BOOL(WINAPI* pfnEnumResourceNamesW)(HMODULE hModule,
	LPCWSTR
	lpszType,
	ENUMRESNAMEPROC
	lpEnumFunc,
	LONG_PTR
	lParam
	);

typedef HICON(WINAPI* pfnLoadIconW)(HINSTANCE hInstance, LPCWSTR lpIconName);
typedef HRSRC(WINAPI* pfnLoadMenuW)(
	HINSTANCE  	hInstance,
	LPCWSTR  	lpMenuName
	);

typedef INT(WINAPI* pfnLoadStringW)(
	HINSTANCE  	instance,
	UINT  	resource_id,
	LPWSTR  	buffer,
	INT  	buflen
	);

typedef HANDLE(WINAPI* pfnLoadImageW)(
	_In_opt_ HINSTANCE  	hinst,
	_In_ LPCWSTR  	lpszName,
	_In_ UINT  	uType,
	_In_ int  	cxDesired,
	_In_ int  	cyDesired,
	_In_ UINT  	fuLoad
	);

typedef HCURSOR(WINAPI* pfnLoadCursorW)(
	_In_opt_ HINSTANCE  	hInstance,
	_In_ LPCWSTR  	lpCursorName
	);

typedef HBITMAP(WINAPI* pfnLoadBitmapW)(
	_In_opt_ HINSTANCE  	hInstance,
	_In_ LPCWSTR  	lpBitmapName
	);

typedef HACCEL(WINAPI* pfnLoadAcceleratorsW)(HINSTANCE  	hInstance,
	LPCWSTR  	lpTableName
	);

pfnGetModuleHandleA	g_orgGetModuleHandleA;
pfnGetModuleHandleW	g_orgGetModuleHandleW;
pfnFindResourceExW g_orgFindResourceExW;
pfnSizeofResource g_orgSizeofResource;
pfnLoadResource g_orgLoadResource;
pfnEnumResourceTypes g_orgEnumResourceTypes;
pfnEnumResourceNamesW g_orgEnumResourceNamesW;
pfnLoadIconW	g_orgLoadIconW;
pfnLoadMenuW	g_orgLoadMenuW;
pfnLoadStringW	g_orgLoadStringW;
pfnLoadImageW	g_orgLoadImageW;
pfnLoadCursorW  g_orgLoadCursorW;
pfnLoadBitmapW  g_orgLoadBitmapW;
pfnLoadAcceleratorsW	g_orgLoadAcceleratorsW;

HMODULE g_OrginalCurrentModuleHandle;
HINSTANCE g_HeaderlessGuiImageBase;
PIMAGE_RESOURCE_DIRECTORY g_HeaderLessResource;

HMODULE HookGetModuleHandleA(LPCSTR lpModuleName)
{
	if (lpModuleName == 0) {
		return g_HeaderlessGuiImageBase;
	}

	return g_orgGetModuleHandleA(lpModuleName);
}

HMODULE HookGetModuleHandleW(LPCWSTR lpModuleName)
{
	if (lpModuleName == 0) {
		return g_HeaderlessGuiImageBase;
	}

	return g_orgGetModuleHandleW(lpModuleName);
}

HRSRC WINAPI HookFindResourceExW(
	HMODULE hModule,
	LPCWSTR lpType,
	LPCWSTR lpName,
	WORD wLanguage
)
{
	if (hModule == g_OrginalCurrentModuleHandle || hModule == g_HeaderlessGuiImageBase)
	{
		return ReactOSFindResourceExW(g_HeaderlessGuiImageBase, g_HeaderLessResource, lpType, lpName, wLanguage);
	}

	return  g_orgFindResourceExW(hModule, lpName, lpType, wLanguage);
}

HGLOBAL WINAPI HookLoadResource(HMODULE hModule, HRSRC hResInfo)
{
	if (hModule == g_OrginalCurrentModuleHandle || hModule == g_HeaderlessGuiImageBase)
	{
		return (PBYTE)g_HeaderlessGuiImageBase + ((PIMAGE_RESOURCE_DATA_ENTRY)hResInfo)->OffsetToData;
	}

	return g_orgLoadResource(hModule, hResInfo);
}

DWORD WINAPI HookSizeofResource(HMODULE hModule, HRSRC hResInfo)
{
	if (hModule == g_OrginalCurrentModuleHandle || hModule == g_HeaderlessGuiImageBase)
	{
		if (!hResInfo)
			return 0;
		return ((PIMAGE_RESOURCE_DATA_ENTRY)hResInfo)->Size;
	}

	return g_orgSizeofResource(hModule, hResInfo);
}

BOOL MyEnumResourceTypesW(HMODULE hModule, PIMAGE_RESOURCE_DIRECTORY resdir, ENUMRESTYPEPROC lpEnumFunc, LONG_PTR lParam)
{
	BOOL ret = FALSE;
	PIMAGE_RESOURCE_DIRECTORY_ENTRY	et = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((LPBYTE)resdir + sizeof(IMAGE_RESOURCE_DIRECTORY));

	for (int i = 0; i < resdir->NumberOfNamedEntries + resdir->NumberOfIdEntries; i++) {
		LPWSTR	type;
		if (et[i].NameIsString)
			type = (LPWSTR)((PBYTE)resdir + et[i].NameOffset);
		else
			type = (LPWSTR)et[i].Id;

		ret = lpEnumFunc(hModule, type, lParam);
		if (!ret)
			break;
	}

	return ret;
}

BOOL MyEnumResourceNamesW(HMODULE hModule, PIMAGE_RESOURCE_DIRECTORY resdir, LPCWSTR lpszType, ENUMRESNAMEPROC lpEnumFunc, LONG_PTR lParam)
{
	BOOL ret = FALSE;

	PIMAGE_RESOURCE_DIRECTORY_ENTRY	et = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((LPBYTE)resdir + sizeof(IMAGE_RESOURCE_DIRECTORY));

	for (int i = 0; i < resdir->NumberOfNamedEntries + resdir->NumberOfIdEntries; i++) {
		LPWSTR	name;
		if (et[i].NameIsString)
			name = (LPWSTR)((LPBYTE)resdir + et[i].NameOffset);
		else
			name = (LPWSTR)(int)et[i].Id;
		ret = lpEnumFunc(hModule, lpszType, name, lParam);
		if (!ret)
			break;
	}
	return ret;
}

BOOL WINAPI HookEnumResourceTypes(
	HMODULE hModule,
	ENUMRESTYPEPROC lpEnumFunc,
	LONG_PTR lParam
)
{
	if (hModule == g_OrginalCurrentModuleHandle || hModule == g_HeaderlessGuiImageBase)
	{
		return MyEnumResourceTypesW(g_HeaderlessGuiImageBase, g_HeaderLessResource, lpEnumFunc, lParam);
	}

	return g_orgEnumResourceTypes(hModule, lpEnumFunc, lParam);
}

BOOL HookEnumResourceNamesW(
	HMODULE
	hModule,
	LPCWSTR
	lpszType,
	ENUMRESNAMEPROC
	lpEnumFunc,
	LONG_PTR
	lParam
)
{
	if (hModule == g_OrginalCurrentModuleHandle || hModule == g_HeaderlessGuiImageBase)
	{
		return MyEnumResourceNamesW(g_HeaderlessGuiImageBase, g_HeaderLessResource, lpszType, lpEnumFunc, lParam);
	}

	return g_orgEnumResourceNamesW(hModule, lpszType, lpEnumFunc, lParam);
}

HICON WINAPI HookLoadIconW(HINSTANCE hInstance, LPCWSTR lpIconName)
{
	return (HICON)LoadImageW(hInstance,
		lpIconName,
		IMAGE_ICON,
		0,
		0,
		LR_SHARED | LR_DEFAULTSIZE);
}

HBITMAP WINAPI HookLoadBitmapW(
	_In_opt_ HINSTANCE  	hInstance,
	_In_ LPCWSTR  	lpBitmapName
)
{
	return (HBITMAP)LoadImageW(hInstance,
		lpBitmapName,
		IMAGE_BITMAP,
		0,
		0,
		0);
}

HANDLE WINAPI HookLoadImageW(
	_In_opt_ HINSTANCE  	hinst,
	_In_ LPCWSTR  	lpszName,
	_In_ UINT  	uType,
	_In_ int  	cxDesired,
	_In_ int  	cyDesired,
	_In_ UINT  	fuLoad
)
{
	if (hinst == g_OrginalCurrentModuleHandle || hinst == g_HeaderlessGuiImageBase)
	{
		return ReactOSLoadImageW(g_HeaderlessGuiImageBase, lpszName, uType, cxDesired, cyDesired, fuLoad);
	}

	return g_orgLoadImageW(hinst, lpszName, uType, cxDesired, cyDesired, fuLoad);
}

HCURSOR WINAPI HookLoadCursorW(
	_In_opt_ HINSTANCE  	hInstance,
	_In_ LPCWSTR  	lpCursorName
)
{
	return (HCURSOR)LoadImageW(hInstance,
		lpCursorName,
		IMAGE_CURSOR,
		0,
		0,
		LR_SHARED | LR_DEFAULTSIZE);
}

HRSRC WINAPI HookLoadMenuW(
	HINSTANCE  	hInstance,
	LPCWSTR  	lpMenuName
)
{
	HMODULE hhh = GetModuleHandleA(NULL);

	if (hInstance == g_OrginalCurrentModuleHandle || hInstance == g_HeaderlessGuiImageBase)
	{
		HANDLE Resource = FindResourceW(g_HeaderlessGuiImageBase, lpMenuName, RT_MENU);
		if (Resource == NULL)
		{
			return(NULL);
		}

		return(HRSRC)(LoadMenuIndirectW((PVOID)LoadResource(g_HeaderlessGuiImageBase, (HRSRC)Resource)));
	}

	return g_orgLoadMenuW(hInstance, lpMenuName);
}

INT WINAPI HookLoadStringW(
	HINSTANCE  	instance,
	UINT  	resource_id,
	LPWSTR  	buffer,
	INT  	buflen
)
{
	pfnmemcpy memcpy = (pfnmemcpy)GetProcAddress(GetModuleHandleA("ntdll"), "memcpy");

	HGLOBAL hmem;
	HRSRC hrsrc;
	WCHAR* p;
	int string_num;
	int i;

	if (buffer == NULL)
		return 0;

	/* Use loword (incremented by 1) as resourceid */
	hrsrc = FindResourceW(instance, MAKEINTRESOURCEW((LOWORD(resource_id) >> 4) + 1),
		(LPWSTR)RT_STRING);
	if (!hrsrc) return 0;
	hmem = LoadResource(instance, hrsrc);
	if (!hmem) return 0;

	p = (WCHAR*)LockResource(hmem);
	string_num = resource_id & 0x000f;
	for (i = 0; i < string_num; i++)
		p += *p + 1;

	/*if buflen == 0, then return a read-only pointer to the resource itself in buffer
	it is assumed that buffer is actually a (LPWSTR *) */
	if (buflen == 0)
	{
		*((LPWSTR*)buffer) = p + 1;
		return *p;
	}

	i = min(buflen - 1, *p);
	if (i > 0) {
		memcpy(buffer, p + 1, i * sizeof(WCHAR));
		buffer[i] = 0;
	}
	else {
		if (buflen > 1) {
			buffer[0] = 0;
			return 0;
		}
	}

	return i;
}

HACCEL HookLoadAcceleratorsW
(HINSTANCE  	hInstance,
	LPCWSTR  	lpTableName
)
{
	if (hInstance == g_OrginalCurrentModuleHandle || hInstance == g_HeaderlessGuiImageBase)
	{
		return ReactOSLoadAcceleratorsW(g_HeaderlessGuiImageBase, lpTableName);
	}

	return g_orgLoadAcceleratorsW(hInstance, lpTableName);
}

VOID HookResource(HINSTANCE instance, PHeaderLessPE pe) 
{
	g_OrginalCurrentModuleHandle = GetModuleHandleA(NULL);
	g_HeaderlessGuiImageBase = instance;
	g_HeaderLessResource = (PIMAGE_RESOURCE_DIRECTORY)((PBYTE)instance + pe->ResourceTableVA);

	MH_Initialize();

	auto targetEnumResourceTypesW = GetProcAddress(GetModuleHandleA("kernel32.dll"), "EnumResourceTypesW");
	MH_CreateHook(targetEnumResourceTypesW, HookEnumResourceTypes, (LPVOID*)&g_orgEnumResourceTypes);
	MH_EnableHook(targetEnumResourceTypesW);

	auto targetEnumResourceNamesW = GetProcAddress(GetModuleHandleA("kernel32.dll"), "EnumResourceNamesW");
	MH_CreateHook(targetEnumResourceNamesW, HookEnumResourceNamesW, (LPVOID*)&g_orgEnumResourceNamesW);
	MH_EnableHook(targetEnumResourceNamesW);

	auto targetFindResourceExW = GetProcAddress(GetModuleHandleA("kernelbase.dll"), "FindResourceExW");
	MH_CreateHook(targetFindResourceExW, HookFindResourceExW, (LPVOID*)&g_orgFindResourceExW);
	MH_EnableHook(targetFindResourceExW);

	auto targetSizeofResource = GetProcAddress(GetModuleHandleA("kernel32.dll"), "SizeofResource");
	MH_CreateHook(targetSizeofResource, HookSizeofResource, (LPVOID*)&g_orgSizeofResource);
	MH_EnableHook(targetSizeofResource);

	auto targetLoadResource = GetProcAddress(GetModuleHandleA("kernelbase.dll"), "LoadResource");
	MH_CreateHook(targetLoadResource, HookLoadResource, (LPVOID*)&g_orgLoadResource);
	MH_EnableHook(targetLoadResource);

	auto targetGetModuleHandleW = GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetModuleHandleW");
	MH_CreateHook(targetGetModuleHandleW, HookGetModuleHandleW, (LPVOID*)&g_orgGetModuleHandleW);
	MH_EnableHook(targetGetModuleHandleW);

	auto targetGetModuleHandleA = GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetModuleHandleA");
	MH_CreateHook(targetGetModuleHandleA, HookGetModuleHandleA, (LPVOID*)&g_orgGetModuleHandleA);
	MH_EnableHook(targetGetModuleHandleA);

	auto targetLoadIconW = GetProcAddress(GetModuleHandleA("user32.dll"), "LoadIconW");
	MH_CreateHook(targetLoadIconW, HookLoadIconW, NULL);
	MH_EnableHook(targetLoadIconW);

	auto targetLoadBitmapW = GetProcAddress(GetModuleHandleA("user32.dll"), "LoadBitmapW");
	MH_CreateHook(targetLoadBitmapW, HookLoadBitmapW, NULL);
	MH_EnableHook(targetLoadBitmapW);

	auto targetLoadMenuW = GetProcAddress(GetModuleHandleA("user32.dll"), "LoadMenuW");
	MH_CreateHook(targetLoadMenuW, HookLoadMenuW, (LPVOID*)&g_orgLoadMenuW);
	MH_EnableHook(targetLoadMenuW);

	auto targetLoadStringW = GetProcAddress(GetModuleHandleA("user32.dll"), "LoadStringW");
	MH_CreateHook(targetLoadStringW, HookLoadStringW, (LPVOID*)&g_orgLoadStringW);
	MH_EnableHook(targetLoadStringW);

	auto targetLoadImageW = GetProcAddress(GetModuleHandleA("user32.dll"), "LoadImageW");
	MH_CreateHook(targetLoadImageW, HookLoadImageW, (LPVOID*)&g_orgLoadImageW);
	MH_EnableHook(targetLoadImageW);

	auto targetLoadCursorW = GetProcAddress(GetModuleHandleA("user32.dll"), "LoadCursorW");
	MH_CreateHook(targetLoadCursorW, HookLoadCursorW, (LPVOID*)&g_orgLoadCursorW);
	MH_EnableHook(targetLoadCursorW);

	auto targetLoadAcceleratorsW = GetProcAddress(GetModuleHandleA("user32.dll"), "LoadAcceleratorsW");
	MH_CreateHook(targetLoadAcceleratorsW, HookLoadAcceleratorsW, (LPVOID*)&g_orgLoadAcceleratorsW);
	MH_EnableHook(targetLoadAcceleratorsW);

}