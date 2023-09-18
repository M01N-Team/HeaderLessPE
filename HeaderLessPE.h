#ifndef __HEADER_LESS_GUI_PE__
#define __HEADER_LESS_GUI_PE__

#include <windows.h>

typedef void (*pfnStart)(int, const char* []);
typedef int (WINAPI* pfnWinMain)(HINSTANCE hInstance, HINSTANCE prevInstance, LPSTR lpCmdLine, int nShowCmd);


#pragma pack(push, 1)

typedef struct _HeaderLessSection {
	DWORD	VA;
	DWORD	VirtualSize;
	DWORD	RawOffset;
	DWORD	RawSize;
	BYTE	Access;
}HeaderLessSection, * PHeaderLessSection;

typedef struct _HeaderLessPE
{
	PVOID	ImageBase;
	DWORD	ImageSize;
	DWORD	ImageEntryPoint;
	DWORD	ImportTableVA;
	DWORD	RelocTableVA;
	DWORD	RelocTableSize;
	DWORD	ResourceTableVA;
	DWORD	ResourceTableSize;
	DWORD	SectionCount;
	HeaderLessSection Section[1];
}HeaderLessPE, * PHeaderLessPE;

#pragma pack(pop)


BOOL pe2headerless(BYTE* image, PHeaderLessPE* header_less_pe, SIZE_T* length);
FARPROC LoadHeaderLessPE(BYTE* blob, BYTE* args, HINSTANCE* instance);
FARPROC SpawnHeaderLessPE(PHeaderLessPE pe, HANDLE hTarget, BYTE* args);

#endif