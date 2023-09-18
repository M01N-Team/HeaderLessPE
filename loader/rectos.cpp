#include "hook.h"

#include <Windows.h>
#include <WinNT.h>
//
// Loader Resource Information
//

#define DPRINT 

// NTSTATUS
typedef LONG NTSTATUS;
#define NT_SUCCESS(Status)								((NTSTATUS)(Status) >= 0)
#define STATUS_SUCCESS										((NTSTATUS)0x00000000L)
#define STATUS_UNSUCCESSFUL								((NTSTATUS)0xC0000001L)
#define STATUS_INFO_LENGTH_MISMATCH				((NTSTATUS)0xC0000004L)
#define STATUS_BUFFER_TOO_SMALL						((NTSTATUS)0xC0000023L)

#define STATUS_RESOURCE_TYPE_NOT_FOUND   ((NTSTATUS)0xC000008A)
#define STATUS_RESOURCE_NAME_NOT_FOUND   ((NTSTATUS)0xC000008B)
#define STATUS_RESOURCE_NOT_OWNED   ((NTSTATUS)0xC0000264)
#define STATUS_RESOURCE_REQUIREMENTS_CHANGED   ((NTSTATUS)0x00000119)
#define STATUS_RESOURCE_TYPE_NOT_FOUND   ((NTSTATUS)0xC000008A)
#define STATUS_RESOURCE_LANG_NOT_FOUND   ((NTSTATUS)0xC0000204)

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _LDR_RESOURCE_INFO
{
    ULONG_PTR Type;
    ULONG_PTR Name;
    ULONG_PTR Language;
} LDR_RESOURCE_INFO, * PLDR_RESOURCE_INFO;

typedef struct _LDR_ENUM_RESOURCE_INFO
{
    ULONG_PTR Type;
    ULONG_PTR Name;
    ULONG_PTR Language;
    PVOID Data;
    ULONG Size;
    ULONG Reserved;
} LDR_ENUM_RESOURCE_INFO, * PLDR_ENUM_RESOURCE_INFO;

/**********************************************************************
 *  push_language
 *
 * push a language in the list of languages to try
 */
int push_language(USHORT* list, ULONG pos, WORD lang)
{
    ULONG i;
    for (i = 0; i < pos; i++) if (list[i] == lang) return pos;
    list[pos++] = lang;
    return pos;
}

IMAGE_RESOURCE_DIRECTORY* find_entry_by_id(IMAGE_RESOURCE_DIRECTORY* dir,
    WORD  	id,
    void* root,
    int  	want_dir
)
{
    const IMAGE_RESOURCE_DIRECTORY_ENTRY* entry;
    int min, max, pos;

    entry = (const IMAGE_RESOURCE_DIRECTORY_ENTRY*)(dir + 1);
    min = dir->NumberOfNamedEntries;
    max = min + dir->NumberOfIdEntries - 1;
    while (min <= max)
    {
        pos = (min + max) / 2;
        if (entry[pos].Id == id)
        {
            if (!entry[pos].DataIsDirectory == !want_dir)
            {
                DPRINT("root %p dir %p id %04x ret %p\n",
                    root, dir, id, (const char*)root + entry[pos].OffsetToDirectory);
                return (IMAGE_RESOURCE_DIRECTORY*)((char*)root + entry[pos].OffsetToDirectory);
            }
            break;
        }
        if (entry[pos].Id > id) max = pos - 1;
        else min = pos + 1;
    }
    DPRINT("root %p dir %p id %04x not found\n", root, dir, id);
    return NULL;
}

IMAGE_RESOURCE_DIRECTORY* find_entry_by_name(IMAGE_RESOURCE_DIRECTORY* dir,
    LPCWSTR  	name,
    void* root,
    int  	want_dir
)
{
    pfnwcslen wcslen = (pfnwcslen)GetProcAddress(GetModuleHandleA("ntdll"), "wcslen");
    pfn_wcsnicmp _wcsnicmp = (pfn_wcsnicmp)GetProcAddress(GetModuleHandleA("ntdll"), "_wcsnicmp");

    const IMAGE_RESOURCE_DIRECTORY_ENTRY* entry;
    const IMAGE_RESOURCE_DIR_STRING_U* str;
    int min, max, res, pos;
    size_t namelen;

    if (!((ULONG_PTR)name & 0xFFFF0000)) return find_entry_by_id(dir, (ULONG_PTR)name & 0xFFFF, root, want_dir);
    entry = (const IMAGE_RESOURCE_DIRECTORY_ENTRY*)(dir + 1);
    namelen = wcslen(name);
    min = 0;
    max = dir->NumberOfNamedEntries - 1;
    while (min <= max)
    {
        pos = (min + max) / 2;
        str = (const IMAGE_RESOURCE_DIR_STRING_U*)((const char*)root + entry[pos].NameOffset);
        res = _wcsnicmp(name, str->NameString, str->Length);
        if (!res && namelen == str->Length)
        {
            if (!entry[pos].DataIsDirectory == !want_dir)
            {
                DPRINT("root %p dir %p name %ws ret %p\n",
                    root, dir, name, (const char*)root + entry[pos].OffsetToDirectory);
                return (IMAGE_RESOURCE_DIRECTORY*)((char*)root + entry[pos].OffsetToDirectory);
            }
            break;
        }
        if (res < 0) max = pos - 1;
        else min = pos + 1;
    }
    DPRINT("root %p dir %p name %ws not found\n", root, dir, name);
    return NULL;
}

IMAGE_RESOURCE_DIRECTORY* find_first_entry(IMAGE_RESOURCE_DIRECTORY* dir,
    void* root,
    int  	want_dir
)
{
    const IMAGE_RESOURCE_DIRECTORY_ENTRY* entry = (const IMAGE_RESOURCE_DIRECTORY_ENTRY*)(dir + 1);
    int pos;

    for (pos = 0; pos < dir->NumberOfNamedEntries + dir->NumberOfIdEntries; pos++)
    {
        if (!entry[pos].DataIsDirectory == !want_dir)
            return (IMAGE_RESOURCE_DIRECTORY*)((char*)root + entry[pos].OffsetToDirectory);
    }
    return NULL;
}

NTSTATUS find_entry(
    PVOID  	BaseAddress,
    PIMAGE_RESOURCE_DIRECTORY pResoucesRoot,
    LDR_RESOURCE_INFO* info,
    ULONG  	level,
    void** ret,
    int  	want_dir
)
{
    ULONG size;
    void* root = (void*)pResoucesRoot;
    IMAGE_RESOURCE_DIRECTORY* resdirptr = pResoucesRoot;
    USHORT list[9];  /* list of languages to try */
    int i, pos = 0;
    LCID user_lcid, system_lcid;

    if (!level--) goto done;
    if (!(*ret = find_entry_by_name(resdirptr, (LPCWSTR)info->Type, root, want_dir || level)))
        return STATUS_RESOURCE_TYPE_NOT_FOUND;
    if (!level--) return STATUS_SUCCESS;

    resdirptr = (PIMAGE_RESOURCE_DIRECTORY)*ret;
    if (!(*ret = find_entry_by_name(resdirptr, (LPCWSTR)info->Name, root, want_dir || level)))
        return STATUS_RESOURCE_NAME_NOT_FOUND;
    if (!level--) return STATUS_SUCCESS;
    if (level) return STATUS_INVALID_PARAMETER;  /* level > 3 */

    /* 1. specified language */
    pos = push_language(list, pos, info->Language);

    /* 2. specified language with neutral sublanguage */
    pos = push_language(list, pos, MAKELANGID(PRIMARYLANGID(info->Language), SUBLANG_NEUTRAL));

    /* 3. neutral language with neutral sublanguage */
    pos = push_language(list, pos, MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL));

    /* if no explicitly specified language, try some defaults */
    if (PRIMARYLANGID(info->Language) == LANG_NEUTRAL)
    {
        /* user defaults, unless SYS_DEFAULT sublanguage specified  */
        if (SUBLANGID(info->Language) != SUBLANG_SYS_DEFAULT)
        {
            /* 4. current thread locale language */
            //pos = push_language(list, pos, LANGIDFROMLCID(NtCurrentTeb()->CurrentLocale));

            //if (NT_SUCCESS(NtQueryDefaultLocale(TRUE, &user_lcid)))
            //{
            //    /* 5. user locale language */
            //    pos = push_language(list, pos, LANGIDFROMLCID(user_lcid));

            //    /* 6. user locale language with neutral sublanguage  */
            //    pos = push_language(list, pos, MAKELANGID(PRIMARYLANGID(user_lcid), SUBLANG_NEUTRAL));
            //}
        }

        /* now system defaults */

        //if (NT_SUCCESS(NtQueryDefaultLocale(FALSE, &system_lcid)))
        //{
        //    /* 7. system locale language */
        //    pos = push_language(list, pos, LANGIDFROMLCID(system_lcid));

        //    /* 8. system locale language with neutral sublanguage */
        //    pos = push_language(list, pos, MAKELANGID(PRIMARYLANGID(system_lcid), SUBLANG_NEUTRAL));
        //}

        /* 9. English */
        pos = push_language(list, pos, MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT));
    }

    resdirptr = (PIMAGE_RESOURCE_DIRECTORY)*ret;
    for (i = 0; i < pos; i++)
        if ((*ret = find_entry_by_id(resdirptr, list[i], root, want_dir))) return STATUS_SUCCESS;

    /* if no explicitly specified language, return the first entry */
    if (PRIMARYLANGID(info->Language) == LANG_NEUTRAL)
    {
        if ((*ret = find_first_entry(resdirptr, root, want_dir))) return STATUS_SUCCESS;
    }
    return STATUS_RESOURCE_LANG_NOT_FOUND;

done:
    *ret = resdirptr;
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI LdrFindResource_U(
    PVOID  	BaseAddress,
    PIMAGE_RESOURCE_DIRECTORY   root,
	PLDR_RESOURCE_INFO  	ResourceInfo,
	ULONG  	Level,
	PIMAGE_RESOURCE_DATA_ENTRY* ResourceDataEntry
)
{
    void* res;
    NTSTATUS status = STATUS_SUCCESS;

    if (ResourceInfo)
    {
        DPRINT("module %p type %lx name %lx lang %04lx level %lu\n",
            BaseAddress, ResourceInfo->Type,
            Level > 1 ? ResourceInfo->Name : 0,
            Level > 2 ? ResourceInfo->Language : 0, Level);
    }

    status = find_entry(BaseAddress, root, ResourceInfo, Level, &res, FALSE);
    if (NT_SUCCESS(status))
        *ResourceDataEntry = (PIMAGE_RESOURCE_DATA_ENTRY)res;
    return status;
}

NTSTATUS NTAPI RtlUnicodeStringToInteger(
    PUNICODE_STRING  	str,
    ULONG  	    base,
    PULONG  	value
)
{
    LPWSTR lpwstr = str->Buffer;
    USHORT CharsRemaining = str->Length / sizeof(WCHAR);
    WCHAR wchCurrent;
    int digit;
    ULONG RunningTotal = 0;
    char bMinus = 0;

    while (CharsRemaining >= 1 && *lpwstr <= ' ')
    {
        lpwstr++;
        CharsRemaining--;
    }

    if (CharsRemaining >= 1)
    {
        if (*lpwstr == '+')
        {
            lpwstr++;
            CharsRemaining--;
        }
        else if (*lpwstr == '-')
        {
            bMinus = 1;
            lpwstr++;
            CharsRemaining--;
        }
    }

    if (base == 0)
    {
        base = 10;

        if (CharsRemaining >= 2 && lpwstr[0] == '0')
        {
            if (lpwstr[1] == 'b')
            {
                lpwstr += 2;
                CharsRemaining -= 2;
                base = 2;
            }
            else if (lpwstr[1] == 'o')
            {
                lpwstr += 2;
                CharsRemaining -= 2;
                base = 8;
            }
            else if (lpwstr[1] == 'x')
            {
                lpwstr += 2;
                CharsRemaining -= 2;
                base = 16;
            }
        }
    }
    else if (base != 2 && base != 8 && base != 10 && base != 16)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (value == NULL)
    {
        return STATUS_ACCESS_VIOLATION;
    }

    while (CharsRemaining >= 1)
    {
        wchCurrent = *lpwstr;

        if (wchCurrent >= '0' && wchCurrent <= '9')
        {
            digit = wchCurrent - '0';
        }
        else if (wchCurrent >= 'A' && wchCurrent <= 'Z')
        {
            digit = wchCurrent - 'A' + 10;
        }
        else if (wchCurrent >= 'a' && wchCurrent <= 'z')
        {
            digit = wchCurrent - 'a' + 10;
        }
        else
        {
            digit = -1;
        }

        if (digit < 0 || (ULONG)digit >= base) break;

        RunningTotal = RunningTotal * base + digit;
        lpwstr++;
        CharsRemaining--;
    }

    *value = bMinus ? (0 - RunningTotal) : RunningTotal;
    return STATUS_SUCCESS;
}

typedef void(*__cdecl pfnmemcpy)(
    _Out_writes_bytes_all_(_Size) void* _Dst,
    _In_reads_bytes_(_Size)       void const* _Src,
    _In_                          size_t      _Size
    );

typedef NTSTATUS(NTAPI* pfnRtlUpcaseUnicodeString)(
    PUNICODE_STRING  	dst,
    PUNICODE_STRING  	src,
    BOOLEAN  	Alloc
    );

static NTSTATUS get_res_nameW(
    LPCWSTR  	name,
    UNICODE_STRING* str
)
{
    typedef BOOLEAN(NTAPI* pfnRtlCreateUnicodeString)(
        IN OUT PUNICODE_STRING  	UniDest,
        IN PCWSTR  	Source
        );

    typedef VOID(NTAPI* pfnRtlInitUnicodeString)(PUNICODE_STRING DestinationString, PCWSTR SourceString);

    pfnRtlCreateUnicodeString RtlCreateUnicodeString = (pfnRtlCreateUnicodeString)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlCreateUnicodeString");
    pfnRtlInitUnicodeString RtlInitUnicodeString = (pfnRtlInitUnicodeString)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlInitUnicodeString");
    pfnRtlUpcaseUnicodeString RtlUpcaseUnicodeString = (pfnRtlUpcaseUnicodeString)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlUpcaseUnicodeString");

    if (IS_INTRESOURCE(name))
    {
        str->Buffer = (PWSTR)ULongToPtr(LOWORD(name));
        return STATUS_SUCCESS;
    }
    if (name[0] == '#')
    {
        ULONG value;
        RtlInitUnicodeString(str, name + 1);
        if (RtlUnicodeStringToInteger(str, 10, &value) != STATUS_SUCCESS || HIWORD(value))
            return STATUS_INVALID_PARAMETER;
        str->Buffer = (PWSTR)ULongToPtr(value);
        return STATUS_SUCCESS;
    }
    RtlCreateUnicodeString(str, name);
    RtlUpcaseUnicodeString(str, str, FALSE);
    return STATUS_SUCCESS;
}

static HRSRC find_resourceW(
    HMODULE  	hModule,
    PIMAGE_RESOURCE_DIRECTORY root,
    LPCWSTR  	type,
    LPCWSTR  	name,
    WORD  	lang
)
{
    typedef ULONG(WINAPI* pfnRtlNtStatusToDosError)(NTSTATUS);

    pfnRtlNtStatusToDosError RtlNtStatusToDosError = (pfnRtlNtStatusToDosError)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlNtStatusToDosError");

    NTSTATUS status;
    UNICODE_STRING nameW, typeW;
    LDR_RESOURCE_INFO info;
    IMAGE_RESOURCE_DATA_ENTRY* entry = NULL;

    nameW.Buffer = typeW.Buffer = NULL;

    if ((status = get_res_nameW(name, &nameW)) != STATUS_SUCCESS) goto done;
    if ((status = get_res_nameW(type, &typeW)) != STATUS_SUCCESS) goto done;
    info.Type = (ULONG_PTR)typeW.Buffer;
    info.Name = (ULONG_PTR)nameW.Buffer;
    info.Language = lang;
    status = LdrFindResource_U(hModule, root, &info, 3, &entry);
done:
    if (status != STATUS_SUCCESS) SetLastError(RtlNtStatusToDosError(status));



    if (!IS_INTRESOURCE(nameW.Buffer)) HeapFree(GetProcessHeap(), 0, nameW.Buffer);
    if (!IS_INTRESOURCE(typeW.Buffer)) HeapFree(GetProcessHeap(), 0, typeW.Buffer);

    return (HRSRC)entry;
}

static NTSTATUS LdrpAccessResource(
    PVOID  	BaseAddress,
    IMAGE_RESOURCE_DATA_ENTRY* entry,
    void** ptr,
    ULONG* size
)
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG dirsize;

    //if (!RtlImageDirectoryEntryToData(BaseAddress, TRUE, IMAGE_DIRECTORY_ENTRY_RESOURCE, &dirsize))
    //    status = STATUS_RESOURCE_DATA_NOT_FOUND;
    //else
    //{
    //    if (ptr)
    //    {
    //        if (is_data_file_module(BaseAddress))
    //        {
    //            PVOID mod = (PVOID)((ULONG_PTR)BaseAddress & ~1);
    //            *ptr = RtlImageRvaToVa(RtlImageNtHeader(mod), mod, entry->OffsetToData, NULL);
    //        }
    //        else *ptr = (char*)BaseAddress + entry->OffsetToData;
    //    }
    //    if (size) *size = entry->Size;
    //}

    return status;
}

HGLOBAL WINAPI ReactOSLoadResource(HINSTANCE  	hModule,
    HRSRC  	hRsrc
)
{
    NTSTATUS status;
    void* ret = NULL;

    //TRACE("%p %p\n", hModule, hRsrc);

    if (!hRsrc) return 0;
    if (!hModule) hModule = GetModuleHandleA(NULL);
    status = LdrpAccessResource(hModule, (IMAGE_RESOURCE_DATA_ENTRY*)hRsrc, &ret, NULL);
    //if (status != STATUS_SUCCESS) SetLastError(RtlNtStatusToDosError(status));
    return ret;
}

HRSRC WINAPI ReactOSFindResourceExW(
    HMODULE  	hModule,
    PIMAGE_RESOURCE_DIRECTORY root,
    LPCWSTR  	type,
    LPCWSTR  	name,
    WORD  	lang
)
{
    return find_resourceW(hModule, root, type, name, lang);
}

HRSRC WINAPI ReactOSLoadMenuW(
    HINSTANCE  	hInstance,
    LPCWSTR  	lpMenuName
) 
{
    HANDLE Resource = FindResourceW(hInstance, lpMenuName, RT_MENU);
    if (Resource == NULL)
    {
        return(NULL);
    }
    return(HRSRC)(LoadMenuIndirectW((PVOID)LoadResource(hInstance, (HRSRC)Resource)));
}

static void* map_fileW(
    LPCWSTR  	name,
    LPDWORD  	filesize
)
{
    HANDLE hFile, hMapping;
    LPVOID ptr = NULL;

    hFile = CreateFileW(name, GENERIC_READ, FILE_SHARE_READ, NULL,
        OPEN_EXISTING, FILE_FLAG_RANDOM_ACCESS, 0);
    if (hFile != INVALID_HANDLE_VALUE)
    {
        hMapping = CreateFileMappingW(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
        if (hMapping)
        {
            ptr = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
            CloseHandle(hMapping);
            if (filesize)
                *filesize = GetFileSize(hFile, NULL);
        }
        CloseHandle(hFile);
    }
    return ptr;
}

#define FIXME 
#define WARN 
#define ERR
#define TRACE

static int bitmap_info_size(const BITMAPINFO* info,
    WORD  	coloruse
)
{
    unsigned int colors, size, masks = 0;

    if (info->bmiHeader.biSize == sizeof(BITMAPCOREHEADER))
    {
        const BITMAPCOREHEADER* core = (const BITMAPCOREHEADER*)info;
        colors = (core->bcBitCount <= 8) ? 1 << core->bcBitCount : 0;
        return sizeof(BITMAPCOREHEADER) + colors *
            ((coloruse == DIB_RGB_COLORS) ? sizeof(RGBTRIPLE) : sizeof(WORD));
    }
    else  /* assume BITMAPINFOHEADER */
    {
        colors = info->bmiHeader.biClrUsed;
        if (colors > 256) /* buffer overflow otherwise */
            colors = 256;
        if (!colors && (info->bmiHeader.biBitCount <= 8))
            colors = 1 << info->bmiHeader.biBitCount;
        if (info->bmiHeader.biCompression == BI_BITFIELDS) masks = 3;
        size = max(info->bmiHeader.biSize, sizeof(BITMAPINFOHEADER) + masks * sizeof(DWORD));
        return size + colors * ((coloruse == DIB_RGB_COLORS) ? sizeof(RGBQUAD) : sizeof(WORD));
    }
}

static int DIB_GetBitmapInfo(const BITMAPINFOHEADER* header,
    LONG* width,
    LONG* height,
    WORD* bpp,
    DWORD* compr
)
{
    if (header->biSize == sizeof(BITMAPCOREHEADER))
    {
        const BITMAPCOREHEADER* core = (const BITMAPCOREHEADER*)header;
        *width = core->bcWidth;
        *height = core->bcHeight;
        *bpp = core->bcBitCount;
        *compr = 0;
        return 0;
    }
    else if (header->biSize == sizeof(BITMAPINFOHEADER) ||
        header->biSize == sizeof(BITMAPV4HEADER) ||
        header->biSize == sizeof(BITMAPV5HEADER))
    {
        *width = header->biWidth;
        *height = header->biHeight;
        *bpp = header->biBitCount;
        *compr = header->biCompression;
        return 1;
    }
    ERR("(%d): unknown/wrong size for header\n", header->biSize);
    return -1;
}

const WCHAR DISPLAYW[] = L"DISPLAY";
static BOOL is_dib_monochrome(const BITMAPINFO* info)
{
    if (info->bmiHeader.biSize == sizeof(BITMAPCOREHEADER))
    {
        const RGBTRIPLE* rgb = ((const BITMAPCOREINFO*)info)->bmciColors;

        if (((const BITMAPCOREINFO*)info)->bmciHeader.bcBitCount != 1) return FALSE;

        /* Check if the first color is black */
        if ((rgb->rgbtRed == 0) && (rgb->rgbtGreen == 0) && (rgb->rgbtBlue == 0))
        {
            rgb++;

            /* Check if the second color is white */
            return ((rgb->rgbtRed == 0xff) && (rgb->rgbtGreen == 0xff)
                && (rgb->rgbtBlue == 0xff));
        }
        else return FALSE;
    }
    else  /* assume BITMAPINFOHEADER */
    {
        const RGBQUAD* rgb = info->bmiColors;

        if (info->bmiHeader.biBitCount != 1) return FALSE;

        /* Check if the first color is black */
        if ((rgb->rgbRed == 0) && (rgb->rgbGreen == 0) &&
            (rgb->rgbBlue == 0) && (rgb->rgbReserved == 0))
        {
            rgb++;

            /* Check if the second color is white */
            return ((rgb->rgbRed == 0xff) && (rgb->rgbGreen == 0xff)
                && (rgb->rgbBlue == 0xff) && (rgb->rgbReserved == 0));
        }
        else return FALSE;
    }
}

static HBITMAP BITMAP_LoadImageW(_In_opt_ HINSTANCE  	hinst,
    _In_ LPCWSTR  	lpszName,
    _In_ int  	cxDesired,
    _In_ int  	cyDesired,
    _In_ UINT  	fuLoad
)
{
    const BITMAPINFO* pbmi;
    BITMAPINFO* pbmiScaled = NULL;
    BITMAPINFO* pbmiCopy = NULL;
    const VOID* pvMapping = NULL;
    DWORD dwOffset = 0;
    HGLOBAL hgRsrc = NULL;
    int iBMISize;
    PVOID pvBits;
    HDC hdcScreen = NULL;
    HDC hdc = NULL;
    HBITMAP hbmpOld, hbmpRet = NULL;
    LONG width, height;
    WORD bpp;
    DWORD compr;
    pfnmemcpy memcpy = (pfnmemcpy)GetProcAddress(GetModuleHandleA("ntdll"), "memcpy");

    /* Map the bitmap info */
    if (fuLoad & LR_LOADFROMFILE)
    {
        const BITMAPFILEHEADER* pbmfh;

        pvMapping = map_fileW(lpszName, NULL);
        if (!pvMapping)
            return NULL;
        pbmfh = (const BITMAPFILEHEADER*)pvMapping;
        if (pbmfh->bfType != 0x4d42 /* 'BM' */)
        {
            WARN("Invalid/unsupported bitmap format!\n");
            goto end;
        }
        pbmi = (const BITMAPINFO*)(pbmfh + 1);

        /* Get the image bits */
        if (pbmfh->bfOffBits)
            dwOffset = pbmfh->bfOffBits - sizeof(BITMAPFILEHEADER);
    }
    else
    {
        HRSRC hrsrc;

        /* Caller wants an OEM bitmap */
        //if (!hinst)
        //    hinst = User32Instance;
        hrsrc = FindResourceW(hinst, lpszName, RT_BITMAP);
        if (!hrsrc)
            return NULL;
        hgRsrc = LoadResource(hinst, hrsrc);
        if (!hgRsrc)
            return NULL;
        pbmi = (const BITMAPINFO*)LockResource(hgRsrc);
        if (!pbmi)
            return NULL;
    }

    /* Fix up values */
    if (DIB_GetBitmapInfo(&pbmi->bmiHeader, &width, &height, &bpp, &compr) == -1)
        goto end;
    if ((width > 65535) || (height > 65535))
        goto end;
    if (cxDesired == 0)
        cxDesired = width;
    if (cyDesired == 0)
        cyDesired = height;
    else if (height < 0)
        cyDesired = -cyDesired;

    iBMISize = bitmap_info_size(pbmi, DIB_RGB_COLORS);

    /* Get a pointer to the image data */
    pvBits = (char*)pbmi + (dwOffset ? dwOffset : iBMISize);

    /* Create a copy of the info describing the bitmap in the file */
    pbmiCopy = (BITMAPINFO*)HeapAlloc(GetProcessHeap(), 0, iBMISize);
    if (!pbmiCopy)
        goto end;
    memcpy(pbmiCopy, pbmi, iBMISize);

    /* Fix it up, if needed */
    if (fuLoad & (LR_LOADTRANSPARENT | LR_LOADMAP3DCOLORS))
    {
        WORD bpp, incr, numColors;
        char* pbmiColors;
        RGBTRIPLE* ptr;
        COLORREF crWindow, cr3DShadow, cr3DFace, cr3DLight;
        BYTE pixel = *((BYTE*)pvBits);
        UINT i;

        if (pbmiCopy->bmiHeader.biSize == sizeof(BITMAPCOREHEADER))
        {
            bpp = ((BITMAPCOREHEADER*)&pbmiCopy->bmiHeader)->bcBitCount;
            numColors = 1 << bpp;
            /* BITMAPCOREINFO holds RGBTRIPLEs */
            incr = 3;
        }
        else
        {
            bpp = pbmiCopy->bmiHeader.biBitCount;
            /* BITMAPINFOHEADER holds RGBQUADs */
            incr = 4;
            numColors = pbmiCopy->bmiHeader.biClrUsed;
            if (numColors > 256) numColors = 256;
            if (!numColors && (bpp <= 8)) numColors = 1 << bpp;
        }

        if (bpp > 8)
            goto create_bitmap;

        pbmiColors = (char*)pbmiCopy + pbmiCopy->bmiHeader.biSize;

        /* Get the relevant colors */
        crWindow = GetSysColor(COLOR_WINDOW);
        cr3DShadow = GetSysColor(COLOR_3DSHADOW);
        cr3DFace = GetSysColor(COLOR_3DFACE);
        cr3DLight = GetSysColor(COLOR_3DLIGHT);

        /* Fix the transparent palette entry */
        if (fuLoad & LR_LOADTRANSPARENT)
        {
            switch (bpp)
            {
            case 1: pixel >>= 7; break;
            case 4: pixel >>= 4; break;
            case 8: break;
            default:
                FIXME("Unhandled bit depth %d.\n", bpp);
                goto create_bitmap;
            }

            if (pixel >= numColors)
            {
                ERR("Wrong pixel passed in.\n");
                goto create_bitmap;
            }

            /* If both flags are set, we must use COLOR_3DFACE */
            if (fuLoad & LR_LOADMAP3DCOLORS) crWindow = cr3DFace;

            /* Define the color */
            ptr = (RGBTRIPLE*)(pbmiColors + pixel * incr);
            ptr->rgbtBlue = GetBValue(crWindow);
            ptr->rgbtGreen = GetGValue(crWindow);
            ptr->rgbtRed = GetRValue(crWindow);
            goto create_bitmap;
        }

        /* If we are here, then LR_LOADMAP3DCOLORS is set without LR_TRANSPARENT */
        for (i = 0; i < numColors; i++)
        {
            ptr = (RGBTRIPLE*)(pbmiColors + i * incr);
            if ((ptr->rgbtBlue == ptr->rgbtRed) && (ptr->rgbtBlue == ptr->rgbtGreen))
            {
                if (ptr->rgbtBlue == 128)
                {
                    ptr->rgbtBlue = GetBValue(cr3DShadow);
                    ptr->rgbtGreen = GetGValue(cr3DShadow);
                    ptr->rgbtRed = GetRValue(cr3DShadow);
                }
                if (ptr->rgbtBlue == 192)
                {
                    ptr->rgbtBlue = GetBValue(cr3DFace);
                    ptr->rgbtGreen = GetGValue(cr3DFace);
                    ptr->rgbtRed = GetRValue(cr3DFace);
                }
                if (ptr->rgbtBlue == 223)
                {
                    ptr->rgbtBlue = GetBValue(cr3DLight);
                    ptr->rgbtGreen = GetGValue(cr3DLight);
                    ptr->rgbtRed = GetRValue(cr3DLight);
                }
            }
        }
    }

create_bitmap:
    if (fuLoad & LR_CREATEDIBSECTION)
    {
        /* Allocate the BMI describing the new bitmap */
        pbmiScaled = (BITMAPINFO*)HeapAlloc(GetProcessHeap(), 0, iBMISize);
        if (!pbmiScaled)
            goto end;
        memcpy(pbmiScaled, pbmiCopy, iBMISize);

        /* Fix it up */
        if (pbmiScaled->bmiHeader.biSize == sizeof(BITMAPCOREHEADER))
        {
            BITMAPCOREHEADER* pbmch = (BITMAPCOREHEADER*)&pbmiScaled->bmiHeader;
            pbmch->bcWidth = cxDesired;
            pbmch->bcHeight = cyDesired;
        }
        else
        {
            pbmiScaled->bmiHeader.biWidth = cxDesired;
            pbmiScaled->bmiHeader.biHeight = cyDesired;
            /* No compression for DIB sections */
            pbmiScaled->bmiHeader.biCompression = BI_RGB;
        }
    }

    /* Top-down image */
    if (cyDesired < 0) cyDesired = -cyDesired;

    /* We need a device context */
    hdcScreen = CreateDCW(DISPLAYW, NULL, NULL, NULL);
    if (!hdcScreen)
        goto end;
    hdc = CreateCompatibleDC(hdcScreen);
    if (!hdc)
        goto end;

    /* Now create the bitmap */
    if (fuLoad & LR_CREATEDIBSECTION)
        hbmpRet = CreateDIBSection(hdc, pbmiScaled, DIB_RGB_COLORS, NULL, 0, 0);
    else
    {
        if (is_dib_monochrome(pbmiCopy) || (fuLoad & LR_MONOCHROME))
            hbmpRet = CreateBitmap(cxDesired, cyDesired, 1, 1, NULL);
        else
            hbmpRet = CreateCompatibleBitmap(hdcScreen, cxDesired, cyDesired);
    }

    if (!hbmpRet)
        goto end;

    hbmpOld = (HBITMAP)SelectObject(hdc, hbmpRet);
    if (!hbmpOld)
        goto end;
    if (!StretchDIBits(hdc, 0, 0, cxDesired, cyDesired,
        0, 0, width, height,
        pvBits, pbmiCopy, DIB_RGB_COLORS, SRCCOPY))
    {
        ERR("StretchDIBits failed!.\n");
        SelectObject(hdc, hbmpOld);
        DeleteObject(hbmpRet);
        hbmpRet = NULL;
        goto end;
    }

    SelectObject(hdc, hbmpOld);

end:
    if (hdcScreen)
        DeleteDC(hdcScreen);
    if (hdc)
        DeleteDC(hdc);
    if (pbmiScaled)
        HeapFree(GetProcessHeap(), 0, pbmiScaled);
    if (pbmiCopy)
        HeapFree(GetProcessHeap(), 0, pbmiCopy);
    if (pvMapping)
        UnmapViewOfFile(pvMapping);
    if (hgRsrc)
        FreeResource(hgRsrc);

    return hbmpRet;
}

typedef struct
{
    WORD   wWidth;
    WORD   wHeight;
} CURSORDIR;

typedef struct
{
    BYTE bWidth;
    BYTE bHeight;
    BYTE bColorCount;
    BYTE bReserved;
} ICONRESDIR;

typedef struct
{
    WORD wWidth;
    WORD wHeight;
} CURSORRESDIR;

typedef struct
{
    union
    {
        ICONRESDIR icon;
        CURSORRESDIR  cursor;
    } ResInfo;
    WORD   wPlanes;
    WORD   wBitCount;
    DWORD  dwBytesInRes;
    WORD   wResId;
} CURSORICONDIRENTRY;

typedef struct
{
    WORD                idReserved;
    WORD                idType;
    WORD                idCount;
    CURSORICONDIRENTRY  idEntries[1];
} CURSORICONDIR;

typedef struct tagDDEPACK
{
    UINT_PTR uiLo;
    UINT_PTR uiHi;
} DDEPACK, * PDDEPACK;

typedef struct tagDDEPACK DDEPACK;

typedef struct tagCURSORDATA
{
    LPWSTR lpName;
    LPWSTR lpModName;
    USHORT rt;
    USHORT dummy;
    ULONG CURSORF_flags;
    SHORT xHotspot;
    SHORT yHotspot;
    HBITMAP hbmMask;
    HBITMAP hbmColor;
    HBITMAP hbmAlpha;
    RECT rcBounds;
    HBITMAP hbmUserAlpha; /* Could be in W7U, not in W2k */
    ULONG bpp;
    ULONG cx;
    ULONG cy;
    UINT cpcur;
    UINT cicur;
    struct tagCURSORDATA* aspcur;
    DWORD* aicur;
    INT* ajifRate;
    UINT iicur;
} CURSORDATA, * PCURSORDATA; /* !dso CURSORDATA */

typedef struct tagCURSORDATA CURSORDATA;

typedef struct _tagFINDEXISTINGCURICONPARAM
{
    BOOL bIcon;
    LONG cx;
    LONG cy;
} FINDEXISTINGCURICONPARAM;

typedef struct _tagFINDEXISTINGCURICONPARAM FINDEXISTINGCURICONPARAM;
#define CURSORF_FROMRESOURCE   0x0001

static int get_dib_image_size(
    int  	width,
    int  	height,
    int  	depth
)
{
    pfnabs abs = (pfnabs)GetProcAddress(GetModuleHandleA("ntdll"), "abs");
    return (((width * depth + 31) / 8) & ~3) * abs(height);
}

static BOOL bmi_has_alpha(const BITMAPINFO* info,
    const void* bits
)
{
    pfnabs abs = (pfnabs)GetProcAddress(GetModuleHandleA("ntdll"), "abs");

    int i;
    BOOL has_alpha = FALSE;
    const unsigned char* ptr = (const unsigned char*)bits;

    if (info->bmiHeader.biBitCount != 32) return FALSE;
    for (i = 0; i < info->bmiHeader.biWidth * abs(info->bmiHeader.biHeight); i++, ptr += 4)
        if ((has_alpha = (ptr[3] != 0))) break;
    return has_alpha;
}

static HBITMAP create_alpha_bitmap(_In_opt_ HBITMAP  	color,
    _In_opt_ BITMAPINFO* src_info,
    _In_opt_ const void* color_bits,
    _In_ LONG  	width,
    _In_ LONG  	height
)
{
    pfnmemcpy memcpy = (pfnmemcpy)GetProcAddress(GetModuleHandleA("ntdll"), "memcpy");
    HBITMAP alpha = NULL, hbmpOld;
    HDC hdc = NULL, hdcScreen;
    unsigned char* ptr;
    void* bits = NULL;
    ULONG size;

    hdcScreen = CreateDCW(DISPLAYW, NULL, NULL, NULL);
    if (!hdcScreen)
        return NULL;
    hdc = CreateCompatibleDC(hdcScreen);
    if (!hdc)
    {
        DeleteDC(hdcScreen);
        return NULL;
    }

    if (color)
    {
        BITMAP bm;
        BITMAPINFO* info = NULL;

        TRACE("Creating alpha bitmap from existing bitmap.\n");

        if (!GetObjectW(color, sizeof(bm), &bm))
            goto done;
        if (bm.bmBitsPixel != 32)
            goto done;

        size = get_dib_image_size(bm.bmWidth, bm.bmHeight, 32);

        info = (BITMAPINFO*)HeapAlloc(GetProcessHeap(), 0, FIELD_OFFSET(BITMAPINFO, bmiColors[256]));
        if (!info)
            goto done;
        info->bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
        info->bmiHeader.biWidth = bm.bmWidth;
        info->bmiHeader.biHeight = -bm.bmHeight;
        info->bmiHeader.biPlanes = 1;
        info->bmiHeader.biBitCount = 32;
        info->bmiHeader.biCompression = BI_RGB;
        info->bmiHeader.biSizeImage = size;
        info->bmiHeader.biXPelsPerMeter = 0;
        info->bmiHeader.biYPelsPerMeter = 0;
        info->bmiHeader.biClrUsed = 0;
        info->bmiHeader.biClrImportant = 0;

        bits = HeapAlloc(GetProcessHeap(), 0, size);
        if (!bits)
        {
            HeapFree(GetProcessHeap(), 0, info);
            goto done;
        }
        if (!GetDIBits(hdc, color, 0, bm.bmHeight, bits, info, DIB_RGB_COLORS))
        {
            HeapFree(GetProcessHeap(), 0, info);
            goto done;
        }
        if (!bmi_has_alpha(info, bits))
        {
            HeapFree(GetProcessHeap(), 0, info);
            goto done;
        }

        /* pre-multiply by alpha */
        for (ptr = (unsigned char*)bits; ptr < ((BYTE*)bits + size); ptr += 4)
        {
            unsigned int alpha = ptr[3];
            ptr[0] = (ptr[0] * alpha) / 255;
            ptr[1] = (ptr[1] * alpha) / 255;
            ptr[2] = (ptr[2] * alpha) / 255;
        }

        /* Directly create a 32-bits DDB (thanks to undocumented CreateDIBitmap flag). */
        alpha = CreateDIBitmap(hdc, NULL, CBM_INIT | 2, bits, info, DIB_RGB_COLORS);

        HeapFree(GetProcessHeap(), 0, info);
    }
    else
    {
        WORD bpp;
        DWORD compr;
        LONG orig_width, orig_height;

        TRACE("Creating alpha bitmap from bitmap info.\n");

        if (!bmi_has_alpha(src_info, color_bits))
            goto done;

        if (!DIB_GetBitmapInfo(&src_info->bmiHeader, &orig_width, &orig_height, &bpp, &compr))
            goto done;
        if (bpp != 32)
            goto done;

        size = get_dib_image_size(orig_width, orig_height, bpp);
        bits = HeapAlloc(GetProcessHeap(), 0, size);
        if (!bits)
            goto done;
        memcpy(bits, color_bits, size);
        /* pre-multiply by alpha */
        for (ptr = (unsigned char*)bits; ptr < ((BYTE*)bits + size); ptr += 4)
        {
            unsigned int alpha = ptr[3];
            ptr[0] = (ptr[0] * alpha) / 255;
            ptr[1] = (ptr[1] * alpha) / 255;
            ptr[2] = (ptr[2] * alpha) / 255;
        }

        /* Create the bitmap. Set the bitmap info to have the right width and height */
        if (src_info->bmiHeader.biSize == sizeof(BITMAPCOREHEADER))
        {
            ((BITMAPCOREHEADER*)&src_info->bmiHeader)->bcWidth = width;
            ((BITMAPCOREHEADER*)&src_info->bmiHeader)->bcHeight = height;
        }
        else
        {
            src_info->bmiHeader.biWidth = width;
            src_info->bmiHeader.biHeight = height;
        }
        /* Directly create a 32-bits DDB (thanks to undocumented CreateDIBitmap flag). */
        alpha = CreateDIBitmap(hdcScreen, NULL, 2, NULL, src_info, DIB_RGB_COLORS);
        /* Restore values */
        if (src_info->bmiHeader.biSize == sizeof(BITMAPCOREHEADER))
        {
            ((BITMAPCOREHEADER*)&src_info->bmiHeader)->bcWidth = orig_width;
            ((BITMAPCOREHEADER*)&src_info->bmiHeader)->bcHeight = orig_height;
        }
        else
        {
            src_info->bmiHeader.biWidth = orig_width;
            src_info->bmiHeader.biHeight = orig_height;
        }
        if (!alpha)
            goto done;
        hbmpOld = (HBITMAP)SelectObject(hdc, alpha);
        if (!hbmpOld)
        {
            DeleteObject(alpha);
            alpha = NULL;
            goto done;
        }
        if (!StretchDIBits(hdc, 0, 0, width, height,
            0, 0, orig_width, orig_height,
            bits, src_info, DIB_RGB_COLORS, SRCCOPY))
        {
            SelectObject(hdc, hbmpOld);
            hbmpOld = NULL;
            DeleteObject(alpha);
            alpha = NULL;
        }
        else
        {
            SelectObject(hdc, hbmpOld);
        }
    }

done:
    DeleteDC(hdcScreen);
    DeleteDC(hdc);
    if (bits) HeapFree(GetProcessHeap(), 0, bits);

    TRACE("Returning 0x%08x.\n", alpha);
    return alpha;
}

static BOOL CURSORICON_GetCursorDataFromBMI(_Inout_ CURSORDATA* pdata,
    _In_ const BITMAPINFO* pbmi
)
{
    pfnmemcpy memcpy = (pfnmemcpy)GetProcAddress(GetModuleHandleA("ntdll"), "memcpy");
    UINT ubmiSize = bitmap_info_size(pbmi, DIB_RGB_COLORS);
    BOOL monochrome = is_dib_monochrome(pbmi);
    LONG width, height;
    WORD bpp;
    DWORD compr;
    int ibmpType;
    HDC hdc, hdcScreen;
    BITMAPINFO* pbmiCopy;
    HBITMAP hbmpOld = NULL;
    BOOL bResult = FALSE;
    const VOID* pvColor, * pvMask;

    ibmpType = DIB_GetBitmapInfo(&pbmi->bmiHeader, &width, &height, &bpp, &compr);
    /* Invalid data */
    if (ibmpType < 0)
        return FALSE;

    /* No compression for icons */
    if (compr != BI_RGB)
        return FALSE;

    /* If no dimensions were set, use the one from the icon */
    if (!pdata->cx) pdata->cx = width;
    if (!pdata->cy) pdata->cy = height < 0 ? -height / 2 : height / 2;

    /* Fix the hotspot coords */
    if (pdata->rt == (USHORT)((ULONG_PTR)RT_CURSOR))
    {
        if (pdata->cx != width)
            pdata->xHotspot = (pdata->xHotspot * pdata->cx) / width;
        if (pdata->cy != height / 2)
            pdata->yHotspot = (pdata->yHotspot * pdata->cy * 2) / height;
    }
    else
    {
        pdata->xHotspot = pdata->cx / 2;
        pdata->yHotspot = pdata->cy / 2;
    }

    hdcScreen = CreateDCW(DISPLAYW, NULL, NULL, NULL);
    if (!hdcScreen)
        return FALSE;
    hdc = CreateCompatibleDC(hdcScreen);
    if (!hdc)
    {
        DeleteDC(hdcScreen);
        return FALSE;
    }

    pbmiCopy = (BITMAPINFO*)HeapAlloc(GetProcessHeap(), 0, max(ubmiSize, FIELD_OFFSET(BITMAPINFO, bmiColors[3])));
    if (!pbmiCopy)
        goto done;
    memcpy(pbmiCopy, pbmi, ubmiSize);

    /* In an icon/cursor, the BITMAPINFO holds twice the height */
    if (pbmiCopy->bmiHeader.biSize == sizeof(BITMAPCOREHEADER))
        ((BITMAPCOREHEADER*)&pbmiCopy->bmiHeader)->bcHeight /= 2;
    else
        pbmiCopy->bmiHeader.biHeight /= 2;
    height /= 2;

    pvColor = (const char*)pbmi + ubmiSize;
    pvMask = (const char*)pvColor +
        get_dib_image_size(width, height, bpp);

    /* Set XOR bits */
    if (monochrome)
    {
        /* Create the 1bpp bitmap which will contain everything */
        pdata->hbmColor = NULL;
        pdata->hbmMask = CreateBitmap(pdata->cx, pdata->cy * 2, 1, 1, NULL);
        if (!pdata->hbmMask)
            goto done;
        hbmpOld = (HBITMAP)SelectObject(hdc, pdata->hbmMask);
        if (!hbmpOld)
            goto done;

        if (!StretchDIBits(hdc, 0, pdata->cy, pdata->cx, pdata->cy,
            0, 0, width, height,
            pvColor, pbmiCopy, DIB_RGB_COLORS, SRCCOPY))
            goto done;
        pdata->bpp = 1;
    }
    else
    {
        /* Create the bitmap. It has to be compatible with the screen surface */
        pdata->hbmColor = CreateCompatibleBitmap(hdcScreen, pdata->cx, pdata->cy);
        if (!pdata->hbmColor)
            goto done;
        /* Create the 1bpp mask bitmap */
        pdata->hbmMask = CreateBitmap(pdata->cx, pdata->cy, 1, 1, NULL);
        if (!pdata->hbmMask)
            goto done;
        hbmpOld = (HBITMAP)SelectObject(hdc, pdata->hbmColor);
        if (!hbmpOld)
            goto done;
        if (!StretchDIBits(hdc, 0, 0, pdata->cx, pdata->cy,
            0, 0, width, height,
            pvColor, pbmiCopy, DIB_RGB_COLORS, SRCCOPY))
            goto done;
        pdata->bpp = GetDeviceCaps(hdcScreen, BITSPIXEL);
        pdata->hbmAlpha = create_alpha_bitmap(NULL, pbmiCopy, pvColor, pdata->cx, pdata->cy);

        /* Now convert the info to monochrome for the mask bits */
        if (pbmiCopy->bmiHeader.biSize != sizeof(BITMAPCOREHEADER))
        {
            RGBQUAD* rgb = pbmiCopy->bmiColors;

            pbmiCopy->bmiHeader.biClrUsed = pbmiCopy->bmiHeader.biClrImportant = 2;
            rgb[0].rgbBlue = rgb[0].rgbGreen = rgb[0].rgbRed = 0x00;
            rgb[1].rgbBlue = rgb[1].rgbGreen = rgb[1].rgbRed = 0xff;
            rgb[0].rgbReserved = rgb[1].rgbReserved = 0;
            pbmiCopy->bmiHeader.biBitCount = 1;
        }
        else
        {
            RGBTRIPLE* rgb = (RGBTRIPLE*)(((BITMAPCOREHEADER*)pbmiCopy) + 1);

            rgb[0].rgbtBlue = rgb[0].rgbtGreen = rgb[0].rgbtRed = 0x00;
            rgb[1].rgbtBlue = rgb[1].rgbtGreen = rgb[1].rgbtRed = 0xff;
            ((BITMAPCOREHEADER*)&pbmiCopy->bmiHeader)->bcBitCount = 1;
        }
    }
    /* Set the mask bits */
    if (!SelectObject(hdc, pdata->hbmMask))
        goto done;
    bResult = StretchDIBits(hdc, 0, 0, pdata->cx, pdata->cy,
        0, 0, width, height,
        pvMask, pbmiCopy, DIB_RGB_COLORS, SRCCOPY) != 0;

done:
    DeleteDC(hdcScreen);
    if (hbmpOld) SelectObject(hdc, hbmpOld);
    DeleteDC(hdc);
    if (pbmiCopy) HeapFree(GetProcessHeap(), 0, pbmiCopy);
    /* Clean up in case of failure */
    if (!bResult)
    {
        if (pdata->hbmMask) DeleteObject(pdata->hbmMask);
        if (pdata->hbmColor) DeleteObject(pdata->hbmColor);
        if (pdata->hbmAlpha) DeleteObject(pdata->hbmAlpha);
    }
    return bResult;
}

static HANDLE CURSORICON_LoadImageW(_In_opt_ HINSTANCE  	hinst,
    _In_ LPCWSTR  	lpszName,
    _In_ int  	cxDesired,
    _In_ int  	cyDesired,
    _In_ UINT  	fuLoad,
    _In_ BOOL  	bIcon
)
{
    HRSRC hrsrc;
    HANDLE handle, hCurIcon = NULL;
    CURSORICONDIR* dir;
    WORD wResId;
    LPBYTE bits;
    CURSORDATA cursorData;
    BOOL bStatus;
    UNICODE_STRING ustrRsrc;
    UNICODE_STRING ustrModule = { 0, 0, NULL };

    typedef BOOLEAN(NTAPI* pfnRtlCreateUnicodeString)(
        IN OUT PUNICODE_STRING  	UniDest,
        IN PCWSTR  	Source
        );

    typedef VOID(NTAPI* pfnRtlInitUnicodeString)(PUNICODE_STRING DestinationString, PCWSTR SourceString);
    typedef void(*__cdecl pfnmemset)(
        _Out_writes_bytes_all_(_Size) void* _Dst,
        _In_                          int    _Val,
        _In_                          size_t _Size
        );

    pfnRtlCreateUnicodeString RtlCreateUnicodeString = (pfnRtlCreateUnicodeString)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlCreateUnicodeString");
    pfnRtlInitUnicodeString RtlInitUnicodeString = (pfnRtlInitUnicodeString)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlInitUnicodeString");
    pfnmemset memset = (pfnmemset)GetProcAddress(GetModuleHandleA("ntdll"), "memset");

    /* Fix width/height */
    if (fuLoad & LR_DEFAULTSIZE)
    {
        if (!cxDesired) cxDesired = GetSystemMetrics(bIcon ? SM_CXICON : SM_CXCURSOR);
        if (!cyDesired) cyDesired = GetSystemMetrics(bIcon ? SM_CYICON : SM_CYCURSOR);
    }

    if (fuLoad & LR_LOADFROMFILE)
    {
        //return CURSORICON_LoadFromFileW(lpszName, cxDesired, cyDesired, fuLoad, bIcon);
    }

    /* Check if caller wants OEM icons */
    //if (!hinst)
    //    hinst = User32Instance;

    if (lpszName)
    {
        /* Prepare the resource name string */
        if (IS_INTRESOURCE(lpszName))
        {
            ustrRsrc.Buffer = (LPWSTR)lpszName;
            ustrRsrc.Length = 0;
            ustrRsrc.MaximumLength = 0;
        }
        else
            RtlInitUnicodeString(&ustrRsrc, lpszName);
    }

    if (hinst)
    {
        //DWORD size = MAX_PATH;
        ///* Get the module name string */
        //while (TRUE)
        //{
        //    DWORD ret;
        //    ustrModule.Buffer = (PWSTR)HeapAlloc(GetProcessHeap(), 0, size * sizeof(WCHAR));
        //    if (!ustrModule.Buffer)
        //    {
        //        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        //        return NULL;
        //    }
        //    ret = GetModuleFileNameW(hinst, ustrModule.Buffer, size);
        //    if (ret == 0)
        //    {
        //        HeapFree(GetProcessHeap(), 0, ustrModule.Buffer);
        //        return NULL;
        //    }

        //    /* This API is completely broken... */
        //    if (ret == size)
        //    {
        //        HeapFree(GetProcessHeap(), 0, ustrModule.Buffer);
        //        size *= 2;
        //        continue;
        //    }

        //    ustrModule.Buffer[ret] = UNICODE_NULL;
        //    ustrModule.Length = ret * sizeof(WCHAR);
        //    ustrModule.MaximumLength = size * sizeof(WCHAR);
        //    break;
        //}
    }

    if (fuLoad & LR_SHARED)
    {
        FINDEXISTINGCURICONPARAM param;

        //TRACE("Checking for an LR_SHARED cursor/icon.\n");
        ///* Ask win32k */
        //param.bIcon = bIcon;
        //param.cx = cxDesired;
        //param.cy = cyDesired;
        //hCurIcon = NtUserFindExistingCursorIcon(&ustrModule, &ustrRsrc, &param);
        //if (hCurIcon)
        //{
        //    /* Woohoo, got it! */
        //    TRACE("MATCH! %p\n", hCurIcon);
        //    HeapFree(GetProcessHeap(), 0, ustrModule.Buffer);
        //    return hCurIcon;
        //}
    }

    /* Find resource ID */
    hrsrc = FindResourceW(
        hinst,
        lpszName,
        bIcon ? RT_GROUP_ICON : RT_GROUP_CURSOR);

    /* We let FindResource, LoadResource, etc. call SetLastError */
    if (!hrsrc)
        goto done;

    handle = LoadResource(hinst, hrsrc);
    if (!handle)
        goto done;

    dir = (CURSORICONDIR*)LockResource(handle);
    if (!dir)
        goto done;

    wResId = LookupIconIdFromDirectoryEx((PBYTE)dir, bIcon, cxDesired, cyDesired, fuLoad);
    FreeResource(handle);

    /* Get the relevant resource pointer */
    hrsrc = FindResourceW(
        hinst,
        MAKEINTRESOURCEW(wResId),
        bIcon ? RT_ICON : RT_CURSOR);
    if (!hrsrc)
        goto done;

    handle = LoadResource(hinst, hrsrc);
    if (!handle)
        goto done;

    bits = (LPBYTE)LockResource(handle);
    if (!bits)
    {
        FreeResource(handle);
        goto done;
    }

    memset(&cursorData, 0, sizeof(cursorData));

    /* This is from resource */
    cursorData.CURSORF_flags = CURSORF_FROMRESOURCE;

    if (dir->idType == 2)
    {
        /* idType == 2 for cursor resources */
        SHORT* ptr = (SHORT*)bits;
        cursorData.xHotspot = ptr[0];
        cursorData.yHotspot = ptr[1];
        bits += 2 * sizeof(SHORT);
    }
    cursorData.cx = cxDesired;
    cursorData.cy = cyDesired;
    cursorData.rt = (USHORT)((ULONG_PTR)(bIcon ? RT_ICON : RT_CURSOR));

    /* Get the bitmaps */
    bStatus = CURSORICON_GetCursorDataFromBMI(
        &cursorData,
        (BITMAPINFO*)bits);

    FreeResource(handle);

    if (!bStatus)
        goto done;

    ///* Create the handle */
    //hCurIcon = NtUserxCreateEmptyCurObject(FALSE);
    //if (!hCurIcon)
    //{
    //    goto end_error;
    //}

    //if (fuLoad & LR_SHARED)
    //{
    //    cursorData.CURSORF_flags |= CURSORF_LRSHARED;
    //}

    ///* Tell win32k */
    //bStatus = NtUserSetCursorIconData(hCurIcon, hinst ? &ustrModule : NULL, lpszName ? &ustrRsrc : NULL, &cursorData);

    //if (!bStatus)
    //{
    //    NtUserDestroyCursor(hCurIcon, TRUE);
    //    goto end_error;
    //}

done:
    if (ustrModule.Buffer)
        HeapFree(GetProcessHeap(), 0, ustrModule.Buffer);
    return hCurIcon;

end_error:
    if (ustrModule.Buffer)
        HeapFree(GetProcessHeap(), 0, ustrModule.Buffer);
    DeleteObject(cursorData.hbmMask);
    if (cursorData.hbmColor) DeleteObject(cursorData.hbmColor);
    if (cursorData.hbmAlpha) DeleteObject(cursorData.hbmAlpha);

    return NULL;
}

HANDLE WINAPI ReactOSLoadImageW(_In_opt_ HINSTANCE  	hinst,
    _In_ LPCWSTR  	lpszName,
    _In_ UINT  	uType,
    _In_ int  	cxDesired,
    _In_ int  	cyDesired,
    _In_ UINT  	fuLoad
) 
{
    /* Redirect to each implementation */
    switch (uType)
    {
    case IMAGE_BITMAP:
        return BITMAP_LoadImageW(hinst, lpszName, cxDesired, cyDesired, fuLoad);
    case IMAGE_CURSOR:
    case IMAGE_ICON:
        return CURSORICON_LoadImageW(hinst, lpszName, cxDesired, cyDesired, fuLoad, uType == IMAGE_ICON);
    default:
        SetLastError(ERROR_INVALID_PARAMETER);
        break;
    }
    return NULL;
}

typedef struct _USER_ACCEL_CACHE_ENTRY
{
    struct _USER_ACCEL_CACHE_ENTRY* Next;
    ULONG_PTR Usage; /* how many times the table has been loaded */
    HACCEL Object;   /* handle to the NtUser accelerator table object */
    HGLOBAL Data;    /* base address of the resource data */
}
U32_ACCEL_CACHE_ENTRY;

typedef struct
{
    BYTE   fVirt;
    BYTE   pad0;
    WORD   key;
    WORD   cmd;
    WORD   pad1;
} PE_ACCEL, * LPPE_ACCEL;

HACCEL WINAPI U32LoadAccelerators(HINSTANCE  	hInstance, HRSRC  	hTableRes)
{
    HGLOBAL hAccTableData;
    HACCEL hAccTable = NULL;
    U32_ACCEL_CACHE_ENTRY* pEntry;
    PE_ACCEL* pAccTableResData;
    SIZE_T i = 0;
    SIZE_T j = 0;
    ACCEL* pAccTableData;

    /* load the accelerator table */
    hAccTableData = LoadResource(hInstance, hTableRes);

    /* failure */
    if (hAccTableData == NULL) return NULL;

    //EnterCriticalSection(&U32AccelCacheLock);

    /* see if this accelerator table has already been loaded */
    //pEntry = *U32AccelCacheFind(NULL, hAccTableData);

    ///* accelerator table already loaded */
    //if (pEntry)
    //{
    //    /* increment the reference count */
    //    ++pEntry->Usage;

    //    /* return the existing object */
    //    hAccTable = pEntry->Object;

    //    /* success */
    //    goto l_Leave;
    //}

    /* determine the number of entries in the table */
    i = SizeofResource(hInstance, hTableRes) / sizeof(PE_ACCEL);

    /* allocate the buffer for the table to be passed to Win32K */
    pAccTableData = (ACCEL*)LocalAlloc(LMEM_FIXED, i * sizeof(ACCEL));

    /* failure */
    if (pAccTableData == NULL) goto l_Leave;

    pAccTableResData = (PE_ACCEL*)hAccTableData;

    /* copy the table */
    for (j = 0; j < i; ++j)
    {
        pAccTableData[j].fVirt = pAccTableResData[j].fVirt;
        pAccTableData[j].key = pAccTableResData[j].key;
        pAccTableData[j].cmd = pAccTableResData[j].cmd;
    }
    pAccTableData[i - 1].fVirt |= 0x80;

    /* create a new accelerator table object */
    //hAccTable = NtUserCreateAcceleratorTable(pAccTableData, i);
    hAccTable = CreateAcceleratorTableW(pAccTableData, i);

    /* free the buffer */
    LocalFree(pAccTableData);

    /* failure */
    if (hAccTable == NULL) goto l_Leave;

    /* success - cache the object */
    //U32AccelCacheAdd(hAccTable, pAccTableResData);

l_Leave:
    //LeaveCriticalSection(&U32AccelCacheLock);
    return hAccTable;
}

HACCEL ReactOSLoadAcceleratorsW
(HINSTANCE  	hInstance,
    LPCWSTR  	lpTableName
)
{
    return U32LoadAccelerators
    (
        hInstance,
        FindResourceExW(hInstance, (LPCWSTR)RT_ACCELERATOR, lpTableName, 0)
    );
}