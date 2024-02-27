#include <ntddk.h>
#include "pefile.h"
#include "common.h"

inline PIMAGE_NT_HEADERS get_nt_hdr(UCHAR* rawPE)
{
	IMAGE_DOS_HEADER* DOSHeader = PIMAGE_DOS_HEADER(rawPE);
	if (DOSHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		DbgPrint(DRIVER_PREFIX " Couldn't get DOS hdr %c%c : %X", rawPE[0], rawPE[1], DOSHeader->e_magic);
		return NULL;
	}
	PIMAGE_NT_HEADERS nt = PIMAGE_NT_HEADERS((char*)(rawPE)+DOSHeader->e_lfanew);
	if (nt->Signature != IMAGE_NT_SIGNATURE) {
		DbgPrint(DRIVER_PREFIX " Couldn't get NtHdr: %X\n", nt->Signature);
		return NULL;
	}
	return nt;
}

inline void map_sections(void* image, void* rawPE, IMAGE_NT_HEADERS *nt)
{
	if (!image || !rawPE || !nt) return;

	memcpy(image, rawPE, nt->OptionalHeader.SizeOfHeaders);

	// map sections
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
	for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
		memcpy((BYTE*)(image)+section[i].VirtualAddress, (BYTE*)(rawPE)+section[i].PointerToRawData, section[i].SizeOfRawData);
	}
}

inline bool relocate(void* image, PIMAGE_NT_HEADERS nt, void* newImgBase)
{
    IMAGE_DATA_DIRECTORY relocationsDirectory = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (relocationsDirectory.VirtualAddress == 0) {
        return false;
    }
    PIMAGE_BASE_RELOCATION ProcessBReloc = (PIMAGE_BASE_RELOCATION)(relocationsDirectory.VirtualAddress + (FIELD_PTR)image);
    // apply relocations:
    while (ProcessBReloc->VirtualAddress != 0)
    {
        DWORD page = ProcessBReloc->VirtualAddress;
        DbgPrint(DRIVER_PREFIX " page: %X\n", page);

        if (ProcessBReloc->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION))
        {
            size_t count = (ProcessBReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            BASE_RELOCATION_ENTRY* list = (BASE_RELOCATION_ENTRY*)(WORD*)(ProcessBReloc + 1);

            DbgPrint(DRIVER_PREFIX " Count: %ld\n", count);

            for (size_t i = 0; i < count; i++) {
                if (list[i].Type & RELOC_FIELD) {
                    DWORD rva = list[i].Offset + page;
#ifdef _DEBUG
                    DbgPrint(DRIVER_PREFIX " RVA: %X\n", rva);
#endif
                    PULONG_PTR p = (PULONG_PTR)((BYTE*)image + rva);
                    //relocate the address
                    *p = ((*p) - nt->OptionalHeader.ImageBase) + (FIELD_PTR)newImgBase;
                }
            }
        }
        ProcessBReloc = (PIMAGE_BASE_RELOCATION)((BYTE*)ProcessBReloc + ProcessBReloc->SizeOfBlock);
    }
    return true;
}

inline bool load_imports(void* image, PIMAGE_NT_HEADERS nt, PVOID(*load_lib_callback)(LPCSTR lib_name), PVOID(*get_proc)(void* library, const void* name_or_ord))
{
    IMAGE_DATA_DIRECTORY importsDirectory = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importsDirectory.VirtualAddress == 0) {
        return false;
    }

    PIMAGE_IMPORT_DESCRIPTOR importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(importsDirectory.VirtualAddress + (FIELD_PTR)image);
    while (importDescriptor->Name != NULL)
    {
        LPCSTR libraryName = (LPCSTR)importDescriptor->Name + (FIELD_PTR)image;
        void* library = load_lib_callback(libraryName);
        DbgPrint(DRIVER_PREFIX " libraryName: %s Loaded: %p", libraryName, library);
        if (!library) return false;
        
        PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((FIELD_PTR)image + importDescriptor->FirstThunk);
        while (thunk->u1.AddressOfData != NULL)
        {
            FIELD_PTR functionAddress = NULL;
            if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal))
            {
                LPCSTR functionOrdinal = (LPCSTR)IMAGE_ORDINAL(thunk->u1.Ordinal);
                DbgPrint(DRIVER_PREFIX " functionOrdinal: %p\n", functionOrdinal);
                functionAddress = 0;// (FIELD_PTR)GetProcAddress(library, functionOrdinal);
            }
            else
            {
                PIMAGE_IMPORT_BY_NAME functionName = (PIMAGE_IMPORT_BY_NAME)((FIELD_PTR)image + thunk->u1.AddressOfData);
                functionAddress = (FIELD_PTR)get_proc(library, functionName->Name);
                DbgPrint(DRIVER_PREFIX " functionName: %s Addr: %p\n", functionName->Name, functionAddress);
            }
            if (!functionAddress) return false;

            thunk->u1.Function = functionAddress;
            ++thunk;
        }
        importDescriptor++;
    }
    return true;
}

inline void* get_func_by_name(void* module, const void* func)
{
    if (!module || !func) {
        return NULL;
    }
    IMAGE_DOS_HEADER* idh = (IMAGE_DOS_HEADER*)module;
    if (idh->e_magic != IMAGE_DOS_SIGNATURE) {
        return NULL;
    }
    IMAGE_NT_HEADERS* nt_headers = (IMAGE_NT_HEADERS*)((BYTE*)module + idh->e_lfanew);
    IMAGE_DATA_DIRECTORY* exportsDir = &(nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
    if (exportsDir->VirtualAddress == NULL) {
        return NULL;
    }

    DWORD expAddr = exportsDir->VirtualAddress;
    IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(expAddr + (ULONG_PTR)module);
    SIZE_T namesCount = exp->NumberOfNames;

    DWORD funcsListRVA = exp->AddressOfFunctions;
    DWORD funcNamesListRVA = exp->AddressOfNames;
    DWORD namesOrdsListRVA = exp->AddressOfNameOrdinals;

    //go through names:
    for (SIZE_T i = 0; i < namesCount; i++) {
        DWORD* nameRVA = (DWORD*)(funcNamesListRVA + (BYTE*)module + i * sizeof(DWORD));
        WORD* nameIndex = (WORD*)(namesOrdsListRVA + (BYTE*)module + i * sizeof(WORD));
        DWORD* funcRVA = (DWORD*)(funcsListRVA + (BYTE*)module + (*nameIndex) * sizeof(DWORD));
        LPSTR func_name = (LPSTR)func;
        LPSTR curr_name = (LPSTR)(*nameRVA + (BYTE*)module);
        size_t k = 0;
        for (k = 0; func_name[k] != 0 && curr_name[k] != 0; k++) {
            if (func_name[k] != curr_name[k]) break;
        }
        if (func_name[k] == 0 && curr_name[k] == 0) {
            //found
            return (BYTE*)module + (*funcRVA);
        }
    }
    return NULL;
}
