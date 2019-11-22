#pragma once
#include <Windows.h>

typedef struct _BASE_RELOCATION_ENTRY {
	WORD Offset : 12;
	WORD Type : 4;
} BASE_RELOCATION_ENTRY;

#define RELOC_32BIT_FIELD 3

#define getNtHdr(buf) ((IMAGE_NT_HEADERS*)((size_t)buf + ((IMAGE_DOS_HEADER *)buf)->e_lfanew ))
#define getSectionArr(buf) ((IMAGE_SECTION_HEADER *)((size_t)buf + ((IMAGE_DOS_HEADER *)buf)->e_lfanew + sizeof(IMAGE_NT_HEADERS)))

bool applyReloc(ULONGLONG newBase, ULONGLONG oldBase, SIZE_T moduleSize)
{
	PIMAGE_DATA_DIRECTORY relocDir = &getNtHdr(newBase)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	if (relocDir == NULL) /* Cannot relocate - application have no relocation table */
		return false;

	size_t maxSize = relocDir->Size;
	size_t relocAddr = relocDir->VirtualAddress;
	IMAGE_BASE_RELOCATION* reloc = NULL;
	size_t parsedSize = 0;
	for (; parsedSize < maxSize; parsedSize += reloc->SizeOfBlock) {
		reloc = (IMAGE_BASE_RELOCATION*)(relocAddr + parsedSize + size_t(newBase));

		if (reloc->VirtualAddress == NULL || reloc->SizeOfBlock == 0)
			break;

		size_t entriesNum = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(BASE_RELOCATION_ENTRY);
		size_t page = reloc->VirtualAddress;

		BASE_RELOCATION_ENTRY* entry = (BASE_RELOCATION_ENTRY*)(size_t(reloc) + sizeof(IMAGE_BASE_RELOCATION));
		for (size_t i = 0; i < entriesNum; i++, entry++) {
			size_t offset = entry->Offset;
			size_t type = entry->Type;
			size_t reloc_field = page + offset;
			if (entry == NULL || type == 0)
				break;
			if (type != RELOC_32BIT_FIELD) {
				printf("    [!] Not supported relocations format at %d: %d\n", (int)i, (int)type);
				return false;
			}
			if (reloc_field >= moduleSize) {
				printf("    [-] Out of Bound Field: %lx\n", reloc_field);
				return false;
			}

			size_t* relocateAddr = (size_t*)(size_t(newBase) + reloc_field);
			//printf("    [V] Apply Reloc Field at %x\n", relocateAddr);
			(*relocateAddr) = ((*relocateAddr) - oldBase + newBase);
		}
	}
	return (parsedSize != 0);
}


deque<size_t> getRelocFieldArr(ULONGLONG modulePtr, SIZE_T moduleSize)
{
	deque<size_t> ret = deque<size_t>();
	PIMAGE_DATA_DIRECTORY relocDir = &getNtHdr(modulePtr)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	if (relocDir == NULL) return ret;

	size_t maxSize = relocDir->Size;
	size_t relocAddr = relocDir->VirtualAddress;
	IMAGE_BASE_RELOCATION* reloc = NULL;
	size_t parsedSize = 0;
	for (; parsedSize < maxSize; parsedSize += reloc->SizeOfBlock) {
		reloc = (IMAGE_BASE_RELOCATION*)(relocAddr + parsedSize + size_t(modulePtr));

		if (reloc->VirtualAddress == NULL || reloc->SizeOfBlock == 0)
			break;

		size_t entriesNum = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(BASE_RELOCATION_ENTRY);
		size_t page = reloc->VirtualAddress;

		BASE_RELOCATION_ENTRY* entry = (BASE_RELOCATION_ENTRY*)(size_t(reloc) + sizeof(IMAGE_BASE_RELOCATION));
		for (size_t i = 0; i < entriesNum; i++, entry++) {
			size_t reloc_field = page + entry->Offset;
			if (entry == NULL || entry->Type == 0) break;
			if (entry->Type != RELOC_32BIT_FIELD) return ret;
			if (reloc_field >= moduleSize) return ret;
			size_t relocateAddr = (size_t(modulePtr) + reloc_field);
			ret.push_back(relocateAddr);
		}
	}
	return ret;
}
