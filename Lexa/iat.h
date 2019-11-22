#pragma once
#include <map>
#include <Windows.h>
using namespace std;
#define getNtHdr(buf) ((IMAGE_NT_HEADERS*)((size_t)buf + ((IMAGE_DOS_HEADER *)buf)->e_lfanew ))
#define getSectionArr(buf) ((IMAGE_SECTION_HEADER *)((size_t)buf + ((IMAGE_DOS_HEADER *)buf)->e_lfanew + sizeof(IMAGE_NT_HEADERS)))

map< DWORD, string> getIAT_callVia(size_t modulePtr) {
	map<DWORD, string> impThunkVaArr = map< DWORD, string>();
	PIMAGE_IMPORT_DESCRIPTOR impLib = (PIMAGE_IMPORT_DESCRIPTOR)(modulePtr + getNtHdr(modulePtr)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	size_t libCount = getNtHdr(modulePtr)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);

	// enumerate modules
	for (;(libCount-- > 0) && impLib->Name; impLib++) {
		char* impLibName = (char *)(modulePtr + impLib->Name);

		// enumerate thunk
		for (PIMAGE_THUNK_DATA callVia = (PIMAGE_THUNK_DATA)(modulePtr + impLib->FirstThunk); callVia->u1.ForwarderString; callVia++) {
			pair<DWORD, string> newRecord = pair<DWORD, string>((size_t)callVia - (size_t)modulePtr, impLibName);
			impThunkVaArr.insert(newRecord);
		}
	}
	return impThunkVaArr;
}	
