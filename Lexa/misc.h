#pragma once
#include <Windows.h>
#pragma warning(disable:4996)
#define getNtHdr(buf) ((IMAGE_NT_HEADERS*)((size_t)buf + ((IMAGE_DOS_HEADER *)buf)->e_lfanew ))
#define getSectionArr(buf) ((IMAGE_SECTION_HEADER *)((size_t)buf + ((IMAGE_DOS_HEADER *)buf)->e_lfanew + sizeof(IMAGE_NT_HEADERS)))
unsigned int getExeSizeByLastestSection(char* buf) {
	IMAGE_NT_HEADERS* ntHdr = getNtHdr(buf);
	IMAGE_SECTION_HEADER* sectionHdr = getSectionArr(buf);
	unsigned int currInputExeSize(
		sectionHdr[ntHdr->FileHeader.NumberOfSections - 1].PointerToRawData + \
		sectionHdr[ntHdr->FileHeader.NumberOfSections - 1].SizeOfRawData
	);
	return currInputExeSize;
}


bool readBinFile(const char fileName[], char** bufPtr, DWORD &length) {
	if (FILE* fp = fopen(fileName, "rb")) {
		fseek(fp, 0, SEEK_END);
		length = ftell(fp);
		*bufPtr = new char[length + 1];
		fseek(fp, 0, SEEK_SET);
		fread(*bufPtr, sizeof(char), length, fp);
		return true;
	}
	else return false;
}
bool dumpMappedImgBin(char*buf, BYTE* &mappedImg, size_t* imgSize) {
	PIMAGE_SECTION_HEADER stectionArr = getSectionArr(buf);
	*imgSize = getNtHdr(buf)->OptionalHeader.SizeOfImage; // start with the first section data.
	mappedImg = (BYTE*)VirtualAlloc(0, *imgSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	memset(mappedImg, 0, *imgSize);
	memcpy(mappedImg, buf, getNtHdr(buf)->OptionalHeader.SizeOfHeaders);

	for (size_t i = 0; i < getNtHdr(buf)->FileHeader.NumberOfSections; i++)
		memcpy(mappedImg + stectionArr[i].VirtualAddress, buf + stectionArr[i].PointerToRawData, stectionArr[i].SizeOfRawData);
	return true;
}

deque<PIMAGE_SECTION_HEADER> enumExecSecnHdr(BYTE* fileData)
{
	deque<PIMAGE_SECTION_HEADER> executableScnHdr = deque<PIMAGE_SECTION_HEADER>();
	for (IMAGE_SECTION_HEADER* sectionHdr = getSectionArr(fileData); *sectionHdr->Name; sectionHdr++)
		if (sectionHdr->Characteristics & IMAGE_SCN_MEM_EXECUTE)
			executableScnHdr.push_back(sectionHdr);

	return executableScnHdr;
}