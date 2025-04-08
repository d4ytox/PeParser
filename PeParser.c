#include "PeParser.h"

#include <assert.h>
#include <stdio.h>
#include <windows.h>

void PeParserResetMembers(T_PE_PARSER* pPeParser)
{
	pPeParser->szLoadedFileName[0] = 0;
	pPeParser->pRawData = NULL;
	pPeParser->sRawDataSize = 0;
	pPeParser->pImageDosHeader = NULL;
	pPeParser->pImageNtHeaders = NULL;
	pPeParser->pImageFileHeader = NULL;
	pPeParser->pImageOptionalHeader = NULL;
	pPeParser->pImageSectionHeader = NULL;
	pPeParser->pImageExportDirectory = NULL;
	pPeParser->pImageImportDirectory = NULL;
	pPeParser->pImageResourceDirectory = NULL;
	pPeParser->pImageExceptionDirectory = NULL;
	pPeParser->pBaseRelocationTable = NULL;
	pPeParser->pTLSDirectory = NULL;
	pPeParser->pImportAddressTable = NULL;
}

BOOL PeParserInitialize(T_PE_PARSER* pPeParser)
{
	assert(pPeParser != NULL);

	PeParserResetMembers(pPeParser);
	return TRUE;
}

BOOL PeParserHasLoaded(T_PE_PARSER* pPeParser)
{
	assert(pPeParser != NULL);

	return pPeParser->pRawData != NULL
		&& pPeParser->sRawDataSize != 0
		&& pPeParser->pImageDosHeader != NULL
		&& pPeParser->pImageNtHeaders != NULL
		&& pPeParser->pImageFileHeader != NULL
		&& pPeParser->pImageOptionalHeader != NULL;
}

BOOL PeParserUnload(T_PE_PARSER* pPeParser)
{
	assert(pPeParser != NULL);

	if (!PeParserHasLoaded(pPeParser))
	{
		printf("\t[!] No PE Currently Loaded. \n");
		return FALSE;
	}
	PeParserClean(pPeParser);
	printf("[i] PE Unloaded.\n");
	return TRUE;
}

BOOL PeParserLoadFileBuffer(T_PE_PARSER* pPeParser, LPCWSTR lpFileName)
{
	assert(lpFileName != NULL);

	BOOLEAN bResult = TRUE;
	HANDLE hFile = INVALID_HANDLE_VALUE;
	DWORD dwNumberOfBytesRead = 0;

	hFile = CreateFileW(lpFileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("[!] CreateFileA Failed with Error: %d\n", GetLastError());
		bResult = FALSE;
		goto _End;
	}

	pPeParser->sRawDataSize = GetFileSize(hFile, NULL);
	if (pPeParser->sRawDataSize == 0)
	{
		printf("[!] GetFileSize Failed with Error: %d\n", GetLastError());
		bResult = FALSE;
		goto _End;
	}

	pPeParser->pRawData = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, pPeParser->sRawDataSize);
	if (pPeParser->pRawData == NULL)
	{
		printf("[!] HeapAlloc Failed with Error: %d\n", GetLastError());
		bResult = FALSE;
		goto _End;
	}

	if (!ReadFile(hFile, pPeParser->pRawData, pPeParser->sRawDataSize, &dwNumberOfBytesRead, NULL) || pPeParser->sRawDataSize != dwNumberOfBytesRead)
	{
		printf("[!] ReadFile Failed with Error: %d\n", GetLastError());
		printf("[!] Bytes Read : %d of : %d \n", dwNumberOfBytesRead, pPeParser->sRawDataSize);
		HeapFree(GetProcessHeap(), 0, pPeParser->pRawData);
		bResult = FALSE;
		goto _End;
	}

_End:
	if (hFile)
		CloseHandle(hFile);
	if (!bResult)
	{
		pPeParser->pRawData = NULL;
		pPeParser->sRawDataSize = 0;
	}
	return bResult;
}

BOOL PeParserLoadDosHeader(T_PE_PARSER* pPeParser)
{
	assert(pPeParser != NULL && pPeParser->pRawData != NULL);

	pPeParser->pImageDosHeader = (PIMAGE_DOS_HEADER)pPeParser->pRawData;
	if (pPeParser->pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		printf("[!] Invalid DOS Header.\n");
		PeParserClean(pPeParser);
		return FALSE;
	}
	return TRUE;
}

BOOL PeParserLoadNtHeaders(T_PE_PARSER* pPeParser)
{
	assert(pPeParser != NULL && pPeParser->pRawData != NULL && pPeParser->pImageDosHeader != NULL);

	pPeParser->pImageNtHeaders = (PIMAGE_NT_HEADERS)(pPeParser->pRawData + pPeParser->pImageDosHeader->e_lfanew);
	if (pPeParser->pImageNtHeaders->Signature != IMAGE_NT_SIGNATURE)
	{
		printf("[!] Invalid NT Header.\n");
		PeParserClean(pPeParser);
		return FALSE;
	}
	return TRUE;
}

BOOL PeParserLoadFileHeader(T_PE_PARSER* pPeParser)
{
	assert(pPeParser != NULL && pPeParser->pImageNtHeaders != NULL);

	pPeParser->pImageFileHeader = &pPeParser->pImageNtHeaders->FileHeader;
	return TRUE;
}

BOOL PeParserLoadOptionalHeader(T_PE_PARSER* pPeParser)
{
	assert(pPeParser != NULL && pPeParser->pImageNtHeaders != NULL);

	pPeParser->pImageOptionalHeader = &pPeParser->pImageNtHeaders->OptionalHeader;
	if (pPeParser->pImageOptionalHeader->Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC)
	{
		printf("[!] Invalid Optional Header.\n");
		return FALSE;
	}
	return TRUE;
}

BOOL PeParserLoadSectionHeader(T_PE_PARSER* pPeParser)
{
	assert(pPeParser != NULL && pPeParser->pImageNtHeaders != NULL);

	pPeParser->pImageSectionHeader = (PIMAGE_SECTION_HEADER)(((PBYTE)pPeParser->pImageNtHeaders) + sizeof(IMAGE_NT_HEADERS));
	return TRUE;
}

BOOL PeParserLoadExportDirectory(T_PE_PARSER* pPeParser)
{
	assert(pPeParser != NULL && pPeParser->pRawData != NULL && pPeParser->pImageOptionalHeader != NULL);

	pPeParser->pImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(pPeParser->pRawData + pPeParser->pImageOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	return TRUE;
}

BOOL PeParserLoadImportDirectory(T_PE_PARSER* pPeParser)
{
	assert(pPeParser != NULL && pPeParser->pRawData != NULL && pPeParser->pImageOptionalHeader != NULL);

	pPeParser->pImageImportDirectory = (PVOID)(pPeParser->pRawData + pPeParser->pImageOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	return TRUE;
}

BOOL PeParserLoadResourceDirectory(T_PE_PARSER* pPeParser)
{
	assert(pPeParser != NULL && pPeParser->pRawData != NULL && pPeParser->pImageOptionalHeader != NULL);

	pPeParser->pImageResourceDirectory = (PVOID)(pPeParser->pRawData + pPeParser->pImageOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress);
	return TRUE;
}

BOOL PeParserLoadExceptionDirectory(T_PE_PARSER* pPeParser)
{
	assert(pPeParser != NULL && pPeParser->pRawData != NULL && pPeParser->pImageOptionalHeader != NULL);

	pPeParser->pImageExceptionDirectory = (PVOID)(pPeParser->pRawData + pPeParser->pImageOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress);
	return TRUE;
}

BOOL PeParserLoadBaseRelocationTable(T_PE_PARSER* pPeParser)
{
	assert(pPeParser != NULL && pPeParser->pRawData != NULL && pPeParser->pImageOptionalHeader != NULL);

	pPeParser->pBaseRelocationTable = (PVOID)(pPeParser->pRawData + pPeParser->pImageOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	return TRUE;
}

BOOL PeParserLoadTLSDirectory(T_PE_PARSER* pPeParser)
{
	assert(pPeParser != NULL && pPeParser->pRawData != NULL && pPeParser->pImageOptionalHeader != NULL);

	pPeParser->pTLSDirectory = (PVOID)(pPeParser->pRawData + pPeParser->pImageOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
	return TRUE;
}

BOOL PeParserLoadImportAddressTable(T_PE_PARSER* pPeParser)
{
	assert(pPeParser != NULL && pPeParser->pRawData != NULL && pPeParser->pImageOptionalHeader != NULL);

	pPeParser->pImportAddressTable = (PVOID)(pPeParser->pRawData + pPeParser->pImageOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress);
	return TRUE;
}

BOOL PeParserLoadAll(T_PE_PARSER* pPeParser)
{
	assert(pPeParser != NULL);

	return PeParserLoadDosHeader(pPeParser)
		&& PeParserLoadNtHeaders(pPeParser)
		&& PeParserLoadFileHeader(pPeParser)
		&& PeParserLoadOptionalHeader(pPeParser)
		&& PeParserLoadSectionHeader(pPeParser)
		&& PeParserLoadExportDirectory(pPeParser)
		&& PeParserLoadImportDirectory(pPeParser)
		&& PeParserLoadResourceDirectory(pPeParser)
		&& PeParserLoadExceptionDirectory(pPeParser)
		&& PeParserLoadBaseRelocationTable(pPeParser)
		&& PeParserLoadTLSDirectory(pPeParser)
		&& PeParserLoadImportAddressTable(pPeParser);
}

BOOL PeParserLoadFile(T_PE_PARSER* pPeParser, LPCWSTR lpFileName)
{
	assert(pPeParser != NULL);
	
	printf("[i] Loading PE File \"%S\":\n", lpFileName);
	if (PeParserHasLoaded(pPeParser))
		PeParserUnload(pPeParser);
	if (!PeParserLoadFileBuffer(pPeParser, lpFileName))
		return FALSE;
	if (!PeParserLoadAll(pPeParser))
		return FALSE;
	lstrcpyW(pPeParser->szLoadedFileName, lpFileName);
	printf("[i] File \"%S\" Loaded. \n", pPeParser->szLoadedFileName);
	return TRUE;
}

BOOL PeParserUnloadFile(T_PE_PARSER* pPeParser)
{
	assert(pPeParser != NULL);

	printf("[i] Unloading PE File \"%S\":\n", pPeParser->szLoadedFileName);
	return PeParserUnload(pPeParser);
}

BOOL PeParserHasLoadedFile(T_PE_PARSER* pPeParser)
{
	assert(pPeParser != NULL);

	return pPeParser->szLoadedFileName[0] != 0
		&& PeParserHasLoaded(pPeParser);
}

BOOL PeParserLoadModule(T_PE_PARSER* pPeParser, HANDLE hModule)
{
	assert(pPeParser != NULL);

	printf("[i] Loading PE Module:\n");
	if (PeParserHasLoaded(pPeParser))
		PeParserUnload(pPeParser);
	pPeParser->pRawData = (PBYTE)hModule;
	pPeParser->sRawDataSize = 1; // TODO: Calc the size of hMdodule
	if (!PeParserLoadAll(pPeParser))
		return FALSE;
	printf("[i] PE Module Loaded. \n");
	return TRUE;
}

BOOL PeParserUnloadModule(T_PE_PARSER* pPeParser)
{
	assert(pPeParser != NULL);

	printf("[i] Unloading PE Module:\n");
	return PeParserUnload(pPeParser);
}

BOOL PeParserHasLoadedModule(T_PE_PARSER* pPeParser)
{
	assert(pPeParser != NULL);

	return pPeParser->szLoadedFileName[0] == 0
		&& PeParserHasLoaded(pPeParser);
}

PDWORD PeParserGetExportDirectoryFunctionNameArray(T_PE_PARSER* pPeParser)
{
	assert(pPeParser != NULL && pPeParser->pRawData != NULL && pPeParser->pImageExportDirectory != NULL);

	return (PDWORD)(pPeParser->pRawData + pPeParser->pImageExportDirectory->AddressOfNames);
}

PDWORD PeParserGetExportDirectoryFunctionAddressArray(T_PE_PARSER* pPeParser)
{
	assert(pPeParser != NULL && pPeParser->pRawData != NULL && pPeParser->pImageExportDirectory != NULL);

	return (PDWORD)(pPeParser->pRawData + pPeParser->pImageExportDirectory->AddressOfFunctions);
}

PWORD PeParserGetExportDirectoryFunctionOrdinalArray(T_PE_PARSER* pPeParser)
{
	assert(pPeParser != NULL && pPeParser->pRawData != NULL && pPeParser->pImageExportDirectory != NULL);

	return (PWORD)(pPeParser->pRawData + pPeParser->pImageExportDirectory->AddressOfNameOrdinals);
}

BOOL PeParserPrintFileHeader(T_PE_PARSER* pPeParser)
{
	assert(pPeParser != NULL);

	if (!PeParserHasLoaded(pPeParser))
	{
		printf("\t[!] No PE Currently Loaded. \n");
		return FALSE;
	}

	printf("\n[i] Printing \"%S\" PE File Header:\n", pPeParser->szLoadedFileName);

	if (pPeParser->pImageFileHeader->Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE)
	{

		printf("\t[i] PE File Detected As : ");

		if (pPeParser->pImageFileHeader->Characteristics & IMAGE_FILE_DLL)
			printf("DLL\n");
		else if (pPeParser->pImageFileHeader->Characteristics & IMAGE_SUBSYSTEM_NATIVE)
			printf("SYS\n");
		else
			printf("EXE\n");
	}

	printf("\t[i] File Arch : %s \n", pPeParser->pImageFileHeader->Machine == IMAGE_FILE_MACHINE_I386 ? "x32" : "x64");
	printf("\t[i] Number Of Sections : %d \n", pPeParser->pImageFileHeader->NumberOfSections);
	printf("\t[i] Size Of The Optional Header : %d Byte \n", pPeParser->pImageFileHeader->SizeOfOptionalHeader);
	return TRUE;
}

BOOL PeParserPrintOptionalHeader(T_PE_PARSER* pPeParser)
{
	assert(pPeParser != NULL);

	if (!PeParserHasLoaded(pPeParser))
	{
		printf("\t[!] No PE Currently Loaded. \n");
		return FALSE;
	}

	printf("\n[i] Printing \"%S\" PE Optional Header:\n", pPeParser->szLoadedFileName);

	printf("\t[i] File Arch (Alternate) : %s \n", pPeParser->pImageOptionalHeader->Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC ? "x32" : "x64");

	printf("\t[+] Size Of Code Section : %d \n", pPeParser->pImageOptionalHeader->SizeOfCode);
	printf("\t[+] Address Of Code Section : 0x%p \n\t\t[RVA : 0x%0.8X]\n", (PVOID)(pPeParser->pRawData + pPeParser->pImageOptionalHeader->BaseOfCode), pPeParser->pImageOptionalHeader->BaseOfCode);
	printf("\t[+] Size Of Initialized Data : %d \n", pPeParser->pImageOptionalHeader->SizeOfInitializedData);
	printf("\t[+] Size Of Unitialized Data : %d \n", pPeParser->pImageOptionalHeader->SizeOfUninitializedData);
	printf("\t[+] Preferable Mapping Address : 0x%p \n", (PVOID)pPeParser->pImageOptionalHeader->ImageBase);
	printf("\t[+] Required Version : %d.%d \n", pPeParser->pImageOptionalHeader->MajorOperatingSystemVersion, pPeParser->pImageOptionalHeader->MinorOperatingSystemVersion);
	printf("\t[+] Address Of The Entry Point : 0x%p \n\t\t[RVA : 0x%0.8X]\n", (PVOID)(pPeParser->pRawData + pPeParser->pImageOptionalHeader->AddressOfEntryPoint), pPeParser->pImageOptionalHeader->AddressOfEntryPoint);
	printf("\t[+] Size Of The Image : %d \n", pPeParser->pImageOptionalHeader->SizeOfImage);
	printf("\t[+] File CheckSum : 0x%0.8X \n", pPeParser->pImageOptionalHeader->CheckSum);
	printf("\t[+] Number of entries in the DataDirectory array : %d \n", pPeParser->pImageOptionalHeader->NumberOfRvaAndSizes); // this is the same as `IMAGE_NUMBEROF_DIRECTORY_ENTRIES` - `16`

	printf("\n[i] Printing \"%S\" PE Directories:\n", pPeParser->szLoadedFileName);

	printf("\t[*] Export Directory At 0x%p Of Size : %d \n\t\t[RVA : 0x%0.8X]\n",
		(PVOID)(pPeParser->pImageExportDirectory),
		pPeParser->pImageOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size,
		pPeParser->pImageOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	printf("\t[*] Import Directory At 0x%p Of Size : %d \n\t\t[RVA : 0x%0.8X]\n",
		pPeParser->pImageImportDirectory,
		pPeParser->pImageOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size,
		pPeParser->pImageOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	printf("\t[*] Resource Directory At 0x%p Of Size : %d \n\t\t[RVA : 0x%0.8X]\n",
		pPeParser->pImageResourceDirectory,
		pPeParser->pImageOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size,
		pPeParser->pImageOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress);

	printf("\t[*] Exception Directory At 0x%p Of Size : %d \n\t\t[RVA : 0x%0.8X]\n",
		pPeParser->pImageExceptionDirectory,
		pPeParser->pImageOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size,
		pPeParser->pImageOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress);

	printf("\t[*] Base Relocation Table At 0x%p Of Size : %d \n\t\t[RVA : 0x%0.8X]\n",
		pPeParser->pBaseRelocationTable,
		pPeParser->pImageOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size,
		pPeParser->pImageOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

	printf("\t[*] TLS Directory At 0x%p Of Size : %d \n\t\t[RVA : 0x%0.8X]\n",
		pPeParser->pTLSDirectory,
		pPeParser->pImageOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size,
		pPeParser->pImageOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);

	printf("\t[*] Import Address Table At 0x%p Of Size : %d \n\t\t[RVA : 0x%0.8X]\n",
		pPeParser->pImportAddressTable,
		pPeParser->pImageOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size,
		pPeParser->pImageOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress);
	return TRUE;
}

BOOL PeParserPrintSections(T_PE_PARSER* pPeParser)
{
	assert(pPeParser != NULL);

	if (!PeParserHasLoaded(pPeParser))
	{
		printf("\t[!] No PE Currently Loaded. \n");
		return FALSE;
	}

	printf("\n[i] Printing \"%S\" PE Sections:\n", pPeParser->szLoadedFileName);

	PIMAGE_SECTION_HEADER* ppImgSectionHdr = &pPeParser->pImageSectionHeader;

	for (size_t i = 0; i < pPeParser->pImageNtHeaders->FileHeader.NumberOfSections; i++)
	{
		printf("[#] %s \n", (CHAR*)pPeParser->pImageSectionHeader->Name);
		printf("\tSize : %d \n", pPeParser->pImageSectionHeader->SizeOfRawData);
		printf("\tRVA : 0x%0.8X \n", pPeParser->pImageSectionHeader->VirtualAddress);
		printf("\tAddress : 0x%p \n", (PVOID)(pPeParser->pRawData + pPeParser->pImageSectionHeader->VirtualAddress));
		printf("\tRelocations : %d \n", pPeParser->pImageSectionHeader->NumberOfRelocations);
		printf("\tPermissions : ");
		if (pPeParser->pImageSectionHeader->Characteristics & IMAGE_SCN_MEM_READ)
			printf("PAGE_READONLY | ");
		if (pPeParser->pImageSectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE && pPeParser->pImageSectionHeader->Characteristics & IMAGE_SCN_MEM_READ)
			printf("PAGE_READWRITE | ");
		if (pPeParser->pImageSectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE)
			printf("PAGE_EXECUTE | ");
		if (pPeParser->pImageSectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE && pPeParser->pImageSectionHeader->Characteristics & IMAGE_SCN_MEM_READ)
			printf("PAGE_EXECUTE_READWRITE");
		printf("\n\n");

		*ppImgSectionHdr = (PIMAGE_SECTION_HEADER)((PBYTE)*ppImgSectionHdr + (DWORD)sizeof(IMAGE_SECTION_HEADER));
	}
	return TRUE;
}

BOOL PeParserPrintAll(T_PE_PARSER *pPeParser)
{
	assert(pPeParser != NULL);

	if (!PeParserHasLoaded(pPeParser))
	{
		printf("\t[!] No PE Currently Loaded. \n");
		return FALSE;
	}

	PeParserPrintFileHeader(pPeParser);

	PeParserPrintOptionalHeader(pPeParser);

	PeParserPrintSections(pPeParser);

	return TRUE;
}

BOOL PeParserClean(T_PE_PARSER *pPeParser)
{
	assert(pPeParser != NULL);

	if (pPeParser->pRawData)
	{
		if (PeParserHasLoadedFile(pPeParser)) // Only free when the file buffer was loaded
			HeapFree(GetProcessHeap(), 0, pPeParser->pRawData);
		pPeParser->pRawData = NULL;
	}
	PeParserResetMembers(pPeParser);
	return TRUE;
}