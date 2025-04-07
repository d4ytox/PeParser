#include "PeParser.h"

#include <assert.h>
#include <stdio.h>
#include <windows.h>

BOOL PeParserInitialize(T_PE_PARSER *pPeParser)
{
	assert(pPeParser != NULL);

	pPeParser->pBase = NULL;
	pPeParser->sSize = 0;
	pPeParser->pImgDosHdr = NULL;
	pPeParser->pImgNtHdrs = NULL;
	pPeParser->pImgFileHdr = NULL;
	pPeParser->pImgOptHdr = NULL;
	pPeParser->pImgSectionHdr = NULL;
	pPeParser->pImgExportDir = NULL;
	return TRUE;
}

BOOL PeParserHasLoaded(T_PE_PARSER* pPeParser)
{
	assert(pPeParser != NULL);

	return pPeParser->pBase != NULL
		&& pPeParser->sSize != 0
		&& pPeParser->pImgDosHdr != NULL
		&& pPeParser->pImgNtHdrs != NULL
		&& pPeParser->pImgFileHdr != NULL
		&& pPeParser->pImgOptHdr != NULL;
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

	pPeParser->sSize = GetFileSize(hFile, NULL);
	if (pPeParser->sSize == 0)
	{
		printf("[!] GetFileSize Failed with Error: %d\n", GetLastError());
		bResult = FALSE;
		goto _End;
	}

	pPeParser->pBase = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, pPeParser->sSize);
	if (pPeParser->pBase == NULL)
	{
		printf("[!] HeapAlloc Failed with Error: %d\n", GetLastError());
		bResult = FALSE;
		goto _End;
	}

	if (!ReadFile(hFile, pPeParser->pBase, pPeParser->sSize, &dwNumberOfBytesRead, NULL) || pPeParser->sSize != dwNumberOfBytesRead)
	{
		printf("[!] ReadFile Failed with Error: %d\n", GetLastError());
		printf("[!] Bytes Read : %d of : %d \n", dwNumberOfBytesRead, pPeParser->sSize);
		HeapFree(GetProcessHeap(), 0, pPeParser->pBase);
		bResult = FALSE;
		goto _End;
	}

_End:
	if (hFile)
		CloseHandle(hFile);
	if (!bResult)
	{
		pPeParser->pBase = NULL;
		pPeParser->sSize = 0;
	}
	return bResult;
}

BOOL PeParserLoadDosHeader(T_PE_PARSER* pPeParser)
{
	assert(pPeParser != NULL && pPeParser->pBase != NULL);

	pPeParser->pImgDosHdr = (PIMAGE_DOS_HEADER)pPeParser->pBase;
	if (pPeParser->pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
	{
		printf("[!] Invalid DOS Header.\n");
		PeParserClean(pPeParser);
		return FALSE;
	}
	return TRUE;
}

BOOL PeParserLoadNtHeaders(T_PE_PARSER* pPeParser)
{
	assert(pPeParser != NULL && pPeParser->pBase != NULL && pPeParser->pImgDosHdr != NULL);

	pPeParser->pImgNtHdrs = (PIMAGE_NT_HEADERS)(pPeParser->pBase + pPeParser->pImgDosHdr->e_lfanew);
	if (pPeParser->pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
	{
		printf("[!] Invalid NT Header.\n");
		PeParserClean(pPeParser);
		return FALSE;
	}
	return TRUE;
}

BOOL PeParserLoadFileHeader(T_PE_PARSER* pPeParser)
{
	assert(pPeParser != NULL && pPeParser->pImgNtHdrs != NULL);

	pPeParser->pImgFileHdr = &pPeParser->pImgNtHdrs->FileHeader;
	return TRUE;
}

BOOL PeParserLoadOptionalHeader(T_PE_PARSER* pPeParser)
{
	assert(pPeParser != NULL && pPeParser->pImgNtHdrs != NULL);

	pPeParser->pImgOptHdr = &pPeParser->pImgNtHdrs->OptionalHeader;
	if (pPeParser->pImgOptHdr->Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC)
	{
		printf("[!] Invalid Optional Header.\n");
		return FALSE;
	}
	return TRUE;
}

BOOL PeParserLoadSectionHeader(T_PE_PARSER* pPeParser)
{
	assert(pPeParser != NULL && pPeParser->pImgNtHdrs != NULL);

	pPeParser->pImgSectionHdr = (PIMAGE_SECTION_HEADER)(((PBYTE)pPeParser->pImgNtHdrs) + sizeof(IMAGE_NT_HEADERS));
	return TRUE;
}

BOOL PeParserLoadExportDirectory(T_PE_PARSER* pPeParser)
{
	assert(pPeParser != NULL && pPeParser->pBase != NULL && pPeParser->pImgOptHdr != NULL);

	pPeParser->pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pPeParser->pBase + pPeParser->pImgOptHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
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
		&& PeParserLoadExportDirectory(pPeParser);
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
	lstrcpyW(pPeParser->szLoadedFile, lpFileName);
	printf("[i] File \"%S\" Loaded. \n", pPeParser->szLoadedFile);
	return TRUE;
}

BOOL PeParserUnloadFile(T_PE_PARSER* pPeParser)
{
	assert(pPeParser != NULL);

	printf("[i] Unloading PE File \"%S\":\n", pPeParser->szLoadedFile);
	return PeParserUnload(pPeParser);
}

BOOL PeParserHasLoadedFile(T_PE_PARSER* pPeParser)
{
	assert(pPeParser != NULL);

	return pPeParser->szLoadedFile[0] != 0
		&& PeParserHasLoaded(pPeParser);
}

BOOL PeParserLoadModule(T_PE_PARSER* pPeParser, HANDLE hModule)
{
	assert(pPeParser != NULL);

	printf("[i] Loading PE Module:\n");
	if (PeParserHasLoaded(pPeParser))
		PeParserUnload(pPeParser);
	pPeParser->pBase = (PBYTE)hModule;
	pPeParser->sSize = 1; // TODO: Calc the size of hMdodule
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

	return pPeParser->szLoadedFile[0] == 0
		&& PeParserHasLoaded(pPeParser);
}

PDWORD PeParserGetExportDirectoryFunctionNameArray(T_PE_PARSER* pPeParser)
{
	assert(pPeParser != NULL && pPeParser->pBase != NULL && pPeParser->pImgExportDir != NULL);

	return (PDWORD)(pPeParser->pBase + pPeParser->pImgExportDir->AddressOfNames);
}

PDWORD PeParserGetExportDirectoryFunctionAddressArray(T_PE_PARSER* pPeParser)
{
	assert(pPeParser != NULL && pPeParser->pBase != NULL && pPeParser->pImgExportDir != NULL);

	return (PDWORD)(pPeParser->pBase + pPeParser->pImgExportDir->AddressOfFunctions);
}

PWORD PeParserGetExportDirectoryFunctionOrdinalArray(T_PE_PARSER* pPeParser)
{
	assert(pPeParser != NULL && pPeParser->pBase != NULL && pPeParser->pImgExportDir != NULL);

	return (PWORD)(pPeParser->pBase + pPeParser->pImgExportDir->AddressOfNameOrdinals);
}

BOOL PeParserPrintFileHeader(T_PE_PARSER* pPeParser)
{
	assert(pPeParser != NULL);

	if (!PeParserHasLoaded(pPeParser))
	{
		printf("\t[!] No PE Currently Loaded. \n");
		return FALSE;
	}

	printf("\n[i] Printing \"%S\" PE File Header:\n", pPeParser->szLoadedFile);

	if (pPeParser->pImgFileHdr->Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE)
	{

		printf("\t[i] PE File Detected As : ");

		if (pPeParser->pImgFileHdr->Characteristics & IMAGE_FILE_DLL)
			printf("DLL\n");
		else if (pPeParser->pImgFileHdr->Characteristics & IMAGE_SUBSYSTEM_NATIVE)
			printf("SYS\n");
		else
			printf("EXE\n");
	}

	printf("\t[i] File Arch : %s \n", pPeParser->pImgFileHdr->Machine == IMAGE_FILE_MACHINE_I386 ? "x32" : "x64");
	printf("\t[i] Number Of Sections : %d \n", pPeParser->pImgFileHdr->NumberOfSections);
	printf("\t[i] Size Of The Optional Header : %d Byte \n", pPeParser->pImgFileHdr->SizeOfOptionalHeader);
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

	printf("\n[i] Printing \"%S\" PE Optional Header:\n", pPeParser->szLoadedFile);

	printf("\t[i] File Arch (Alternate) : %s \n", pPeParser->pImgOptHdr->Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC ? "x32" : "x64");

	printf("\t[+] Size Of Code Section : %d \n", pPeParser->pImgOptHdr->SizeOfCode);
	printf("\t[+] Address Of Code Section : 0x%p \n\t\t[RVA : 0x%0.8X]\n", (PVOID)(pPeParser->pBase + pPeParser->pImgOptHdr->BaseOfCode), pPeParser->pImgOptHdr->BaseOfCode);
	printf("\t[+] Size Of Initialized Data : %d \n", pPeParser->pImgOptHdr->SizeOfInitializedData);
	printf("\t[+] Size Of Unitialized Data : %d \n", pPeParser->pImgOptHdr->SizeOfUninitializedData);
	printf("\t[+] Preferable Mapping Address : 0x%p \n", (PVOID)pPeParser->pImgOptHdr->ImageBase);
	printf("\t[+] Required Version : %d.%d \n", pPeParser->pImgOptHdr->MajorOperatingSystemVersion, pPeParser->pImgOptHdr->MinorOperatingSystemVersion);
	printf("\t[+] Address Of The Entry Point : 0x%p \n\t\t[RVA : 0x%0.8X]\n", (PVOID)(pPeParser->pBase + pPeParser->pImgOptHdr->AddressOfEntryPoint), pPeParser->pImgOptHdr->AddressOfEntryPoint);
	printf("\t[+] Size Of The Image : %d \n", pPeParser->pImgOptHdr->SizeOfImage);
	printf("\t[+] File CheckSum : 0x%0.8X \n", pPeParser->pImgOptHdr->CheckSum);
	printf("\t[+] Number of entries in the DataDirectory array : %d \n", pPeParser->pImgOptHdr->NumberOfRvaAndSizes); // this is the same as `IMAGE_NUMBEROF_DIRECTORY_ENTRIES` - `16`

	printf("\n[i] Printing \"%S\" PE Directories:\n", pPeParser->szLoadedFile);

	printf("\t[*] Export Directory At 0x%p Of Size : %d \n\t\t[RVA : 0x%0.8X]\n",
		(PVOID)(pPeParser->pImgExportDir),
		pPeParser->pImgOptHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size,
		pPeParser->pImgOptHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	printf("\t[*] Import Directory At 0x%p Of Size : %d \n\t\t[RVA : 0x%0.8X]\n",
		(PVOID)(pPeParser->pBase + pPeParser->pImgOptHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress),
		pPeParser->pImgOptHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size,
		pPeParser->pImgOptHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	printf("\t[*] Resource Directory At 0x%p Of Size : %d \n\t\t[RVA : 0x%0.8X]\n",
		(PVOID)(pPeParser->pBase + pPeParser->pImgOptHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress),
		pPeParser->pImgOptHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size,
		pPeParser->pImgOptHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress);

	printf("\t[*] Exception Directory At 0x%p Of Size : %d \n\t\t[RVA : 0x%0.8X]\n",
		(PVOID)(pPeParser->pBase + pPeParser->pImgOptHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress),
		pPeParser->pImgOptHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size,
		pPeParser->pImgOptHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress);

	printf("\t[*] Base Relocation Table At 0x%p Of Size : %d \n\t\t[RVA : 0x%0.8X]\n",
		(PVOID)(pPeParser->pBase + pPeParser->pImgOptHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress),
		pPeParser->pImgOptHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size,
		pPeParser->pImgOptHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

	printf("\t[*] TLS Directory At 0x%p Of Size : %d \n\t\t[RVA : 0x%0.8X]\n",
		(PVOID)(pPeParser->pBase + pPeParser->pImgOptHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress),
		pPeParser->pImgOptHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size,
		pPeParser->pImgOptHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);

	printf("\t[*] Import Address Table At 0x%p Of Size : %d \n\t\t[RVA : 0x%0.8X]\n",
		(PVOID)(pPeParser->pBase + pPeParser->pImgOptHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress),
		pPeParser->pImgOptHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size,
		pPeParser->pImgOptHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress);
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

	printf("\n[i] Printing \"%S\" PE Sections:\n", pPeParser->szLoadedFile);

	PIMAGE_SECTION_HEADER pImgSectionHdr = pPeParser->pImgSectionHdr;

	for (size_t i = 0; i < pPeParser->pImgNtHdrs->FileHeader.NumberOfSections; i++)
	{
		printf("[#] %s \n", (CHAR*)pPeParser->pImgSectionHdr->Name);
		printf("\tSize : %d \n", pPeParser->pImgSectionHdr->SizeOfRawData);
		printf("\tRVA : 0x%0.8X \n", pPeParser->pImgSectionHdr->VirtualAddress);
		printf("\tAddress : 0x%p \n", (PVOID)(pPeParser->pBase + pPeParser->pImgSectionHdr->VirtualAddress));
		printf("\tRelocations : %d \n", pPeParser->pImgSectionHdr->NumberOfRelocations);
		printf("\tPermissions : ");
		if (pPeParser->pImgSectionHdr->Characteristics & IMAGE_SCN_MEM_READ)
			printf("PAGE_READONLY | ");
		if (pPeParser->pImgSectionHdr->Characteristics & IMAGE_SCN_MEM_WRITE && pPeParser->pImgSectionHdr->Characteristics & IMAGE_SCN_MEM_READ)
			printf("PAGE_READWRITE | ");
		if (pPeParser->pImgSectionHdr->Characteristics & IMAGE_SCN_MEM_EXECUTE)
			printf("PAGE_EXECUTE | ");
		if (pPeParser->pImgSectionHdr->Characteristics & IMAGE_SCN_MEM_EXECUTE && pPeParser->pImgSectionHdr->Characteristics & IMAGE_SCN_MEM_READ)
			printf("PAGE_EXECUTE_READWRITE");
		printf("\n\n");

		pImgSectionHdr = (PIMAGE_SECTION_HEADER)((PBYTE)pImgSectionHdr + (DWORD)sizeof(IMAGE_SECTION_HEADER));
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

	pPeParser->szLoadedFile[0] = 0;
	if (pPeParser->pBase)
	{
		if (PeParserHasLoadedFile(pPeParser)) // Only free when the file buffer was loaded
			HeapFree(GetProcessHeap(), 0, pPeParser->pBase);
		pPeParser->pBase = NULL;
	}
	pPeParser->sSize = 0;
	pPeParser->pImgDosHdr = NULL;
	pPeParser->pImgNtHdrs = NULL;
	pPeParser->pImgFileHdr = NULL;
	pPeParser->pImgOptHdr = NULL;
	pPeParser->pImgSectionHdr = NULL;
	pPeParser->pImgExportDir = NULL;
	return TRUE;
}