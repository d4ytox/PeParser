#ifndef PE_PARSER_H_INCLUDED
#define PE_PARSER_H_INCLUDED

#include <windows.h>

typedef struct PE_PARSER
{
	WCHAR szLoadedFileName[MAX_PATH];

	// Raw Data
	PBYTE pRawData;
	SIZE_T sRawDataSize;

	// Headers
	PIMAGE_DOS_HEADER pImageDosHeader;
	PIMAGE_NT_HEADERS pImageNtHeaders;
	PIMAGE_FILE_HEADER pImageFileHeader;
	PIMAGE_OPTIONAL_HEADER pImageOptionalHeader;
	PIMAGE_SECTION_HEADER pImageSectionHeader;

	// Directories
	PIMAGE_EXPORT_DIRECTORY pImageExportDirectory;
	PVOID pImageImportDirectory;
	PVOID pImageResourceDirectory;
	PVOID pImageExceptionDirectory;
	PVOID pBaseRelocationTable;
	PVOID pTLSDirectory;
	PVOID pImportAddressTable;
} T_PE_PARSER;

BOOL PeParserInitialize(T_PE_PARSER *pPeParser);

BOOL PeParserLoadFile(T_PE_PARSER* pPeParser, LPCWSTR lpFileName);
BOOL PeParserUnloadFile(T_PE_PARSER* pPeParser);
BOOL PeParserHasLoadedFile(T_PE_PARSER* pPeParser);

BOOL PeParserLoadModule(T_PE_PARSER* pPeParser, HANDLE hModule);
BOOL PeParserUnloadModule(T_PE_PARSER* pPeParser);

PDWORD PeParserGetExportDirectoryFunctionNameArray(T_PE_PARSER* pPeParser);
PDWORD PeParserGetExportDirectoryFunctionAddressArray(T_PE_PARSER* pPeParser);
PWORD PeParserGetExportDirectoryFunctionOrdinalArray(T_PE_PARSER* pPeParser);

BOOL PeParserPrintFileHeader(T_PE_PARSER* pPeParser);
BOOL PeParserPrintOptionalHeader(T_PE_PARSER* pPeParser);
BOOL PeParserPrintSections(T_PE_PARSER* pPeParser);
BOOL PeParserPrintAll(T_PE_PARSER *pPeParser);

BOOL PeParserClean(T_PE_PARSER *pPeParser);

#endif /* PE_PARSER_H_INCLUDED */