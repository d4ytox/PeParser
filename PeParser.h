#ifndef PE_PARSER_H_INCLUDED
#define PE_PARSER_H_INCLUDED

#include <windows.h>

typedef struct PE_PARSER
{
	WCHAR szLoadedFile[MAX_PATH];

	// Raw Data
	PBYTE pBase;
	SIZE_T sSize;

	// Headers
	PIMAGE_DOS_HEADER pImgDosHdr;
	PIMAGE_NT_HEADERS pImgNtHdrs;
	PIMAGE_FILE_HEADER pImgFileHdr;
	PIMAGE_OPTIONAL_HEADER pImgOptHdr;
	PIMAGE_SECTION_HEADER pImgSectionHdr;

	// Directories
	PIMAGE_EXPORT_DIRECTORY pImgExportDir;
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