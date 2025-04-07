#include <stdio.h>
#include <windows.h>

#include "PeParser.h"

int wmain(int argc, wchar_t* argv[])
{
	T_PE_PARSER PeParser;

	if (argc < 2)
	{
		printf("[!] Usage : \"%S\" <PE File>\n", argv[0]);
		return FALSE;
	}

	PeParserInitialize(&PeParser);

	PeParserLoadFile(&PeParser, argv[1]);

	PeParserPrintAll(&PeParser);

	PeParserUnloadFile(&PeParser);

	PeParserClean(&PeParser);
}