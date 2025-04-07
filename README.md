# PeParser

Object-oriented PE file parser.

Heavily inspired and based off the amazing work by [mrd0x](https://github.com/mrd0x) and [NUL0x4C](https://github.com/NUL0x4C).

Coming from a background in OOP as well as low-level, I thought that the Pe Parsing could be a great C "class".

See the provided main.c for a typical use case

## Installation

Just copy PeParser.c and PeParser.h in your project.

See HOWTO below for example usages.

## HOWTO

### Targeting a File

`T_PE_PARSER PeParser;

`PeParserInitialize(&PeParser);

`PeParserLoadFile(&PeParser, sFileName); // where sFileName is your targeted PE file name (with full path)

`PeParserPrintAll(&PeParser); // To print all headers / directories / directories

`PeParserUnloadFile(&PeParser);

`PeParserClean(&PeParser);

### Targeting a Module Handle

`T_PE_PARSER PeParser;

`PeParserInitialize(&PeParser);

`PeParserLoadModule(&PeParser, hModule); // where hModule is your targeted PE module pre-loaded handle

`PeParserPrintAll(&PeParser); // To print all headers / directories / directories

`PeParserUnloadModule(&PeParser);

`PeParserClean(&PeParser);
