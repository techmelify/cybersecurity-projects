# Learn — ELF and PE headers

## Magic numbers

ELF starts with `7f 45 4c 46`; PE files start with the DOS stub `MZ` and store the real PE offset at `0x3C`. A parser checks magic before interpreting any other field.

## Class and endianness

ELF encodes class (32/64-bit) and byte order in `e_ident[4]` and `e_ident[5]`. Those two bytes decide every subsequent `struct` format string. PE is little-endian and distinguishes PE32 from PE32+ using the optional header magic (`0x10b` vs `0x20b`).

## Section and segment tables

Section headers describe linker views (`.text`, `.data`, `.shstrtab`); program headers describe loader views (`PT_LOAD`, `PT_INTERP`). Section names live in a string table referenced by `e_shstrndx`, so reading names requires a second indirection.

## Why synthetic fixtures

Hand-building a 64-byte header teaches the field layout far better than shipping a real executable. It also keeps the repository free of binaries that antivirus tools might flag, and makes tests deterministic across platforms.

## Exercises

- Parse symbolic entries from `.symtab` / `.strtab`.
- Decode PE import directory names from the optional header data directories.
- Add a check for suspicious section names and permissions as a static triage aid.
