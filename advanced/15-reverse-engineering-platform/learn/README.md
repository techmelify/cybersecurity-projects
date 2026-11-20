# Learn — static binary triage

## Why inspect bytes without running them

Executing an unknown program is dangerous. Static inspection asks safer first questions: what format is this, what architecture does it target, what readable text does it contain, and which libraries does it mention?

## Header basics

- **ELF** begins with `7f 45 4c 46`. Byte 4 gives 32- or 64-bit class, byte 5 gives endianness, and bytes 18–19 give the machine type. The header also points to a section table.
- **PE** begins with `MZ`. The four bytes at `0x3C` point to a `PE\0\0` signature, followed by the COFF machine type, section count, and section table.

## Strings and imports

Printable ASCII runs often reveal error messages, URLs, file paths, and library names. Library names such as `kernel32.dll` or `libcrypto.so.3` hint at capabilities (Windows APIs, cryptography) without needing to disassemble code.

## Entropy

Shannon entropy measures byte diversity. Uniform padding has entropy near zero; compressed or encrypted data approaches eight bits per byte. It is only a hint — many ordinary files compress parts of themselves.

## Safety rule

Read bytes, never execute them. Keep samples synthetic or isolated, and prefer static facts over dynamic behaviour whenever a quick triage is enough.
