# Custom 64-bit ELF Loader

## Overview
A custom Executable and Linkable Format (ELF) loader written in C for Linux environments. Instead of relying on the standard Linux `execve` system call, this project manually parses 64-bit ELF binaries, maps them into memory, initializes the execution stack (including the Auxiliary Vector), and transfers control to the loaded program via inline assembly.

This project was built to explore the deep internals of the Linux operating system, virtual memory management, and process initialization.

## Key Features
- **ELF Parsing & Validation:** Validates `ELFMAG` magic bytes and ensures the binary conforms to the 64-bit class (`ELFCLASS64`).
- **Memory Mapping & Page Alignment:** Iterates through `PT_LOAD` segments, calculating strict page-aligned virtual addresses (4KB boundaries). It applies per-segment permissions via `mprotect()`.
- **Position Independent Executable (PIE) Support:** Detects dynamic ELF types (`ET_DYN`) and assigns a custom load base (`0x400000`) for correct memory placement.
- **Manual Stack & AuxV Initialization:** Allocates an 8MB anonymous memory region to build the process stack from scratch. It correctly pushes environment variables (`envp`), command-line arguments (`argv`), and constructs the **Auxiliary Vector (AuxV)** (including `AT_RANDOM`, `AT_PHNUM`, `AT_PHENT`, `AT_PHDR`) required by the C runtime.
- **Context Switch:** Uses GCC inline assembly to overwrite the stack pointer (`%rsp`), clear the base pointer (`%rbp`), and execute a direct jump (`jmp`) into the program's entry point.

## Prerequisites
- Linux environment (tested on x86_64 architecture)
- GCC compiler
- GNU Make

## Build Instructions
Clone the repository and run `make` to compile the loader:
```bash
make
