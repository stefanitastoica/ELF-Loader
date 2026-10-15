// SPDX-License-Identifier: BSD-3-Clause

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <elf.h>
#include <string.h>
#include <math.h>
#include <sys/auxv.h>

void *map_elf(const char *filename)
{
	struct stat st;
	void *file;
	int fd;

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		perror("open");
		exit(1);
	}

	fstat(fd, &st);

	file = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (file == MAP_FAILED) {
		perror("mmap");
		close(fd);
		exit(1);
	}

	return file;
}

void *stack_create(int argc, char **argv, char **envp, Elf64_Ehdr *ehdr, Elf64_Phdr *phdr, int phnum, uint64_t load_base)
{
	int i;
	int stack_size = 8 * 1024 * 1024;
	void *stack = mmap(NULL, stack_size, PROT_READ | PROT_WRITE,
						MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	void *curr_stack = (char *)stack + stack_size;
	uint64_t phdr_vaddr = 0;

	for (i = 0; i < phnum; i++) {
		if (phdr[i].p_type == PT_PHDR) {
			phdr_vaddr = phdr[i].p_vaddr + load_base;
			break;
		}
	}

	char *envp_addr[200];

	i = 0;
	while (envp[i] != NULL) {
		char *envp_entry = envp[i];
		int len = strlen(envp_entry) + 1;

		curr_stack = (void *)((char *)curr_stack - len);
		memcpy(curr_stack, envp_entry, len);
		envp_addr[i] = curr_stack;
		i++;
	}
	int envp_len = i;

	char *argv_addr[200];

	for (i = 0; i < argc; i++) {
		char *argv_entry = argv[i];
		int len = strlen(argv_entry) + 1;

		curr_stack = (void *)((char *)curr_stack - len);
		memcpy(curr_stack, argv_entry, len);
		argv_addr[i] = curr_stack;
	}

	curr_stack = (void *)((char *)curr_stack - 16);
	memset(curr_stack, 0, 16);
	uint64_t random_ptr = (uint64_t)curr_stack;

	uint64_t *sp = (uint64_t *)((uint64_t)curr_stack);

	--sp;
	*sp = 0;
	--sp;
	*sp = AT_NULL;

	--sp;
	*sp = random_ptr;
	--sp;
	*sp = AT_RANDOM;

	--sp;
	*sp = (uint64_t)ehdr->e_phnum;
	--sp;
	*sp = AT_PHNUM;

	--sp;
	*sp = (uint64_t)ehdr->e_phentsize;
	--sp;
	*sp = AT_PHENT;

	--sp;
	*sp = phdr_vaddr;
	--sp;
	*sp = AT_PHDR;

	--sp;
	*sp = 0;
	i = envp_len - 1;
	while (i >= 0) {
		--sp;
		*sp = (uint64_t)envp_addr[i];
		i--;
	}
	--sp;
	*sp = 0;

	i = argc - 1;
	while (i >= 0) {
		--sp;
		*sp = (uint64_t)argv_addr[i];
		i--;
	}
	--sp;
	*sp = (uint64_t)argc;

	return (void *)sp;
}

void load_and_run(const char *filename, int argc, char **argv, char **envp)
{
	// Contents of the ELF file are in the buffer: elf_contents[x] is the x-th byte of the ELF file.
	void *elf_contents = map_elf(filename);
	/**
	 * Validate ELF magic bytes - "Not a valid ELF file" + exit code 3 if invalid.
	 * Validate ELF class is 64-bit (ELFCLASS64) - "Not a 64-bit ELF" + exit code 4 if invalid.
	 */
	Elf64_Ehdr *ehdr = (Elf64_Ehdr *)elf_contents;

	if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
		fprintf(stderr, "Not a valid ELF file\n");
		exit(3);
	}

	if (ehdr->e_ident[EI_CLASS] != ELFCLASS64) {
		fprintf(stderr, "Not a 64-bit ELF\n");
		exit(4);
	}
	Elf64_Phdr *phdr = (Elf64_Phdr *)((char *)elf_contents + ehdr->e_phoff);
	int phnum = ehdr->e_phnum;

	size_t page_size = 4096;
	uint64_t load_base = 0;

	int i;
	/**
	 * For each PT_LOAD segment:
	 *	- Set memory permissions according to program header p_flags (PF_R, PF_W, PF_X).
	 *	- Use mprotect() or map with the correct permissions directly using mmap().
	 */
	if (ehdr->e_type == ET_DYN)
		load_base = 0x400000;

	for (i = 0; i < phnum; i++) {
		Elf64_Phdr *elfp = &phdr[i];

		if (elfp->p_type == PT_LOAD) {
			uint64_t addr = ((elfp->p_vaddr + load_base) / page_size) * page_size;
			uint64_t page_offset = (elfp->p_vaddr + load_base) - addr;
			size_t size = elfp->p_memsz + page_offset;

			size = ((size + 4095) / page_size) * page_size;

			void *memory = mmap(
				(void *)addr,
				size,
				PROT_READ | PROT_WRITE,
				MAP_PRIVATE | MAP_ANONYMOUS,
				-1,
				0
			);

			memcpy(
				(char *)memory + page_offset,
				(char *)elf_contents + elfp->p_offset,
				elfp->p_filesz
			);

			int prot = 0;

			if (elfp->p_flags & PF_R)
				prot |= PROT_READ;
			if (elfp->p_flags & PF_W)
				prot |= PROT_WRITE;
			if (elfp->p_flags & PF_X)
				prot |= PROT_EXEC;
			mprotect(memory, size, prot);
		}
	}
	void *final_sp = stack_create(argc, argv, envp, ehdr, phdr, phnum, load_base);
	void (*entry)() = (void(*)())(ehdr->e_entry + load_base);

	__asm__ __volatile__(
			"mov %0, %%rsp\n"
			"xor %%rbp, %%rbp\n"
			"jmp *%1\n"
			:
			: "r"(final_sp), "r"(entry)
			: "memory"
			);
}

int main(int argc, char **argv, char **envp)
{
	if (argc < 2) {
		fprintf(stderr, "Usage: %s <static-elf-binary>\n", argv[0]);
		exit(1);
	}

	load_and_run(argv[1], argc - 1, &argv[1], envp);
	return 0;
}
