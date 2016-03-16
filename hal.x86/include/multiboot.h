#ifndef MULTIBOOT_H
#define MULTIBOOT_H

#include "types.h"

struct multiboot_info {
	uint32_t	mbs_flags;
	uint32_t	mbs_mem_lower;
	uint32_t	mbs_mem_upper;
	uint32_t	mbs_bootdevice;
	uint32_t	mbs_cmdline;
	uint32_t	mbs_mods_count;
	void*	   mbs_mods_addr;
	uint32_t	mbs_syms[4];
	uint32_t	mbs_mmap_length;
	void*	   mbs_mmap_addr;
}PACKED;

struct multiboot_mmap {
	uint32_t	entry_size;
	uint64_t	base;
	uint64_t	length;
	uint32_t	type;
}PACKED;

struct multiboot_module {
	uint32_t	mod_start;
	uint32_t	mod_end;
	char*	   cmdline;
	uint32_t	reserved;
}PACKED;

#endif
