#ifndef ELF_H
#define ELF_H

#include <types.h>
#include <vmm.h>

#define PF_X 1
#define ET_DYN 3
#define ET_EXEC 2

#define EM_386 3

#define ELF_MAGIC 0x464C457F


#define SHT_NULL 0
#define SHT_PROGBITS 1
#define SHT_SYMTAB 2
#define SHT_STRTAB 3
#define SHT_RELA 4
#define SHT_HASH 5
#define SHT_DYNAMIC 6
#define SHT_NOTE 7
#define SHT_NOBITS 8
#define SHT_REL 9
#define SHT_SHLIB 10
#define SHT_DYNSYM 11
#define SHT_LOPROC 0x70000000
#define SHT_HIPROC 0x7fffffff
#define SHT_LOUSER 0x80000000
#define SHT_HIUSER 0xffffffff

struct header_type {
    uint32_t    magic;
    uint32_t    version;
    uint64_t    reserved;
    uint64_t    versions;
    uint32_t    entry;
    uint32_t    offset;
    uint32_t    soffset;
    uint32_t    flags;
    uint16_t    header_size;
    uint16_t    pentry_size;
    uint16_t    pentry_count;
    uint16_t    sentry_size;
    uint16_t    sentry_count;
    uint16_t    stable_index;
} __attribute__((packed));

typedef struct header_type header_t;

struct program_type {
    uint32_t    type;
    uint32_t    offset;
    uint32_t    vaddr;
    uint32_t    paddr;
    uint32_t    fsize;
    uint32_t    msize;
    uint32_t    flags;
    uint32_t    alignment;
}__attribute__((packed));

typedef struct program_type program_t;

struct elf_program_header {
    uint32_t    type;
    uint32_t    offset;
    uint32_t    virt_addr;
    uint32_t    phys_addr;
    uint32_t    file_size;
    uint32_t    mem_size;
    uint32_t    flags;
    uint32_t    alignment;
} __attribute__((packed));

#define EI_NIDENT 16

typedef struct {
unsigned char e_ident[EI_NIDENT];
unsigned short e_type;
unsigned short e_machine;
uint32_t e_version;
uint32_t e_entry;
uint32_t e_phoff;
uint32_t e_shoff;
uint32_t e_flags;
unsigned short e_ehsize;
unsigned short e_phentsize;
unsigned short e_phnum;
unsigned short e_shentsize;
unsigned short e_shnum;
unsigned short e_shstrndx;
} Elf32_Ehdr;

typedef struct {
uint32_t sh_name;
uint32_t sh_type;
uint32_t sh_flags;
uint32_t sh_addr;
uint32_t sh_offset;
uint32_t sh_size;
uint32_t sh_link;
uint32_t sh_info;
uint32_t sh_addralign;
uint32_t sh_entsize;
} Elf32_Shdr;

typedef void (*function_t)();

function_t ParseElf(uintptr_t addr, vmm_context_t* context);

#endif
