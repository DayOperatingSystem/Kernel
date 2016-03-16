#ifndef PMM_H
#define PMM_H

#include "multiboot.h"

// Mindestens vorrausgesetzter Speicher (in MB)
#define MIN_MEMORY 30

#define PAGESIZE 0x1000
#define MEMORY_LIMIT 0x100000000

void InitPmm(struct multiboot_info *mb_info);
void* pmm_alloc(uint32_t start, uint32_t end);
void* pmm_alloc_start(uint32_t start);
void pmm_free(void* addr);
void pmm_info();

#endif
