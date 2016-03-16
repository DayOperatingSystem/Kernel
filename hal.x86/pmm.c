#include <pmm.h>
#include <vmm.h>
#include <debug.h>
#include <string.h>
#include <heap.h>

#define BITMAP_SIZE 32768
#define MEMORY_SIZE BITMAP_SIZE * 32
static uint32_t bitmap[BITMAP_SIZE];

uint32_t total_memory = 0;
uint32_t free_memory;

uint32_t get_index(uint32_t addr, uint32_t* offset)
{
	addr /= PAGESIZE;
	*offset = addr % 32;
	return addr / 32;
}

static uint32_t is_free(void* addr)
{
	uint32_t offset;
	uint32_t index = get_index((uint32_t) addr, &offset);
	return (bitmap[index] & (1 << offset));
}

void pmm_free(void* addr)
{
	uint32_t offset;
	uint32_t index = get_index((uint32_t) addr, &offset);
	bitmap[index] &= ~(1 << offset);
	free_memory += 0x1000;
}

static void use(void* addr)
{
	uint32_t offset;
	uint32_t index = get_index((uint32_t) addr, &offset);
	bitmap[index] |= (1 << offset);
	free_memory -= 0x1000;
}

void InitPmm(struct multiboot_info* mb_info)
{
	// mbs_mem_upper zählt erst hinter dem ersten Megabyte
	// deshalb muss die Rechnung um eines erhöht werden
	total_memory = (mb_info->mbs_mem_upper / 1024) + 1;

	assert(total_memory > MIN_MEMORY);
	
	struct multiboot_mmap* mmap = (struct multiboot_mmap*) mb_info->mbs_mmap_addr;
	
	struct multiboot_mmap* mmap_end = (struct multiboot_mmap*)((uintptr_t)
			mb_info->mbs_mmap_addr + mb_info->mbs_mmap_length);

	// Alles als belegt markieren.
	memset(&bitmap, 0, sizeof(uint32_t) * BITMAP_SIZE);
		
	// Nur was laut der BIOS Memory MAP Frei ist, wird wieder freigegeben.
	while(mmap < mmap_end)
	{
		if (mmap->type == 1)
		{
			uintptr_t addr = mmap->base;
			uintptr_t end_addr = addr + mmap->length;

			while (addr < end_addr)
			{
				pmm_free((void *)addr);
				addr += 0x1000;
			}
		}
		mmap++;
	}
	
	// Den Kernel als belegt markieren
	uintptr_t addr = VM_KERNEL_START;
	while (addr < VM_KERNEL_END)
	{
		use((void *) addr);
		addr += 0x1000;
	}
	
	struct multiboot_module *modules =(struct multiboot_module*) mb_info->mbs_mods_addr;

	// Die Multiboot Struktur ist auch belegt.
	use(mb_info);
	// Die Multiboot Modul Struktur ist auch belegt.
	use(modules);
	
	uint32_t i;
	for (i = 0; i < mb_info->mbs_mods_count; i++)
	{
		addr = modules[i].mod_start;
		while (addr < modules[i].mod_end)
		{
			use((void*) addr);
			addr += 0x1000;
		}
	}

	// Heap allozieren
	for(i = HEAP_START; i < HEAP_END; i += PAGESIZE)
	{
		use((void*) i);
	}	

	// Die IVT vor überschreiben schützen.
	use((void*) 0x0);
	
	DebugPrintf("[ PMM ] Total memory: %dMB\n[ PMM ] Free memory: %dMB\n", total_memory, free_memory/1024/1024);
	DebugLog("[ PMM ] Physical Memory management succesfully initialized.");
}

/**
 * Sucht eine freie Seite im Speicher, welche zwischen start und end liegt
 * ACHTUNG: start und end MÜSSEN Vielfache von PAGESIZE (0x1000) sein!
 */
void* pmm_alloc(uint32_t start, uint32_t end)
{
	uint32_t i = start;
	
	// FIXME: Einfach NULL zurückgeben!
	assert(start < end);
		
	for(; i < end; i += PAGESIZE)
	{
		if(is_free((void*) i) == 0)
		{
			use((void*) i);
			return (void*) i;
		}
	}
	
	DebugPrintf("No memory found with start 0x%x starting at kernel_end = 0x%x\n", start, &kernel_end);

	return NULL;
}

void* pmm_alloc_start(uint32_t start)
{
	uint32_t i = start / PAGESIZE;
			
	for(; i < MEMORY_SIZE; i++)
	{
		if(is_free((void*) (i * PAGESIZE)) == 0)
		{
			use((void*) (i * PAGESIZE));
			return (void*) (i * PAGESIZE);
		}
	}
	return NULL;
}

void pmm_info()
{
    uintptr_t used = total_memory*1024*1024 - free_memory;
    DebugPrintf("[ PMM ] Using %d bytes of memory, that are %dMB or %d pages of %d\n", 
		used,
		used/1024/1024,
		used/PAGESIZE,
		PAGESIZE
 	      );
}
