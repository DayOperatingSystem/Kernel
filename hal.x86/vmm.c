#include <vmm.h>
#include <types.h>
#include <debug.h>
#include <heap.h>

// Kernel Kontext
vmm_context_t* kernel_context = NULL;
vmm_context_t* current_context = NULL;

static struct multiboot_info* g_mbinfo = NULL;

void activate_memory_context(vmm_context_t* context)
{
	 __asm volatile("mov %0, %%cr3" : : "r" (context->pagedir));
	 current_context = context;
}

vmm_context_t* create_context()
{
	vmm_context_t* context = pmm_alloc(PAGEPOOL_START, PAGEPOOL_END);
	assert(context != NULL);
	
	context->pagedir = pmm_alloc(PAGEPOOL_START, PAGEPOOL_END);
	assert(context->pagedir != NULL);
	
	int i = 0;
	for(; i < 1024; i++)
	{
		context->pagedir[i] = 0;
	}
	
	return context;
}

void destroy_context(vmm_context_t* context)
{
	//return;
	assert(context != NULL);
	assert(context != kernel_context);

	pmm_info();
	int i = 0;

	// Free everything else
	for (; i < 1024; i++)
	{
		if (context->pagedir[i] & 0x1)
		{
			uintptr_t* pagetable = (uintptr_t*)(context->pagedir[i] & ~0xFFF);

			for (int j = 0; j < 1024; j++)
			{
				uintptr_t entry = pagetable[j] & ~0xFFF;

				if (pagetable[j] & VMM_USED && pagetable[j] & VMM_ALLOCATED)
				{
				    pmm_free((void*) entry);
				}
			}
			pmm_free((void*) pagetable);
		}
	}

	pmm_free(context->pagedir);
	pmm_free(context);

	pmm_info();
}

void map_page(vmm_context_t* context, uintptr_t virt, uintptr_t phys, uint8_t userspace, uint8_t allocated)
{
	assert(context != 0);
	uint32_t pageIndex = virt / 0x1000;
	uint32_t pdIndex = pageIndex / 1024;
	uint32_t ptIndex = pageIndex % 1024;
	
	uint32_t* pageTable;
	int i;
	
	uint32_t flags = 0;
	
	if(userspace)
		flags = VMM_USED | VMM_WRITE | VMM_USERSPACE;
	else
		flags = VMM_USED | VMM_WRITE;

	if(allocated)
		flags |= VMM_ALLOCATED;
	
	// Wir brauchen 4k-Alignment
	assert(!((virt & 0xFFF) || (phys & 0xFFF)));
	
	// Page Table heraussuchen bzw. anlegen
	if (context->pagedir[pdIndex] & 0x1)
	{
		// Page Table ist schon vorhanden
		pageTable = (uint32_t*) (context->pagedir[pdIndex] & ~0xFFF);
	}
	else
	{
		// Neue Page Table muss angelegt werden
		pageTable = (uint32_t*) pmm_alloc(PAGEPOOL_START, PAGEPOOL_END);
		
		assert(pageTable != NULL);
		
		for (i = 0; i < 1024; i++)
		{
			pageTable[i] = 0;
		}
		
		context->pagedir[pdIndex] = (uint32_t) pageTable | flags;
	}

	// Neues Mapping in the Page Table eintragen
	pageTable[ptIndex] = phys | flags;
	__asm volatile("invlpg (%0)" : : "r" /*(*(char*)virt)*/ (virt) : "memory"); 
}

void map_range(vmm_context_t* context, uintptr_t start_virt, 
			   uintptr_t start_phys, uint32_t size, uint32_t userspace)
{
	int i;
	for(i = start_virt; i <= start_virt + size; i += PAGESIZE, start_phys += PAGESIZE)
	{
		map_page(context, i, start_phys, userspace, 0);
		//start_phys += PAGESIZE;
	}
}

void vmm_alloc(vmm_context_t* context, uintptr_t vaddr, uint32_t sz)
{
	int i;
	uintptr_t end = vaddr + sz;
	
	for(i = vaddr; i < end; i += PAGESIZE)
	{
		uintptr_t phys_page = (uintptr_t) pmm_alloc_start(HEAP_END);
		assert(phys_page != 0);
		map_page(context, i, phys_page, 1, 1);
	}
}

void enable_paging(int value)
{
	uint32_t cr0;
	__asm volatile("mov %%cr0, %0" : "=r" (cr0));

	if(value)
		cr0 |= (1 << 31);
	else
		cr0 &= ~(1 << 31);
	
	__asm volatile("mov %0, %%cr0" : : "r" (cr0)); 
}

void InitVmm(struct multiboot_info* mb_info)
{
	DebugPrintf("[ VMM ] Kernel at 0x%x - 0x%x\n", VM_KERNEL_START, VM_KERNEL_END);
	DebugPrintf("[ VMM ] Pagepool at 0x%x - 0x%x\n", PAGEPOOL_START, PAGEPOOL_END);
	
	g_mbinfo = mb_info;
	kernel_context = create_context();
	
	// FIXME: Der gesamte Kernel ist schreibbar im usermode?
	map_range(kernel_context, NULL, NULL,
			  VM_KERNEL_END, 0);
	
	map_range(kernel_context, PAGEPOOL_START, PAGEPOOL_START,
			  PAGEPOOL_END - PAGEPOOL_START, 0);
	
	// Heap mappen
	map_range(kernel_context, HEAP_START, HEAP_START, HEAP_SIZE, 0);
	
	// Kernel Speicherkontext aktivieren
	activate_memory_context(kernel_context);
	
	// Paging einschalten
	enable_paging(1);
	
	DebugLog("[ VMM ] Virtual Memory management succesfully initialized.");
}

vmm_context_t* CreateUsermodeContext(int kernel_write)
{
	vmm_context_t* context = create_context();
	
	//int i = 0;
	//for(; i < 1024; i++)
	//{
	//	context->pagedir[i] = kernel_context->pagedir[i];
	//}

	// FIXME: HACK: Allow every process to wrote to addresses below 1MB! DON'T DO THAT!
	map_range(context, NULL, NULL, VM_KERNEL_START, 1);
	
	map_range(context, VM_KERNEL_START, VM_KERNEL_START,
			  VM_KERNEL_END - VM_KERNEL_START, 0);
	
	map_range(context, PAGEPOOL_START, PAGEPOOL_START,
			  PAGEPOOL_END - PAGEPOOL_START, 0);
	
	// Heap mappen
	map_range(context, HEAP_START, HEAP_START, HEAP_SIZE, 0);
	map_page(context, 0, 0, 0, 0); // Don't allow writing to NULL! HACK FOR NOW!
	
	return context;
}
