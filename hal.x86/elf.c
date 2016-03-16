#include <elf.h>
#include <string.h>
#include <debug.h>
#include <heap.h>

// TODO: Freigabe des verwendeten Speichers ermöglichen!
function_t ParseElf(uintptr_t addr, vmm_context_t* context)
{
	if(addr == 0 || context == NULL)
	{
		DebugLog("[ ELF ] Could not load ELF-Image: Given arguments are NULL!");
		return NULL;
	}
	
	header_t* header = (header_t*) addr;
	program_t* program = (program_t*) (addr + header->offset);
	int i;
	
	// ELF-Image ist nicht gültig!
	if(header->magic != ELF_MAGIC)
	{
		DebugLog("[ ELF ] Could not load ELF-Image: Image is damaged!");
		return NULL;
	}
	
	//DebugPrintf("[ ELF ] Got header: pentry_count == %d, entry == 0x%x, magic == 0x%x\n", header->pentry_count, header->entry, header->magic);
	
	for(i = 0; i < header->pentry_count; i++, program++)
	{
		void* dest = (void*) program->vaddr;
		void* src = (void*) (addr + program->offset);

		// DebugPrintf("Copying 0x%x to 0x%x with msize %d and fsize %d addr 0x%x pages needed: %d\n", (uint32_t) src, (uint32_t) dest, program->msize, program->fsize, addr, program->msize / PAGESIZE);
		
		// Können wir diesen Teil brauchen?
		if(program->type != 1 || dest == NULL || src == NULL)
		{
			continue;
		}
		
		// Copy all data to stack so it is available in the new
		// vmm context
		void* buf = kmalloc(program->fsize);
		size_t msize = program->msize;
		size_t fsize = program->fsize;
		
		//if(msize & 0x00000FFF)
		//	msize = (msize + PAGESIZE) & 0xFFFFF000;
		
		memcpy(buf, src, program->fsize);
		
		vmm_alloc(context, program->vaddr & 0xFFFFF000, program->msize);		
		vmm_context_t* old_context = current_context;
		
		activate_memory_context(context);
		
		memset(dest, 0, msize);
		memcpy(dest, buf, fsize);
		
		activate_memory_context(old_context);
		kfree(buf);
	}
	
	return (function_t) header->entry;
}
