#ifndef VMM_H
#define VMM_H

#include "pmm.h"
#include "multiboot.h"
#include "debug.h"

extern void* kernel_end;
extern void* kernel_start;

#define VM_KERNEL_END ((uint32_t) &kernel_end)
#define VM_KERNEL_START ((uint32_t) &kernel_start)

#define PAGEPOOL_START VM_KERNEL_END
// 2MB Pagepool
#define PAGEPOOL_END (PAGEPOOL_START + 0x4600000) // 70MB //0x200000) //

// Userspace heap ab 1GB
#define USERSPACE_PAGEPOOL 0x40000000

// Paging flags
#define VMM_USED 0x1
#define VMM_WRITE 0x2
#define VMM_USERSPACE 0x4

// Custom value: signifies that the page needs to be freed when the context is deleted (1 << 10)
#define VMM_ALLOCATED (1 << 10)

typedef struct
{
	uint32_t* pagedir;
}vmm_context_t;

extern vmm_context_t* current_context;

void InitVmm(struct multiboot_info* mb_info);
vmm_context_t* CreateUsermodeContext(int kernel_write);
void activate_memory_context(vmm_context_t* context);
void vmm_alloc(vmm_context_t* context, uintptr_t vaddr, uint32_t sz);
void destroy_context(vmm_context_t* context);
void map_page(vmm_context_t* context, uintptr_t virt, uintptr_t phys, uint8_t userspace, uint8_t allocated);
void enable_paging(int value);
void map_range(vmm_context_t* context, uintptr_t start_virt, uintptr_t start_phys, uint32_t size, uint32_t userspace);
vmm_context_t* vmm_clone_context(vmm_context_t* template);

#endif
