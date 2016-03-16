#ifndef HEAP_H
#define HEAP_H

#include <vmm.h>

#define HEAP_START PAGEPOOL_END
#define HEAP_SIZE 0x1400000
#define HEAP_END (HEAP_START + HEAP_SIZE)

void kinit_heap();
void* kmalloc(size_t size);
void kfree(void* addr);

// Header eines jeden Heapspeicher Blocks
typedef struct HEADER_STRUCT
{
	uintptr_t start;
	uintptr_t size;
	
	// Nur ein bit für true und false
	uint32_t free : 1;
	uint32_t is_end : 1;
}heap_header_t;

#endif
