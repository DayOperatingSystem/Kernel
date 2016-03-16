#include <heap.h>
#include <debug.h>
#include <vmm.h>

#define HEADERSIZE sizeof(node_t)

#define HEADER_START(x) ((node_t*)(((uintptr_t) x) - HEADERSIZE))
#define BLOCK_START(x) ((void*)((uintptr_t) x + HEADERSIZE))
#define NEXT_BLOCK(x) ((void*)((uintptr_t) BLOCK_START(x) + x->size))
#define MAGIC 0xCAFEBABE

typedef struct NODE
{
	unsigned int magic;
	unsigned int free;
	size_t size;
	struct NODE* next;
} node_t;

static node_t* root = (node_t*) HEAP_START;

void PrintHeap()
{
	DebugPrintf("*********************************************************************************\n");
	node_t* node = root;
	while(node)
	{
		DebugPrintf("Node: size = %d, start = 0x%x, MAGIC = 0x%x, free = %d\n", node->size, BLOCK_START(node), node->magic, node->free);
		node = node->next;
	}
	DebugPrintf("*********************************************************************************\n");
}


node_t* kcreateBlock(node_t* parent, size_t sz)
{
	if (!parent || !sz)
		return NULL;

	parent->next = NEXT_BLOCK(parent);

	assert((uintptr_t) parent->next < HEAP_END);
	
	parent->next->size = sz;
	parent->next->next = NULL;
	parent->next->free = 1;
	parent->next->magic = MAGIC;
	
	//kprintf("Creating block for memory: 0x%x at 0x%x\n", BLOCK_START(parent->next), parent->next);
	
	return parent->next;
}

void* kmalloc(size_t size)
{
	node_t* node = root;
	node_t* last = node;
	while(node != NULL)
	{
		assert((uintptr_t) node < HEAP_END);
		
		if(node->magic != MAGIC)
			PrintHeap();
		
		assert(node->magic == MAGIC);
		
		if(node->size >= size && node->free == 1)
		{
			node->free = 0;
			return BLOCK_START(node);
		}
		
		last = node;
		node = node->next;
	}
	
	node = kcreateBlock(last, size);
	node->free = 0;
	
	return BLOCK_START(node);
}

void kfree(void* addr)
{
	//kprintf("Trying to free: %x\n", addr);
  
	if(addr == NULL) return;
	assert((uintptr_t) addr < HEAP_END);
	node_t* node = HEADER_START(addr);
	
	if(node->magic != MAGIC)
	{
		PrintHeap();
	}
		
	assert(node->magic == MAGIC);

	node->free = 1;
	
	/*node_t* node = root;
	while(node != NULL)
	{
		assert(node < HEAP_END);
		assert(node->magic == MAGIC);
		// DebugPrintf("Processing: %x which starts at %x\n", node, BLOCK_START(node));
		if(BLOCK_START(node) == addr)
		{
			//kprintf("Freeing memory at: 0x%x\n", addr);
			node->free = 1;
		}
		
		node = node->next;
	}*/
}

void kinit_heap()
{
	DebugPrintf("[ KHEAP ] Kernel Heap at 0x%x - 0x%x\n", HEAP_START, HEAP_END);
	
	root->size = 0;
	root->next = NULL;
	root->free = 1;
	root->magic = MAGIC;
	
	DebugLog("[ KHEAP ] Kernel heap succesfully initialized.");
}
