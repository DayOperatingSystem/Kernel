#include <gdt.h>
#include <types.h>
#include <debug.h>

uint32_t tss[32] = { 0, 0, 0x10 };

/// Struktur einer GDT entry
struct GDTEntry
{
	uint16_t limit_low;		   // Die "lower" 16 bits des Limits
	uint16_t base_low;			// Die "lower" 16 bits der Basis
	uint8_t  base_middle;		 // Die folgenden 8 bits
	uint8_t  access;
	uint8_t  granularity;
	uint8_t  base_high;
}__attribute__ ((__packed__));

/// Struktur des GDT pointers
struct GDTPointer
{
	uint16_t limit;			   // Die "upper" 16 bits der selector limits.
	uint32_t base;				// Die Adresse der ersten gdt_entry_t Struktur.
}__attribute__ ((__packed__));

struct GDTPointer gp;
struct GDTEntry gdt_entries[6];

static void CreateDescriptor(struct GDTEntry* entry, uint32_t base, 
			uint32_t limit, uint8_t access, uint8_t gran)
{
	entry->base_low = (base & 0xFFFF);
	entry->base_middle = (base >> 16) & 0xFF;
	entry->base_high = (base >> 24) & 0xFF;

	entry->limit_low = (limit & 0xFFFF);
	entry->granularity = (limit >> 16) & 0x0F;

	entry->granularity |= gran & 0xF0;
	entry->access = access;
}

void InitGlobalDescriptors(uint32_t kernel_esp)
{
	tss[1] = kernel_esp;

	gp.limit = (sizeof(struct GDTEntry) * 6) - 1;
	gp.base  = (uint32_t) &gdt_entries;

	CreateDescriptor(&gdt_entries[0], 0, 0, 0, 0);			// Null segment
	CreateDescriptor(&gdt_entries[1], 0, 0xFFFFFFFF, 0x9A, 0xCF); // Code segment
	CreateDescriptor(&gdt_entries[2], 0, 0xFFFFFFFF, 0x92, 0xCF); // Data segment
	CreateDescriptor(&gdt_entries[3], 0, 0xFFFFFFFF, 0xFA, 0xCF); // User mode code segment
	CreateDescriptor(&gdt_entries[4], 0, 0xFFFFFFFF, 0xF2, 0xCF); // User mode data segment

	CreateDescriptor(&gdt_entries[5], (uint32_t) &tss, sizeof(tss), 0x89, 0x40); // TSS 
	
	// GDT neu laden
	__asm("lgdt %0" : : "m" (gp));

	// Segmentregister neu laden, damit die neuen GDT-Einträge auch wirklich benutzt werden
	__asm("mov $0x10, %ax;"
		"mov %ax, %ds;"
		"mov %ax, %es;"
		"mov %ax, %ss;"
		"ljmp $0x8, $.1;"
		".1:");

	__asm volatile("ltr %%ax" : : "a" (0x2B));
}
