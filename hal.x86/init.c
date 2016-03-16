#include <video.h>
#include <debug.h>
#include <gdt.h>
#include <idt.h>
#include <pit.h>
#include <pmm.h>
#include <vmm.h>
#include <heap.h>
#include <ramdisk.h>
#include <multitasking.h>
#include <driver.h>
#include <string.h>

extern void InitBootDrivers();

// #define SELF_TEST

#ifdef SELF_TEST
int selfTest()
{
	kprintln ("Running self test to ensure stability.");
	kprintln ("--> Testing heap functions");

	void *p1 = kmalloc (15);
	void *p2 = kmalloc (12);

	kprintf ("--> Allocated memory: 0x%x and 0x%x\n", p1, p2);

	kfree (p1);
	kfree (p2);

	void *p3 = kmalloc (15);
	void *p4 = kmalloc (12);

	if (p3 != p1 || p2 != p4)
	{
		kprintln ("--> Freeing and allocating memory does not work!");
		kprintf ("--> Allocated memory: 0x%x and 0x%x\n", p3, p4);
		return 1;
	}

	kfree (p1);
	kfree (p2);

	kprintln ("--> Heap test passed!");

	return 0;
}
#endif

// define our structure
typedef struct __attribute__ ( (packed))
{
	unsigned short di, si, bp, sp, bx, dx, cx, ax;
	unsigned short gs, fs, es, ds, eflags;
}
regs16_t;

// tell compiler our int32 function is external
extern void int32 (unsigned char intnum, regs16_t *regs);

// int32 test
void int32_test()
{
	int y;
	regs16_t regs;

	cls();
	kprintln ("Executing VGA graphics test. Press any key to continue.");
	// wait for key
	regs.ax = 0x0000;
	int32 (0x16, &regs);

	// switch to 320x200x256 graphics mode
	regs.ax = 0x0013;
	int32 (0x10, &regs);

	// full screen with blue color (1)
	memset ( (char *) 0xA0000, 1, (320 * 200));

	// draw horizontal line from 100,80 to 100,240 in multiple colors
	for (y = 0; y < 200; y++)
		memset ( (char *) 0xA0000 + (y * 320 + 80), y, 160);

	// wait for key
	regs.ax = 0x0000;
	int32 (0x16, &regs);

	// switch to 80x25x16 text mode
	regs.ax = 0x0003;
	int32 (0x10, &regs);

	__asm ("cli");
}

// CPUID detection code!
int detect_cpu (void);

void init (struct multiboot_info *mb_info, uint32_t kernel_esp)
{
	// Clear screen
	cls();
	
	// HAL-Services
	kprintln ("Booting up...");

	detect_cpu();

	InitSerial (115200, 0, 8);
	InitGlobalDescriptors (kernel_esp);
	InitInterruptDescriptors();
	InitPit (CLOCKS_PER_SEC);
	InitPmm (mb_info);

	InitVmm (mb_info);
	kinit_heap();

#ifdef SELF_TEST

	if (selfTest() != 0)
	{
		kprintln ("Will not start up because of self test errors!");

		while (1);
	}

#endif

	// Erstes Modul ist unsere RAM-Disk
	InitRamdisk ( ( (struct multiboot_module *) mb_info->mbs_mods_addr)->mod_start);
	
	InitMultitasking();

	// while(1);

	// kprintf((char*) ((struct multiboot_module*)
	// mb_info->mbs_mods_addr)->mod_start);
	

	InitBootDrivers();

	//int32_test();
	
	__asm ("sti");
	for (;;);
}
