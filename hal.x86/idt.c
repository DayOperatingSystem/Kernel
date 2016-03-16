#include <idt.h>
#include <string.h>
#include <debug.h>
#include <ports.h>
#include <multitasking.h>
#include <syscall.h>
#include <video.h>
#include "include/ksyscall.h"

#define IDT_ENTRIES 256
#define IDT_FLAG_INTERRUPT_GATE 0x0E
#define IDT_FLAG_PRESENT 0x80
#define IDT_FLAG_RING0 0x00
#define IDT_FLAG_RING3 0x60

extern uint32_t tss[32];
extern process_t* current_process;

static unsigned long long tick_count = 0;

unsigned long long getTickCount()
{
	return tick_count;
}

// Zeigt an, ob der Kernel am rechnen ist oder ein Prozess.
// Damit kann entschieden werden, wo eine Exception ausgeloest wurde.
uint32_t kernel_mode = 0;

struct IDTEntry
{
	uint16_t base_lo;
	uint16_t sel;
	uint8_t be0; // IMMER = 0
	uint8_t flags;
	uint16_t base_hi;
}__attribute__((packed));

struct IDTPointer
{
	uint16_t limit;
	uint32_t base;
}__attribute__((packed));

struct IDTEntry idt_entries[256];
struct IDTPointer ip;

static void CreateInterruptDescriptor(int entry, uint64_t base,
			uint16_t sel, uint8_t flags)
{
	idt_entries[entry].base_lo = (base & 0xFFFF);
	idt_entries[entry].base_hi = (base >> 16) & 0xFFFF;
	
	idt_entries[entry].sel = sel;
	idt_entries[entry].be0 = 0;
	idt_entries[entry].flags = flags;
}

void InitInterruptDescriptors()
{
	ip.limit =  (sizeof(struct IDTEntry)*256) - 1;
	ip.base = (uint32_t) &idt_entries;
	
	memset(&idt_entries, 0, sizeof(idt_entries));
	
	// IRQ remap
	outb(0x20, 0x11);
	outb(0xA0, 0x11);
	outb(0x21, 0x20);
	outb(0xA1, 0x28);
	outb(0x21, 0x04);
	outb(0xA1, 0x02);
	outb(0x21, 0x01);
	outb(0xA1, 0x01);
	outb(0x21, 0x0);
	outb(0xA1, 0x0);
	
	
	// Exceptions
	CreateInterruptDescriptor(0, (unsigned)intr_stub_0, 0x08, 0x8E);
	CreateInterruptDescriptor(1, (unsigned)intr_stub_1, 0x08, 0x8E);
	CreateInterruptDescriptor(2, (unsigned)intr_stub_2, 0x08, 0x8E);
	CreateInterruptDescriptor(3, (unsigned)intr_stub_3, 0x08, 0x8E);
	CreateInterruptDescriptor(4, (unsigned)intr_stub_4, 0x08, 0x8E);
	CreateInterruptDescriptor(5, (unsigned)intr_stub_5, 0x08, 0x8E);
	CreateInterruptDescriptor(6, (unsigned)intr_stub_6, 0x08, 0x8E);
	CreateInterruptDescriptor(7, (unsigned)intr_stub_7, 0x08, 0x8E);

	CreateInterruptDescriptor(8, (unsigned)intr_stub_8, 0x08, 0x8E);
	CreateInterruptDescriptor(9, (unsigned)intr_stub_9, 0x08, 0x8E);
	CreateInterruptDescriptor(10, (unsigned)intr_stub_10, 0x08, 0x8E);
	CreateInterruptDescriptor(11, (unsigned)intr_stub_11, 0x08, 0x8E);
	CreateInterruptDescriptor(12, (unsigned)intr_stub_12, 0x08, 0x8E);
	CreateInterruptDescriptor(13, (unsigned)intr_stub_13, 0x08, 0x8E);
	CreateInterruptDescriptor(14, (unsigned)intr_stub_14, 0x08, 0x8E);
	CreateInterruptDescriptor(15, (unsigned)intr_stub_15, 0x08, 0x8E);

	CreateInterruptDescriptor(16, (unsigned)intr_stub_16, 0x08, 0x8E);
	CreateInterruptDescriptor(17, (unsigned)intr_stub_17, 0x08, 0x8E);
	CreateInterruptDescriptor(18, (unsigned)intr_stub_18, 0x08, 0x8E);
	
	// IRQs
	CreateInterruptDescriptor(32, (unsigned)intr_stub_32, 0x08, 0x8E);
	CreateInterruptDescriptor(33, (unsigned)intr_stub_33, 0x08, 0x8E);
	CreateInterruptDescriptor(34, (unsigned)intr_stub_34, 0x08, 0x8E);
	CreateInterruptDescriptor(35, (unsigned)intr_stub_35, 0x08, 0x8E);
	CreateInterruptDescriptor(36, (unsigned)intr_stub_36, 0x08, 0x8E);

	CreateInterruptDescriptor(37, (unsigned)intr_stub_37, 0x08, 0x8E);
	CreateInterruptDescriptor(38, (unsigned)intr_stub_38, 0x08, 0x8E);
	CreateInterruptDescriptor(39, (unsigned)intr_stub_39, 0x08, 0x8E);
	CreateInterruptDescriptor(40, (unsigned)intr_stub_40, 0x08, 0x8E);
	CreateInterruptDescriptor(41, (unsigned)intr_stub_41, 0x08, 0x8E);
	CreateInterruptDescriptor(42, (unsigned)intr_stub_42, 0x08, 0x8E);
	CreateInterruptDescriptor(43, (unsigned)intr_stub_43, 0x08, 0x8E);
	CreateInterruptDescriptor(44, (unsigned)intr_stub_44, 0x08, 0x8E);
	CreateInterruptDescriptor(45, (unsigned)intr_stub_45, 0x08, 0x8E);
	CreateInterruptDescriptor(46, (unsigned)intr_stub_46, 0x08, 0x8E);
	CreateInterruptDescriptor(47, (unsigned)intr_stub_47, 0x08, 0x8E);
	
	// Syscall
	CreateInterruptDescriptor(48, (unsigned)intr_stub_48, 0x08, 0xEE);
	
	
	__asm("lidt %0" : : "m" (ip));
}

/// Die Fehler die entstehen können
const char* errors[] =
{
	 "Division by zero exception",
	 "Debug exception",
	 "Non maskable interrupt",
	 "Breakpoint exception",
	 "Into detected overflow",
	 "Out of bounds exception",
	 "Invalid opcode exception",
	 "No coprocessor exception",
	 "Double fault",
	 "Coprocessor segment overrun",
	 "Bad TSS",
	 "Segment not present",
	 "Stack fault",
	 "General protection fault",
	 "Page fault",
	 "Unknown interrupt exception",
	 "Coprocessor fault",
	 "Alignment check exception",
	 "Machine check exception"
};

#define NUM_HANDLERS 48
static uint32_t irqHandlers[NUM_HANDLERS] = {0};
int registerHandlerProcess(int irqno, uint32_t pid)
{
	// Don't use it twice!
	if(irqHandlers[irqno]) return 0;
	
	irqHandlers[irqno] = pid;
	return 1;
}

int resetHandlerProcess(int irqno, uint32_t pid)
{
	// Only reset if the same process wants to kill it
	if(irqHandlers[irqno] == pid)
	{
		irqHandlers[irqno] = 0;
		return 1;
	}
	
	return 0;
}

void removeHandlerProcess(uint32_t pid)
{
	int i = 0;
	for(; i < NUM_HANDLERS; i++)
		if(irqHandlers[i] == pid)
			irqHandlers[i] = 0;
}

struct cpu* int_handler(struct cpu* cpu_old)
{
	//asm("cli");
	struct cpu* cpu_new = cpu_old;
	
	if(cpu_old->intr < 32)
	{
		if(cpu_old->intr == 14)
		{
			uint32_t faulting_address;
			__asm volatile("mov %%cr2, %0" : "=r" (faulting_address));
		
			int present = !(cpu_old->error & 0x1);
			int rw = cpu_old->error & 0x2;
			int us = cpu_old->error & 0x4;
			int reserved = cpu_old->error & 0x8;
			int id = cpu_old->error & 0x10;

			DebugPrintf("Page Fault: ");

			if(present)
				DebugPrintf("not present ");
			else
				DebugPrintf("protection fault ");

			if(rw)
				DebugPrintf("read access ");
			else
				DebugPrintf("write access ");

			if(us)
				DebugPrintf("usermode ");
			else
				DebugPrintf("kernelmode ");

			if(reserved)
				DebugPrintf("reserved ");

			if(id)
				DebugPrintf("instruction fetch ");

			DebugPrintf("access to 0x%x at 0x%x in process %s (%d)\n", faulting_address, cpu_old->eip, current_process->name, current_process->pid);
		}
		else
		{
			DebugPrintf("Error: %s at 0x%x in process %s (%d)\n", errors[cpu_old->intr], cpu_old->eip, current_process->name, current_process->pid);
		}
		
		// Only kernel panic if it's not a debug exceptions.
		// Those are thrown when invalid syscalls are made.
		if(kernel_mode && cpu_old->intr != 1)
			panic_cpu(errors[cpu_old->intr], cpu_old);

		//DebugPrintf("\nERROR: Process %d caused an error %d (%s) at 0x%x and will be terminated.\n", current_process->pid, 
		//	cpu_old->intr, errors[cpu_old->intr], cpu_old->eip);

		StackTrace();
		
		// Simulate signal syscall
		/*cpu_old->eax = 12;
		cpu_old->ebx = 11;
		cpu_old->ecx = -1;
		
		cpu_new = Syscall(cpu_old);*/
		cpu_new = KillCurrentProcess();
		tss[1] = (uint32_t) (cpu_new + 1);
	}
	else if (cpu_old->intr >= 0x20 && cpu_old->intr <= 0x2f)
	{
		// Timer Interrupt
		if(cpu_old->intr == 0x20)
		{
			tick_count++;
			cpu_new = Schedule(cpu_old);
			tss[1] = (uint32_t) (cpu_new + 1);
		}
		
		message_t msg;
		msg.signal = cpu_old->intr;
		if(irqHandlers[cpu_old->intr] > 0)
			ksend_message(NULL, GetProcessByPid(irqHandlers[cpu_old->intr]), &msg);
		
		// End of Interrupt zum slave controller
		if (cpu_old->intr >= 40)
		{
			outb(0xA0, 0x20);
		}
	}
	// Unser Syscall
	else if(cpu_old->intr == 0x30)
	{
		kernel_mode = 1;
		cpu_new = Syscall(cpu_old);
		tss[1] = (uint32_t) (cpu_new + 1);
	}
	else
	{
		DebugPrintf("Unknown interrupt: 0x%x\n", cpu_old->intr);
		kprintf("Unknown interrupt: 0x%x\n", cpu_old->intr);
		
		while(1);
	}

	// DebugPrintf("Continuing process %d tick %d\n", current_process->pid, getTickCount());

	
	// End of Interrupt zum master controller
	outb(0x20, 0x20);

	kernel_mode = 0;
	return cpu_new;
}

/// TODO: Mit Treibersystem verbinden!
void common_irq_handler(int irqno)
{	
	// End of Interrupt zum slave controller
	if (irqno >= 40)
	{
		outb(0xA0, 0x20);
	}
	
	// End of Interrupt zum master controller
	outb(0x20, 0x20);	
}


