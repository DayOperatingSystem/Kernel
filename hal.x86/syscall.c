#include <syscall.h>
#include <multitasking.h>
#include <debug.h>
#include <video.h>
#include <message.h>
#include <vmm.h>
#include <idt.h>
#include <elf.h>
#include <kmessage.h>
#include <heap.h>
#include <sys/utsname.h>
#include <string.h>
#include <arch.h>

// Gets true if the pointer is valid. 
// FIXME: NOT PERFECT: THE KERNEL HEAP IS STILL ACCESSIBLE!
#define CHECK_POINTER(p) (((uintptr_t)(p) > PAGEPOOL_END))

extern void int32 (unsigned char intnum, regs16_t *regs);

extern vmm_context_t* kernel_context;

// TODO: Syscalls einrichten
struct cpu* Syscall(struct cpu* cpu_old)
{
	switch(cpu_old->eax)
	{
	// putch
	case SYSCALL_DPUTC: 
		// kputch((char) cpu_old->ebx);
		DebugPrintf("%c", (char) cpu_old->ebx);
		break;
	// exit
	case SYSCALL_EXIT:
		DebugPrintf("[ SYSCALL ] Process %d wants to exit with code %d\n", current_process->pid, cpu_old->ebx);
		cpu_old = KillCurrentProcess();
		
		//DebugPrintf("Current process is now: %d %x\n", current_process->pid, cpu_old);
		break;

	// send_message
	case SYSCALL_SEND_MESSAGE: {
			message_t* msg = (message_t*) cpu_old->ebx;
			
			if(!CHECK_POINTER(cpu_old->ebx))
			{
				DebugPrintf("[ SYSCALL ] Invalid pointer to 0x%x caught!\n", cpu_old->ebx);
				asm("int $0x1");
				break;
			}
			
			process_t* proc = GetProcessByPid(msg->receiver);
			cpu_old->eax = ksend_message(current_process, proc, msg);
		}		
		break;

	// receive_message
	case SYSCALL_RECEIVE_MESSAGE: {
			message_t* msg = (message_t*) cpu_old->ebx;
		
			if(!CHECK_POINTER(cpu_old->ebx))
			{
				DebugPrintf("[ SYSCALL ] Invalid pointer to 0x%x caught!\n", cpu_old->ebx);
				asm("int $0x1");
				break;
			}
			
			cpu_old->eax = kreceive_message(current_process, msg, cpu_old->ecx);
		}
		break;
	
	// sbrk
	case SYSCALL_SBRK: {
			if((int) cpu_old->ebx < 0)
			{
				DebugLog("[ SYSCALL ] Can't sbrk process!");
				cpu_old->eax = -1;
				break;
			}

			// FIXME: Limit fuer sbrk einfuehren, sonst kann jeder Prozess alles an Speicher haben!
			// FIXME: Auf 4k boundary prüfen!
			vmm_alloc(current_process->context, USERSPACE_PAGEPOOL + current_process->sbrk_state , cpu_old->ebx);
			cpu_old->eax = USERSPACE_PAGEPOOL + current_process->sbrk_state;

			current_process->sbrk_state += cpu_old->ebx;
			
			// DebugLog("[ SYSCALL ] Got memory for process!");
		}
		break;
		
	// register_irq
	case SYSCALL_REGISTER_ISR:
		if(current_process->uid != ROOT_UID)
		{
			DebugPrintf("[ SYSCALL ] Process with UID %d tried to request an IRQ handler! Access denied!\n", current_process->uid);
			break;
		}
		
		registerHandlerProcess(cpu_old->ebx, current_process->pid);
		break;
	case SYSCALL_REMOVE_ISR:
		if(current_process->uid != ROOT_UID)
		{
			DebugPrintf("[ SYSCALL ] Process with UID %d tried to request the deletion of an IRQ handler! Access denied!\n", current_process->uid);
			break;
		}
		
		resetHandlerProcess(cpu_old->ebx, current_process->pid);
		break;
	
	// set_timer
	case SYSCALL_SET_TIMER:
		// DebugPrintf("Setting timer for process %d to %d\n", current_process->pid, getTickCount() + cpu_old->ebx);
		
		current_process->sleep_timer = getTickCount() + cpu_old->ebx;
		current_process->status = PROCESS_SLEEPING;
		cpu_old = Schedule(cpu_old);
		break;
	
	// launch_elf_program ebx == ELF image ecx == name
	case SYSCALL_EXECUTE_ELF: {
		
		if(!CHECK_POINTER(cpu_old->ebx))
		{
			DebugPrintf("[ SYSCALL ] Invalid pointer to 0x%x caught!\n", cpu_old->ebx);
			asm("int $0x1");
			break;
		}
		
		if(!CHECK_POINTER(cpu_old->ecx))
		{
			DebugPrintf("[ SYSCALL ] Invalid pointer to 0x%x caught!\n", cpu_old->ecx);
			asm("int $0x1");
			break;
		}
		
		vmm_context_t* context = CreateUsermodeContext(0);
		function_t entry = ParseElf(cpu_old->ebx, context);
		
		if(entry == NULL)
		{
			DebugLog("[ SYSCALL ] Could not load ELF-Image!");
			break;
		}
		
		process_t* newproc = CreateUserProcess(entry, context);
		strncpy(newproc->name, (const char*) cpu_old->ecx, sizeof(newproc->name));
		cpu_old->eax = newproc->pid;
	}
	break;
	
	// Get version information
	case SYSCALL_VERSION: {
		if(!CHECK_POINTER(cpu_old->ebx))
		{
			DebugPrintf("[ SYSCALL ] Invalid pointer to 0x%x caught!\n", cpu_old->ebx);
			asm("int $0x1");
			break;
		}
		
		struct utsname* data = (struct utsname*) cpu_old->ebx;
		strncpy(data->sysname, DAYOS_SYSNAME, sizeof(data->sysname));
		strncpy(data->release, DAYOS_RELEASE, sizeof(data->release));
		strncpy(data->version, DAYOS_VERSION, sizeof(data->version));
		strncpy(data->machine, DAYOS_ARCH, sizeof(data->machine));
		
		cpu_old->eax = 0;
	}
	break;
	
	// register signal handler
	case SYSCALL_REGISTER_SIGNAL_HANDLER: {
		if(!CHECK_POINTER(cpu_old->ebx))
		{
			DebugPrintf("[ SYSCALL ] Invalid pointer to 0x%x caught!\n", cpu_old->ebx);
			asm("int $0x1");
			break;
		}
		
		current_process->signal = cpu_old->ebx;
	}
	break;
	
	// raise signal for process
	case SYSCALL_SIGNAL_RAISE: {
		// Send signal to running process
		if(cpu_old->ecx == -1)
		{
			cpu_old->ecx = cpu_old->eip;
			cpu_old->eip = current_process->signal;
			cpu_old->eax = cpu_old->ebx;
		}
		else // Send signal to other process
			// FIXME: Check privs!
		{
			process_t* proc = GetProcessByPid(cpu_old->ecx);
			if(proc)
			{
				proc->state->ecx = proc->state->eip;
				proc->state->eip = proc->signal;
				proc->state->eax = cpu_old->ebx;
			}
		}
	}
	break;
	
	case SYSCALL_REQUEST_MEMORY_RANGE: {
		uintptr_t addr = cpu_old->ecx;
		if(current_process->uid != 0 
			|| !CHECK_POINTER(cpu_old->ebx) 
			|| (addr >= HEAP_START && addr <= HEAP_END)
			|| cpu_old->edx <= 0)
		{
			DebugPrintf("Operation not permitted for process %d\n", current_process->pid);
			asm("int $0x1");
			break;
		}

		map_range(current_process->context, addr, addr, cpu_old->edx, 1);
	}
	break;
	
	// waitpid
	case SYSCALL_WAITPID: {
		current_process->status = PROCESS_WAITPID;
		current_process->waitpid_param = cpu_old->ebx;
		cpu_old = Schedule(cpu_old);
	}
	break;

	// get tick count
	case SYSCALL_GET_TICKS: {
		cpu_old->eax = getTickCount();
	}
	break;

	// BIOS interrupt
	case SYSCALL_BIOS_INT:
	{
		regs16_t* regs = (regs16_t*) cpu_old->ecx;
		if (current_process->uid != 0 || !CHECK_POINTER(regs))
		{
			DebugPrintf("[ SYSCALL ] Process %d tried to execute the BIOS "
						"interrupt 0x%x without having enough rights.\n"
						"Terminating process.\n",
						current_process->pid, cpu_old->ebx);

			asm("int $0x1");
			break;
		}

		int32(cpu_old->ebx, regs);
	}
	break;
	
	case SYSCALL_READ_PORT: {
		if(current_process->uid != 0)
		{
			asm("int $0x1");
		}
		
		switch(cpu_old->ecx)
		{
			case 1: {
				int8_t result;
				asm volatile("inb %1, %0" : "=a"((int8_t) result) : "dN"((uint16_t) cpu_old->ebx));				
				cpu_old->eax = result;
			}
			break;
			
			case 2: {
				int16_t result;
				asm volatile("inw %1, %0" : "=a"((int16_t) result) : "dN"((uint16_t) cpu_old->ebx));
				cpu_old->eax = result;
			}
			break;
			
			case 4: {
				int32_t result;
				asm volatile("inl %1, %0" : "=a"(result) : "dN"((uint16_t) cpu_old->ebx));
				cpu_old->eax = result;
			}
			break;
		}
	}
	break;
	
	case SYSCALL_WRITE_PORT: {
		if(current_process->uid != 0)
		{
			asm("int $0x1");
		}
		
		switch(cpu_old->ecx)
		{
			case 1:
			asm volatile("outb %1, %0" : : "dN"((uint16_t)cpu_old->ebx), "a"((int8_t)cpu_old->edx));
			break;
			
			case 2:
			asm volatile("outw %1, %0" : : "dN"((uint16_t)cpu_old->ebx), "a"((int16_t)cpu_old->edx));
			break;
			
			case 4:
			asm volatile("outl %1, %0" : : "dN"((uint16_t)cpu_old->ebx), "a"((int32_t)cpu_old->edx));
			break;
		}
	}
	break;

	case SYSCALL_GET_PID:
		cpu_old->eax = current_process->pid;
	break;

	case SYSCALL_GET_PARENT_PID:
		cpu_old->eax = current_process->parent;
	break;

	default: DebugPrintf("[ SYSCALL ] Unknown syscall 0x%x from %d\n", cpu_old->eax, current_process->pid);
	}
	
	return cpu_old;
}
