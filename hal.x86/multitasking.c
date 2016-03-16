#include <multitasking.h>
#include <video.h>
#include <heap.h>
#include <idt.h>
#include <string.h>

// Linked list
process_t* first_process = NULL;
process_t* current_process = NULL;
process_t* idle_process = NULL;
uint32_t num_proc = 0;

// Kernel process
void kernel_process();

void idle()
{
	// Stop processor to save power
	while(1) 
	{
		//DebugPrintf("Halting CPU...\n");
		asm("hlt");
	}
}
 
process_t* CreateKernelProcess(void (*entry)())
{
	uint8_t* stack = (uint8_t*) kmalloc(4096);
	process_t* process = kmalloc(sizeof(process_t));
	
	assert(stack != NULL);
	assert(process != NULL);
	
	process->stack = stack;
	process->sleep_timer = 0;
	process->status = PROCESS_RUNNABLE;
	process->signal = 0;
	
	struct cpu new_state = 
	{
		.eax = 0,
		.ebx = 0,
		.ecx = 0,
		.edx = 0,
		.esi = 0,
		.edi = 0,
		.ebp = 0,
		.esp = (uint32_t) (stack + 4096),

		.eip = (uint32_t) entry,
		 
		.cs = 0x08,
		.ds = 0x10,
		.es = 0x10,
		.fs = 0x10,
		.gs = 0x10,
		.ss = 0x10,
		.eflags = 0x202,
	};
	
	struct cpu* state = (void*) (stack + 4096 - sizeof(new_state));
	*state = new_state;
	
	process->state = state;
	
	process->next = first_process;
	first_process = process;
	
	process->pid = num_proc;
	process->context = CreateUsermodeContext(1);
	process->sbrk_state = 0;
	process->uid = ROOT_UID;
	
	process->messages.num_messages = 0;
	process->messages.first = NULL;
	process->messages.last = NULL;
	
	num_proc++;
	return process;
}

process_t* CreateUserProcess(void (*entry)(), vmm_context_t* context)
{
	uint8_t* stack = kmalloc(4096);
	uint8_t* user_stack = (uint8_t*) USERSPACE_PAGEPOOL;
	process_t* process = kmalloc(sizeof(process_t));
	
	assert(stack != NULL);
	assert(user_stack != NULL);
	assert(process != NULL);
	
	process->stack = stack;
	process->user_stack = user_stack;
	process->sleep_timer = 0;
	process->status = PROCESS_RUNNABLE;
	process->signal = 0;
	
	struct cpu new_state = 
	{
		.eax = 0,
		.ebx = 0,
		.ecx = 0,
		.edx = 0,
		.esi = 0,
		.edi = 0,
		.ebp = 0,
		.esp = (uint32_t) (user_stack + 4096),

		.eip = (uint32_t) entry,
		 
		.cs = 0x18 | 0x03,
		.ds = 0x20 | 0x03,
		.es = 0x20 | 0x03,
		.fs = 0x20 | 0x03,
		.gs = 0x20 | 0x03,
		.ss = 0x20 | 0x03,
		.eflags = 0x202,
	};

	struct cpu* state = (void*) (stack + 4096 - sizeof(new_state));
	*state = new_state;
	
	process->state = state;
	
	process->next = first_process;
	first_process = process;
	
	process->parent = current_process->pid;
	process->pid = num_proc;
	process->context = context;
	
	process->messages.num_messages = 0;
	process->messages.first = NULL;
	process->messages.last = NULL;
	
	vmm_alloc(process->context, (uintptr_t) process->user_stack, PAGESIZE);
	process->sbrk_state = PAGESIZE; // Because the stack starts at USERSPACE_PAGEPOOL and is thus part of the "heap"

	// Check if a process is currently running
	// Every child process inherits the UID of its parent
	if(current_process != NULL)
		process->uid = current_process->uid;
	else
		process->uid = 0;
	
	num_proc++;	
	return process;
}

void PseudoFork(process_t* parent)
{
	uint8_t* stack = kmalloc(4096);
	process_t* child = kmalloc(sizeof(process_t));

	memcpy(stack, parent->stack, 4096);
	child->stack = stack;
	child->state = (void*) (stack + 4096 - sizeof(struct cpu));

	child->next = first_process;
	first_process = child;
	
	child->parent = parent->pid;
	child->pid = num_proc;
	child->context = vmm_clone_context(parent->context);
	
	child->messages.num_messages = 0;
	child->messages.first = NULL;
	child->messages.last = NULL;

	child->state->eax = 0;
	parent->state->eax = child->pid;
	
	num_proc++;
}

struct cpu* Schedule(struct cpu* cpu_old)
{
	unsigned int oldPid = -1;
	
	if(current_process != NULL)
		current_process->state = cpu_old;
	
	if(current_process == NULL)
		current_process = first_process;
	else
	{
		current_process = current_process->next;
			
		if(current_process == NULL)
			current_process = first_process;
		
		// Will wait here for some process to pop up
		while(current_process->status != PROCESS_RUNNABLE)
		{
			if(current_process->sleep_timer > 0 && current_process->sleep_timer <= getTickCount())
			{
				current_process->status = PROCESS_RUNNABLE;
				current_process->sleep_timer = 0;
				break;
			}
			
			current_process = current_process->next;
			
			if(current_process == NULL)
			{
				current_process = idle_process;
				break;
			}
		}
		//if(current_process == NULL && first_process->status != PROCESS_RUNNABLE)	
	}

	// Ein neuer Prozess wurde auserwählt und bekommt nun sein pagedir eingerichtet
	if(oldPid != current_process->pid)
		activate_memory_context(current_process->context);
	
	//DebugPrintf("Chose process with stack: 0x%x pid = %d\n", current_process->state, current_process->pid);
	return current_process->state;
}

struct cpu* KillCurrentProcess()
{
	KillProcess(current_process);
	
	current_process = NULL;
	return Schedule(NULL);
}

extern void copy_message(message_t* dest, message_t* src);

void copy_process(process_t* dest, process_t* src)
{
/*	dest->state = src->state;
	dest->pid = src->pid;
	
	int i;
	for(i = 0; i < MESSAGE_BUFFER_SIZE; i++)
	{
		copy_message(&dest->messages[i], &src->messages[i]);
	}

	dest->num_messages = src->num_messages;

	dest->next = src->next;*/
}

void KillProcess(process_t* process)
{
	process_t* proc = first_process;
	
	// Check for the first process
	if(proc->pid == process->pid)
	{
		// Handle waitpid
		process_t* parent = GetProcessByPid(proc->parent);
		if(parent->status == PROCESS_WAITPID 
			&& (parent->waitpid_param == proc->pid || parent->waitpid_param == -1))
		{
			parent->status = PROCESS_RUNNABLE;
			parent->state->eax = process->pid;
		}
		
		// Destroy process
		first_process = process->next;
		destroy_context(process->context);
		
		kfree(process->stack);
		kfree(process);
		return;
	}
	
	while(proc != NULL)
	{
		if(proc->next->pid == process->pid)
		{
			// Handle waitpid
			process_t* parent = GetProcessByPid(process->parent);
			if(parent->status == PROCESS_WAITPID 
				&& (parent->waitpid_param == proc->pid || parent->waitpid_param == -1))
			{
				parent->status = PROCESS_RUNNABLE;
				parent->state->eax = process->pid;
			}
			
			destroy_context(process->context);
			proc->next = process->next;
			kfree(process->stack);
			kfree(process);
			return;
		}
		proc = proc->next;
	}
	
	DebugPrintf("Could not kill process %d", process->pid);
}

process_t* GetProcessByPid(uint32_t pid)
{
	process_t* proc = first_process;
	
	while(proc != NULL)
	{
		if(proc->pid == pid)
			return proc;

		proc = proc->next;
	}

	return NULL;
}

extern void ramdisk_process();
#include <ramdisk.h>
#include <elf.h>

process_t* LoadFromRamdisk(const char* path)
{
	uintptr_t program = (uintptr_t) RamDiskFileContent(path);
	
	vmm_context_t* context = CreateUsermodeContext(1);
	function_t entry = ParseElf(program, context);
	
	return CreateUserProcess(entry, context);
}

void InitMultitasking()
{
	strcpy(CreateKernelProcess(kernel_process)->name, "kernel");
	idle_process = CreateKernelProcess(idle);
	strcpy(idle_process->name, "idle");
	
	strcpy(CreateKernelProcess(ramdisk_process)->name, "roramdisk");

	strcpy(LoadFromRamdisk("./init.elf")->name, "init");
	strcpy(LoadFromRamdisk("./vfs.elf")->name, "vfs");
	
	idle_process->status = PROCESS_PAUSED;
}

void ListProcesses()
{
	process_t* proc = first_process;
	while(proc != NULL)
	{
		DebugPrintf("Process: %s (%d)\n", proc->name, proc->pid);
		proc = proc->next;
	}
}
