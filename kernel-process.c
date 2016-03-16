#include <types.h>
#include <message.h>
#include <debug.h>
#include <video.h>
#include <heap.h>
#include <string.h>
#include <ramdisk.h>
#include <syscall.h>
#include <sleep.h>

typedef struct service
{
	uint32_t pid;
	char name[255];

	struct service* next;
}service_t;

service_t* service_start = NULL;

void kernel_process()
{
	// TODO: libkernel
	//syscall1(9, RamDiskFileContent("./vfs.elf"));
	//syscall1(9, RamDiskFileContent("./init.elf"));
	
	message_t msg;
	while(1)
	{
		while(receive_message(&msg, MESSAGE_ANY) == MESSAGE_ERR_RECEIVE) sleep(10);
		
		if(msg.sender == 0)
			continue; 
		
		switch(msg.signal)
		{
		// Register service
		case 1: {
				service_t* new_service = kmalloc(sizeof(service_t));
				new_service->pid = msg.sender;
				strcpy(new_service->name, msg.message);
				
				new_service->next = service_start;
				service_start = new_service;
				
				DebugPrintf("[ KERNEL ] Registering service '%s' for %d\n", msg.message, msg.sender);

				
				// FIXME: Check rights and stuff!
				msg.signal = SIGNAL_OK;
				send_message(&msg, msg.sender);
			}
		break;
		
		// Get service PID
		case 2: {
				//DebugPrintf("[ KERNEL ] Sending service info for service '%s' to %d\n", msg.message, msg.sender);

				service_t* service = service_start;
				while(service != NULL)
				{
					if(!strcmp(service->name, msg.message))
					{
						break;
					}
					service = service->next;
				}
				
				if(service != NULL)
				{
				//	DebugPrintf("[ KERNEL ] Found service with pid %d\n", service->pid);
					
					msg.signal = service->pid;
					send_message(&msg, msg.sender);
				}
				else
				{
					msg.signal = 0;
					send_message(&msg, msg.sender);
				}
			}
			
		break;
		
		// Remove service
		case 3:
			DebugLog("[ KERNEL ] Remove service is not yet implemented!");
		break;
		}
	}
}
