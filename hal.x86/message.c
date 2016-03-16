#include <kmessage.h>
#include <heap.h>
#include <string.h>
#include <multitasking.h>

// extern process_t* current_process;

void copy_message(message_t* dest, message_t* src)
{
	if(src == NULL || dest == NULL)
		return;
	
	dest->sender = src->sender;
	dest->receiver = src->receiver;
	dest->signal = src->signal;
	dest->size = src->size;

	memcpy((void*) dest->message, (void*) src->message,  MESSAGE_STRING_SIZE);
}

/*int ksend_message(message_t* msg, uint32_t pid)
{
	if(msg == NULL)
	{
		DebugPrintf("[ KERNEL ] MESSAGE_ERR_SEND at %s in  line %d for process %d: Message == NULL!\n", __FILE__, __LINE__, current_process->pid);
		return MESSAGE_ERR_SEND;
	}

	msg->sender = current_process->pid;
	msg->receiver = pid;

	process_t* proc = GetProcessByPid(pid);

	if(proc == NULL)
	{
		DebugPrintf("[ KERNEL ] MESSAGE_ERR_SEND at %s in  line %d for process %d: Process with PID %d not found!\n", __FILE__, __LINE__, current_process->pid, pid);
		return MESSAGE_ERR_SEND;
	}
	
	struct MESSAGE_NODE* first = proc->messages.first;
	struct MESSAGE_NODE* last = proc->messages.last;

	struct MESSAGE_NODE* newmsg = kmalloc(sizeof(struct MESSAGE_NODE));
	newmsg->next = first;
	newmsg->prev = NULL;
	first->prev = newmsg;
	
	proc->messages.first = newmsg;
	
	if(last == NULL)
		proc->messages.last = newmsg;
		
	//copy_message(&proc->messages[proc->num_messages], msg);
	
	copy_message(&newmsg->message, msg);
	//proc->num_messages++;

	return MESSAGE_SENT;
}

int kreceive_message(message_t* msg, uint32_t who)
{
	if(msg == NULL || current_process->messages.first == NULL)
	{
		//DebugPrintf("[ KERNEL ] MESSAGE_ERR_RECEIVE at %s in  line %d for process %d\n", __FILE__, __LINE__, current_process->pid);		
		return MESSAGE_ERR_RECEIVE;
	}

	struct MESSAGE_NODE* node = current_process->messages.last;
	if(!node) return MESSAGE_ERR_RECEIVE;
	
	if(who == MESSAGE_ANY)
	{
		node->prev->next = NULL;
		current_process->messages.last = node->prev;
	}
	else
	{
		
		if(node == NULL)
			return MESSAGE_ERR_RECEIVE;
	
		while(node != NULL && node->message.sender != who)
			node = node->prev;
		
		if(node->next != NULL)
			node->next->prev = node->prev;
		else
		{
			current_process->messages.last = node->prev;
			node->prev->next = NULL;
		}
		
		if(node->prev != NULL)
			node->prev->next = node->next;
		else
		{
			current_process->messages.first = node->next;
			node->next->prev = NULL;
		}
	}
	
	copy_message(msg, &node->message);
	kfree(node);
	
	return MESSAGE_RECEIVED;
}*/

int ksend_message(process_t* sender, process_t* receiver, message_t* msg)
{
	if(msg == NULL)
	{
		DebugPrintf("[ KERNEL ] MESSAGE_ERR_SEND at %s in  line %d for process %d: Message == NULL!\n", __FILE__, __LINE__, sender->pid);
		return MESSAGE_ERR_SEND;
	}

	if(receiver == NULL)
	{
		return MESSAGE_ERR_SEND;
	}
	
	//if(sender == receiver || sender->pid == receiver->pid) // FIXME: Very strange. Sometimes messages return back to the sender.
	//	return MESSAGE_ERR_SEND;

	msg->sender = (sender) ? sender->pid : 0;
	msg->receiver = receiver->pid;

	//struct MESSAGE_NODE* first = receiver->messages.first;
	//struct MESSAGE_NODE* last = receiver->messages.last;

	struct MESSAGE_NODE* newmsg = kmalloc(sizeof(struct MESSAGE_NODE));
	struct MESSAGE_NODE* node = receiver->messages.first;
	
	if(node == NULL)
		receiver->messages.first = newmsg;
	else
	{
		while(node->next != NULL)
			node = node->next;
		
		node->next = newmsg;
	}
	
	newmsg->prev = node;
	newmsg->next = NULL;
	receiver->messages.last = newmsg;
	
	// DebugPrintf("sender: %d receiver: %d msg: 0x%x\n", sender->pid, receiver->pid, msg);

	copy_message(&newmsg->message, msg);
	receiver->messages.num_messages++;

	return MESSAGE_SENT;
}

int kreceive_message(process_t* current_process, message_t* msg, uint32_t who)
{
	if(msg == NULL || current_process->messages.first == NULL)
	{
		//DebugPrintf("[ KERNEL ] MESSAGE_ERR_RECEIVE at %s in  line %d for process %d\n", __FILE__, __LINE__, current_process->pid);
		return MESSAGE_ERR_RECEIVE;
	}

	struct MESSAGE_NODE* node = current_process->messages.first;
	if(!node || current_process->messages.num_messages == 0) return MESSAGE_ERR_RECEIVE;
	
	if(who == MESSAGE_ANY)
	{
		if(node->next != NULL)
			node->next->prev = NULL;
		
		current_process->messages.first = node->next;
	}
	else
	{
		while(node != NULL && node->message.sender != who)
			node = node->next;
		
		if(node == NULL)
			return MESSAGE_ERR_RECEIVE;
		
		if(node->next != NULL)
			node->next->prev = node->prev;
		else
		{
			current_process->messages.last = node->prev;
			node->prev->next = NULL;
		}
		
		if(node->prev != NULL)
			node->prev->next = node->next;
		else
		{
			current_process->messages.first = node->next;
			node->next->prev = NULL;
		}
	}
	
	copy_message(msg, &node->message);	
	kfree(node);
	current_process->messages.num_messages--;
	
	return MESSAGE_RECEIVED;
}
