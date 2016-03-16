#ifndef __KMESSAGE_H
#define __KMESSAGE_H

#include <types.h>
#include "../../sys/kernelconfig.h"

#define MESSAGE_ERR_SEND 1
#define MESSAGE_SENT 0
#define MESSAGE_RECEIVED 0
#define MESSAGE_ERR_RECEIVE 2

#define MESSAGE_ANY -1

typedef struct process_struct process_t;

typedef struct message
{
	uint32_t sender;
	uint32_t receiver;

	uint32_t size;

	int signal;
	char message[MESSAGE_STRING_SIZE];

	struct message* next;
} message_t;

struct message_queue
{
	message_t* first;
	int num;
};

int kreceive_message(process_t* current_process, message_t* msg, uint32_t who);
int ksend_message(process_t* sender, process_t* receiver, message_t* msg);

#endif
