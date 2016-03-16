#ifndef ARCH_H
#define ARCH_H

// CPU Architecture herausfinden
#ifdef __i386__
#define ARCH_X86

typedef struct __attribute__((packed))
{
	unsigned short di, si, bp, sp, bx, dx, cx, ax;
	unsigned short gs, fs, es, ds, eflags;
} regs16_t;

// Syscall
#define SYSCALL_DPUTC 1
#define SYSCALL_EXIT 2
#define SYSCALL_SEND_MESSAGE 3
#define SYSCALL_RECEIVE_MESSAGE 4
#define SYSCALL_SBRK 5
#define SYSCALL_REGISTER_ISR 6
#define SYSCALL_REMOVE_ISR 7
#define SYSCALL_SET_TIMER 8
#define SYSCALL_EXECUTE_ELF 9
#define SYSCALL_VERSION 10
#define SYSCALL_REGISTER_SIGNAL_HANDLER 11
#define SYSCALL_SIGNAL_RAISE 12
#define SYSCALL_REQUEST_MEMORY_RANGE 13
#define SYSCALL_WAITPID 14
#define SYSCALL_GET_TICKS 15

#define SYSCALL_WRITE_PORT 17
#define SYSCALL_READ_PORT 18
#define SYSCALL_GET_PID 19
#define SYSCALL_GET_PARENT_PID 20
#define SYSCALL_FORK 21

// Platform specific!
#define SYSCALL_BIOS_INT 16

#endif // __i386__
#endif // ARCH_H
