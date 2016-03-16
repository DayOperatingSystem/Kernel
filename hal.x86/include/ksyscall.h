#ifndef __KSYSCALL_H
#define __KSYSCALL_H

#include <types.h>
#include <cpu.h>

// Alle Syscalls
struct cpu* Syscall(struct cpu* cpu_old);

#endif
