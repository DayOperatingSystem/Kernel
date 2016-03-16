#include "ports.h"

/* Schreibt ein byte in einen Port */

void outb(unsigned short port, unsigned char value)
{
	__asm volatile ("outb %1, %0" : : "dN" (port), "a" (value));
}

/* Liest einen byte aus einem Port */

unsigned char inb(unsigned short port)
{
   unsigned char ret;
   __asm volatile("inb %1, %0" : "=a" (ret) : "dN" (port));
   return ret;
}

