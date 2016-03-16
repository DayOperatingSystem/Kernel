#ifndef PORTS_H
#define PORTS_H

#include "types.h"

/* Schreibt ein byte in einen Port */

void outb(unsigned short port, unsigned char value);

/* Liest einen byte aus einem Port */

unsigned char inb(unsigned short port);


#endif
