#include <pit.h>
#include <ports.h>

void InitPit(int freq)
{
	int divisor = 1193180 / freq;
	outb(0x43, 0x36);
	outb(0x40, divisor & 0xFF);
	outb(0x40, divisor >> 8);
}
