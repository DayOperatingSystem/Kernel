#include <ports.h>
#include <video.h>
#include <types.h>
#include <string.h>
#include <args.h>
#include <debug.h>
#include <multitasking.h>

#define IER 1
#define IIR 2
#define FCR 2
#define LCR 3
#define MCR 4
#define LSR 5
#define MSR 6

#define COM1 0x3f8

void InitSerial(uint32_t baud, uint8_t parity, uint8_t bits)
{
	union
	{
		uint8_t b[2];
		uint16_t w;
	} divisor;
	
	divisor.w = 115200/baud;

	outb(COM1 + IER, 0x00);
	outb(COM1 + LCR, 0x80);
	outb(COM1, divisor.b[0]);
	outb(COM1 + 1, divisor.b[1]);
	outb(COM1 + LCR, ((parity & 0x7) << 3) | ((bits-5) & 0x3));
	outb(COM1 + FCR, 0xC7);
	outb(COM1 + MCR, 0x0B);
	 
}

uint8_t IsTransmitEmpty()
{
	return inb(COM1+LSR) & 0x20;
}

void SerialCharOut(char c)
{
	while(!IsTransmitEmpty());
	
	outb(COM1, c);
}

void DebugPuts(const char* msg)
{
	while(*msg)
	{
		SerialCharOut(*msg);
		msg++;
	}
}

void DebugLog(const char* msg)
{
	DebugPuts(msg);	
	SerialCharOut('\n');
}

void StackTrace()
{
	void** ebp = 0;
	__asm("mov %%ebp, %0":"=a"(ebp));
	
	DebugLog("Stack trace:");	
	while(ebp)
	{
		DebugPrintf("0x%x\n", (uint32_t) ebp[1]);
		ebp = (void**) ebp[0];
	}
}

extern process_t* current_process;
void kassert(const char* msg)
{
	DebugPrintf("Assertion failed while process %d was running!\n", current_process->pid);
	DebugLog(msg);
	StackTrace();

	kprintln(msg);
	kprintln("Kernel panic!");
	while(1);
}

void kpanic(const char* expression, const char* message)
{
	DebugLog(message);
	DebugLog(expression);
	
	StackTrace();
	
	kprintf("%s, %s\n", message, expression);
	kprintln("Kernel panic!");
	
	__asm("cli");
	__asm("hlt");
	
	while(1);
}

void kpanic_cpu(const char* expression, const char* message, struct cpu* old_cpu)
{
	DebugLog("Register dump:");
	DebugPrintf("EIP: 0x%x\n", old_cpu->eip);
	DebugPrintf("ESP: 0x%x\n", old_cpu->esp);
	DebugPrintf("EBP: 0x%x\n", old_cpu->ebp);
	
	kpanic(expression, message);
}

void dbgputn(uint32_t x, int base)
{
	char buf[65];
	const char* digits = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	char* p;
	if(base > 36)
	{
		return;
	}

	memset(buf, 0, 64);

	p = buf + 64;
	*p = '\0';
	do
	{
		*--p = digits[x % base];
		x /= base;
	} while(x);
		
	DebugPuts(p);
	
	/*int i = 0;
	char str[128];
	while (x != 0)
	{
		int rem = x % base;
		str[i++] = (rem > 9)? (rem - 10) + 'A' : rem + '0';
		x = x/base;
	}
  
	for(int j = i-1; j >= 0; j--)
		SerialCharOut(str[j]);*/
}

void DebugPrintf(const char* fmt, ...)
{
	va_list ap;
	const char* s;
	unsigned long n;

	va_start(ap, fmt);
	while (*fmt) 
	{
		if (*fmt == '%') 
		{
			fmt++;
			switch (*fmt) 
			{
				case 's':
					s = va_arg(ap, const char*);
					DebugPuts(s);
					break;
				case 'c':
					n = va_arg(ap, int);
					SerialCharOut(n);
					break;
				case 'd':
				case 'u':
					n = va_arg(ap, unsigned long int);
					dbgputn(n, 10);
					break;
				case 'x':
				case 'p':
					n = va_arg(ap, unsigned long int);
					dbgputn(n, 16);
					break;
				case 'l':
					switch(fmt[1])
					{
						case 'd':
							fmt++;
							n = va_arg(ap, long int);
							dbgputn(n, 10);
							break;							
					}
					break;
				case '%':
					SerialCharOut('%');
					break;
				case '\0':
					goto out;
				default:
					SerialCharOut('%');
					SerialCharOut(*fmt);
					break;
			}
		} 
		else 
		{
			SerialCharOut(*fmt);
		}
		fmt++;
	}

out:
	va_end(ap);
}

void UnifiedPrintf(const char* fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	DebugPrintf(fmt, ap);
	kprintf(fmt, ap);
	va_end(ap);
}
