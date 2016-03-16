#include <video.h>
#include <string.h>
#include <args.h>
#include <ports.h>
#include <debug.h>

/**** GLOBAL VARIABLES ****/
char* buffer = (char*) 0xB8000;
char color = (char) 15;
int x = 0;
int y = 0;

/**** FUNCTIONS ****/

void UpdateCursor()
{
	unsigned temp;

	temp = y * 80 + x;

	outb(0x3D4, 14);
	outb(0x3D5, temp >> 8);
	outb(0x3D4, 15);
	outb(0x3D5, temp);
}

static void scroll()
{
	if (y > 24)
	{
		int i;
		for (i = 0; i < 2 * 27 * 80; i++)
		{
			buffer[i] = buffer[i + 160];
		}

		for (; i < 2 * 25 * 80; i++)
		{
			buffer[i] = 0;
		}
		y--;
	}
} 

void cls()
{
	int i;
	for (i = 0; i < 2 * 25 * 80; i = i+2)
	{
		buffer[i] = 0;
		buffer[i+1] = color;
	}

	x = y = 0;
	UpdateCursor();
}

void kputch(char c)
{   
	switch(c)
	{
		case '\n': {x = 0; y++; scroll(); UpdateCursor(); return; }
		break;

		case '\b': { x--; buffer[2 * (y * 80 + x)] = 0; UpdateCursor(); return;}
		break;
	}


	buffer[2 * (y * 80 + x)] = c;
	buffer[2 * (y * 80 + x) + 1] = color;
	
	x++;
		
	if(x >= 80)
	{
		x = 0;
		y++;
	}
	
	scroll();
	UpdateCursor();
}

void kputs(const char* str)
{
	// Alle Zeichen ausgeben
	while(*str)
	{
		kputch(*str);
		str++;
	}
}

void kputn(unsigned int x, int base)
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
		
	kputs(p);		
}

void kprintln(const char* str)
{
	kputs(str);
	kputch('\n');
}

void kprintf(const char* fmt, ...)
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
					kputs(s);
					break;
				case 'c':
					n = va_arg(ap, int);
					kputch(n);
					break;
				case 'd':
				case 'u':
					n = va_arg(ap, unsigned long int);
					kputn(n, 10);
					break;
				case 'x':
				case 'p':
					n = va_arg(ap, unsigned long int);
					kputn(n, 16);
					break;
				case 'l':
					switch(fmt[1])
					{
						case 'd':
							fmt++;
							n = va_arg(ap, long int);
							kputn(n, 10);
							break;							
					}
					break;
				case '%':
					kputch('%');
					break;
				case '\0':
					goto out;
				default:
					kputch('%');
					kputch(*fmt);
					break;
			}
		} 
		else 
		{
			kputch(*fmt);
		}
		fmt++;
	}

out:
	va_end(ap);
}
