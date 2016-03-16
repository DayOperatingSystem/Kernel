
ENTRY(start)

mb = 0x100000;
phys = 0x100400;

SECTIONS
{  
/DISCARD/ :
{
   *(.note*)
}

  . = mb;
  kernel_start = ALIGN(4096);
 
   .mboot mb : AT(mb) {
	*(.mboot)
  }
 
 .text phys : AT(phys) {
    code = .;
    *(.text)   

    . = ALIGN(4096);
  } 
  
.rodata ALIGN(4096) :
	{
		start_ctors = .;
		*(.ctor*)
		end_ctors = .;

		start_dtors = .;
		*(.dtor*)
		end_dtors = .;

		*(.rodata*)
		*(.gnu.linkonce.r*)
	}

  .data : AT(phys + (data - code))
  {
    data = .;
    *(.data)
    . = ALIGN(4096);
  }
  .bss : AT(phys + (bss - code))
  {
    bss = .;
    *(.bss)
    . = ALIGN(4096);
  }
  kernel_end = ALIGN(4096);
}
