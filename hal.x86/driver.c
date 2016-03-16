#include <driver.h>
#include <ramdisk.h>
#include <elf.h>
#include <multitasking.h>
#include <vmm.h>
#include <stdint.h>

void create_driver_process(const char* path)
{
	uintptr_t program = (uintptr_t) RamDiskFileContent(path);
	
	vmm_context_t* context = CreateUsermodeContext(1);
	function_t entry = ParseElf(program, context);
	
	CreateUserProcess(entry, context);
}

void InitBootDrivers()
{
	
	//create_driver_process("./init.elf");
	// VFS process
	/*create_driver_process("./vfs.elf");
	
	// FDC driver
	create_driver_process("./system/fdc.drv");

	// FAT driver
	create_driver_process("./system/fat.drv");
	
	// TTY driver
	create_driver_process("./system/tty.drv");
	
	// SHELL!
	create_driver_process("./shell.elf");*/
}
