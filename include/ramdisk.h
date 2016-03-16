#ifndef RAMDISK_H
#define RAMDISK_H

#include <types.h>

void InitRamdisk(uintptr_t addr);
uintptr_t RamDiskFileContent(const char* name);

#endif
