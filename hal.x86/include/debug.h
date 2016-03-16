#ifndef DEBUG_H
#define DEBUG_H

#include "types.h"
#include "cpu.h"

void kassert(const char* msg);
void kpanic(const char* expression, const char* message);
void kpanic_cpu(const char* expression, const char* message, struct cpu* old_cpu);

void DebugLog(const char* msg);
void DebugPrintf(const char* fmt, ...);
void UnifiedPrintf(const char* fmt, ...);
void InitSerial(uint32_t baud, uint8_t parity, uint8_t bits);
void StackTrace();

#define __symbol2value( x ) #x
#define __symbol2string( x ) __symbol2value( x )

#define assert(expression) if(!(expression)) kassert("Assertion failed: " \
						"(" #expression ")" \
						", in file " __FILE__ \
						" at line " __symbol2string(__LINE__))

#define panic(expression) kpanic(expression, "Kernel Panic in file " __FILE__ " at line " __symbol2string(__LINE__))

#define panic_cpu(expression, cpu) kpanic_cpu(expression, "Kernel Panic in file " __FILE__ " at line " __symbol2string(__LINE__), cpu)

#endif
