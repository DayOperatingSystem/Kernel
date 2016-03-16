#ifndef TYPES_H
#define TYPES_H

/*
  In dieser Datei werden die Grundlegenden Datentypen die verwendet werden definiert.
*/

typedef unsigned long long   uint64_t;
typedef unsigned int   uint32_t;
typedef		  int   sint32_t;
typedef unsigned short uint16_t;
typedef		  short sint16_t;
typedef unsigned char  uint8_t;
typedef		  char  sint8_t;
typedef uint32_t uintptr_t;

typedef __SIZE_TYPE__ size_t;

#define PACKED __attribute__((packed))

#ifndef NULL
#define NULL 0
#endif

// Ein funktionspointer
typedef void (*function)(void);

#endif
