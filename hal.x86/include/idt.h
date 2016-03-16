#ifndef IDT_H
#define IDT_H

#include <types.h>
#include <cpu.h>

void InitInterruptDescriptors();

/// Interrupt stubs in isr.asm
extern void intr_stub_0(void);
extern void intr_stub_1(void);
extern void intr_stub_2(void);
extern void intr_stub_3(void);
extern void intr_stub_4(void);
extern void intr_stub_5(void);
extern void intr_stub_6(void);
extern void intr_stub_7(void);
extern void intr_stub_8(void);
extern void intr_stub_9(void);
extern void intr_stub_10(void);
extern void intr_stub_11(void);
extern void intr_stub_12(void);
extern void intr_stub_13(void);
extern void intr_stub_14(void);
extern void intr_stub_15(void);
extern void intr_stub_16(void);
extern void intr_stub_17(void);
extern void intr_stub_18(void);

extern void intr_stub_32(void);
extern void intr_stub_33(void);
extern void intr_stub_34(void);
extern void intr_stub_35(void);
extern void intr_stub_36(void);
extern void intr_stub_37(void);
extern void intr_stub_38(void);
extern void intr_stub_39(void);
extern void intr_stub_40(void);
extern void intr_stub_41(void);
extern void intr_stub_42(void);
extern void intr_stub_43(void);
extern void intr_stub_44(void);
extern void intr_stub_45(void);
extern void intr_stub_46(void);
extern void intr_stub_47(void);
extern void intr_stub_48(void);
extern void intr_stub_127(void);

int registerHandlerProcess(int irqno, uint32_t pid);
int resetHandlerProcess(int irqno, uint32_t pid);
void removeHandlerProcess(uint32_t pid);

unsigned long long getTickCount();

#endif
