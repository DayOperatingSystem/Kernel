[BITS 32]

; Multiboot header für GRUB
ALIGN 4
SECTION .mboot
mboot:
    MULTIBOOT_PAGE_ALIGN    equ 1<<0
    MULTIBOOT_MEMORY_INFO   equ 1<<1
    MULTIBOOT_AOUT_KLUDGE   equ 1<<16
    MULTIBOOT_HEADER_MAGIC  equ 0x1BADB002
    MULTIBOOT_HEADER_FLAGS  equ MULTIBOOT_PAGE_ALIGN | MULTIBOOT_MEMORY_INFO | MULTIBOOT_AOUT_KLUDGE
    MULTIBOOT_CHECKSUM  equ -(MULTIBOOT_HEADER_MAGIC + MULTIBOOT_HEADER_FLAGS)
    EXTERN code, bss, kernel_end

    dd MULTIBOOT_HEADER_MAGIC
    dd MULTIBOOT_HEADER_FLAGS
    dd MULTIBOOT_CHECKSUM

    dd mboot
    dd code
    dd bss
    dd kernel_end
    dd start

; Ruft Init() auf

SECTION .text

global start
start:
    mov esp, stack     ; Richtet den Stack ein
    jmp main


[extern init]
[extern setup_stack_chk]

main:
    call setup_stack_chk

    push esp ; kernel esp uebergeben
    push ebx ; adresse der multiboot structur als parameter übergeben.
    call init    ;Ruft init auf...
    jmp $       ;... und geht danach in eine Endlos Schleife

;Unser Stack
SECTION .bss
    resb 4096               ;4KB Speicher reservieren
stack:
