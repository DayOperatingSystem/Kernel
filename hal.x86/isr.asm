EXTERN int_handler

; Exceptions
GLOBAL intr_stub_0
intr_stub_0:
    push 0
    push 0
    jmp intr_common_handler

GLOBAL intr_stub_1
intr_stub_1:
    push 0
    push 1
    jmp intr_common_handler

GLOBAL intr_stub_2
intr_stub_2:
    push 0
    push 2
    jmp intr_common_handler

GLOBAL intr_stub_3
intr_stub_3:
    push 0
    push 3
    jmp intr_common_handler

GLOBAL intr_stub_4
intr_stub_4:
    push 0
    push 4
    jmp intr_common_handler

GLOBAL intr_stub_5
intr_stub_5:
    push 0
    push 5
    jmp intr_common_handler

GLOBAL intr_stub_6
intr_stub_6:
    push 0
    push 6
    jmp intr_common_handler

GLOBAL intr_stub_7
intr_stub_7:
    push 0
    push 7
    jmp intr_common_handler

GLOBAL intr_stub_8
intr_stub_8:
    push 8
    jmp intr_common_handler

GLOBAL intr_stub_9
intr_stub_9:
    push 0
    push 9
    jmp intr_common_handler

GLOBAL intr_stub_10
intr_stub_10:
    push 10
    jmp intr_common_handler

GLOBAL intr_stub_11
intr_stub_11:
    push 11
    jmp intr_common_handler

GLOBAL intr_stub_12
intr_stub_12:
    push 12
    jmp intr_common_handler

GLOBAL intr_stub_13
intr_stub_13:
    push 13
    jmp intr_common_handler

GLOBAL intr_stub_14
intr_stub_14:
    push 14
    jmp intr_common_handler

GLOBAL intr_stub_15
intr_stub_15:
    push 0
    push 15
    jmp intr_common_handler

GLOBAL intr_stub_16
intr_stub_16:
    push 0
    push 16
    jmp intr_common_handler

GLOBAL intr_stub_17
intr_stub_17:
    push 17
    jmp intr_common_handler

GLOBAL intr_stub_18
intr_stub_18:
    push 0
    push 18
    jmp intr_common_handler

GLOBAL intr_stub_32
; IRQs
intr_stub_32:
    push 0
    push 32
    jmp intr_common_handler

GLOBAL intr_stub_33
intr_stub_33:
    push 0
    push 33
    jmp intr_common_handler

GLOBAL intr_stub_34
intr_stub_34:
    push 0
    push 34
    jmp intr_common_handler

GLOBAL intr_stub_35
intr_stub_35:
    push 0
    push 35
    jmp intr_common_handler

GLOBAL intr_stub_36
intr_stub_36:
    push 0
    push 36
    jmp intr_common_handler

GLOBAL intr_stub_37
intr_stub_37:
    push 0
    push 37
    jmp intr_common_handler

GLOBAL intr_stub_38
intr_stub_38:
    push 0
    push 38
    jmp intr_common_handler

GLOBAL intr_stub_39
intr_stub_39:
    push 0
    push 39
    jmp intr_common_handler

GLOBAL intr_stub_40
intr_stub_40:
    push 0
    push 40
    jmp intr_common_handler

GLOBAL intr_stub_41
intr_stub_41:
    push 0
    push 41
    jmp intr_common_handler

GLOBAL intr_stub_42
intr_stub_42:
    push 0
    push 42
    jmp intr_common_handler

GLOBAL intr_stub_43
intr_stub_43:
    push 0
    push 43
    jmp intr_common_handler

GLOBAL intr_stub_44
intr_stub_44:
    push 0
    push 44
    jmp intr_common_handler

GLOBAL intr_stub_45
intr_stub_45:
    push 0
    push 45
    jmp intr_common_handler

GLOBAL intr_stub_46
intr_stub_46:
    push 0
    push 46
    jmp intr_common_handler

GLOBAL intr_stub_47
intr_stub_47:
    push 0
    push 47
    jmp intr_common_handler

GLOBAL intr_stub_48
; Syscall
intr_stub_48:
    push 0
    push 48
    jmp intr_common_handler

GLOBAL intr_stub_127
intr_stub_127:
    push 0
    push 127
    jmp intr_common_handler

intr_common_handler:
    push ebp
    push edi
    push esi
    push edx
    push ecx
    push ebx
    push eax 

    push gs
    push fs
    push es
    push ds
            
    mov ax, 0x10   ; Kernel Segment laden
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax
    
    push esp
    call int_handler
    mov esp, eax
    
    pop ds
    pop es
    pop fs
    pop gs
    
    pop eax
    pop ebx
    pop ecx
    pop edx
    pop esi
    pop edi
    pop ebp
    
    add esp, 8     ; Aufräumen...
    iret           ; ... und weiter gehts im Code!
		
