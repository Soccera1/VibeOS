global enter_user_mode

enter_user_mode:
    cli
    mov ebx, [esp+4]    ; entry point
    mov ecx, [esp+8]    ; stack pointer

    mov ax, 0x23      ; User Data segment (0x20 | 0x3)
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax

    push 0x23         ; ss
    push ecx          ; esp
    pushf
    pop eax
    or eax, 0x200     ; Enable interrupts in eflags
    push eax          ; eflags
    push 0x1B         ; cs (0x18 | 0x3)
    push ebx          ; eip
    iret
