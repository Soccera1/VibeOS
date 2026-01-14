extern syscall_handler

global syscall_stub
syscall_stub:
    push ebp
    push edi
    push esi
    push edx
    push ecx
    push ebx
    push eax

    ; Load Kernel Data Segments
    mov ax, 0x10
    mov ds, ax
    mov es, ax

    push esp
    call syscall_handler
    add esp, 4

    ; Restore User Data Segments
    mov ax, 0x23
    mov ds, ax
    mov es, ax

    pop eax
    pop ebx
    pop ecx
    pop edx
    pop esi
    pop edi
    pop ebp
    iret
