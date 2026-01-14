extern syscall_handler

global syscall_stub
syscall_stub:
    push dword 0        ; dummy error code
    push dword 0x80     ; syscall interrupt number
    pushad              ; pushes EDI, ESI, EBP, ESP, EBX, EDX, ECX, EAX

    mov ax, ds
    push eax            ; save DS

    ; Load Kernel Data Segments
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax

    push esp            ; pointer to registers struct
    call syscall_handler
    add esp, 4          ; clean up stack after call

    pop eax             ; restore DS
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax

    popad               ; restore EDI, ESI, EBP, ESP, EBX, EDX, ECX, EAX
    add esp, 8          ; clean up dummy error code and int number
    iret
