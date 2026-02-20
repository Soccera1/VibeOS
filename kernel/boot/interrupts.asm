BITS 64

section .text
global gdt_load
global gdt_load_tss
global idt_load
global enter_user_mode
global syscall_entry
global isr128
global leave_user_mode
global isr0
global isr1
global isr2
global isr3
global isr4
global isr5
global isr6
global isr7
global isr8
global isr9
global isr10
global isr11
global isr12
global isr13
global isr14
global isr15
global isr16
global isr17
global isr18
global isr19
global isr20
global isr21
global isr22
global isr23
global isr24
global isr25
global isr26
global isr27
global isr28
global isr29
global isr30
global isr31

extern syscall_dispatch
extern kernel_exit_stack_top
extern userland_exit_handler
extern exception_dispatch

; void gdt_load(const struct gdtr* gdtr, uint16_t code_sel, uint16_t data_sel)
gdt_load:
    lgdt [rdi]
    mov ax, dx
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax

    push rsi
    lea rax, [rel .flush_cs]
    push rax
    retfq
.flush_cs:
    ret

; void gdt_load_tss(uint16_t selector)
gdt_load_tss:
    mov ax, di
    ltr ax
    ret

; void idt_load(const struct idtr* idtr)
idt_load:
    lidt [rdi]
    ret

; void enter_user_mode(uint64_t entry, uint64_t stack_top)
enter_user_mode:
    xor eax, eax
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax

    ; Linux process entry expects a mostly clean register file.
    xor ebx, ebx
    xor ecx, ecx
    xor edx, edx
    xor ebp, ebp
    xor r8d, r8d
    xor r9d, r9d
    xor r10d, r10d
    xor r11d, r11d
    xor r12d, r12d
    xor r13d, r13d
    xor r14d, r14d
    xor r15d, r15d

    push qword 0x1B
    push rsi
    pushfq
    push qword 0x23
    push rdi
    iretq

; int 0x80 syscall entry from ring3.
; Preserves all GPRs except rax (return value), then iretq back to user.
isr128:
    cld
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push rbp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15

    mov rdi, rsp
    call syscall_dispatch
    mov [rsp + 14 * 8], rax

    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rbp
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    iretq

; syscall/syscall ABI entry from ring3.
; Uses kernel_exit_stack_top as the ring0 stack anchor and returns with iretq.
syscall_entry:
    cld
    mov [rel syscall_user_rsp_tmp], rsp
    mov rsp, [rel kernel_exit_stack_top]
    and rsp, -16

    ; Build an iret frame from syscall-provided return state.
    push qword 0x1B
    push qword [rel syscall_user_rsp_tmp]
    push r11
    push qword 0x23
    push rcx

    ; Save GPRs for C dispatcher (struct syscall_frame layout).
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push rbp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15

    mov rdi, rsp
    call syscall_dispatch
    mov [rsp + 14 * 8], rax

    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rbp
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    iretq

; noreturn void leave_user_mode(uint64_t code)
leave_user_mode:
    mov rsp, [rel kernel_exit_stack_top]
    and rsp, -16
    jmp userland_exit_handler

%macro ISR_NOERR 1
isr%1:
    push qword 0
    push qword %1
    jmp isr_common
%endmacro

%macro ISR_ERR 1
isr%1:
    push qword %1
    jmp isr_common
%endmacro

ISR_NOERR 0
ISR_NOERR 1
ISR_NOERR 2
ISR_NOERR 3
ISR_NOERR 4
ISR_NOERR 5
ISR_NOERR 6
ISR_NOERR 7
ISR_NOERR 8
ISR_NOERR 9
ISR_ERR   10
ISR_ERR   11
ISR_ERR   12
ISR_ERR   13
ISR_ERR   14
ISR_NOERR 15
ISR_NOERR 16
ISR_ERR   17
ISR_NOERR 18
ISR_NOERR 19
ISR_NOERR 20
ISR_ERR   21
ISR_NOERR 22
ISR_NOERR 23
ISR_NOERR 24
ISR_NOERR 25
ISR_NOERR 26
ISR_NOERR 27
ISR_NOERR 28
ISR_ERR   29
ISR_ERR   30
ISR_NOERR 31

isr_common:
    mov rdi, rsp
    call exception_dispatch
.halt:
    cli
    hlt
    jmp .halt

section .bss
align 8
syscall_user_rsp_tmp: resq 1
