[bits 32]
section .text
global _start

_start:
    ; sys_write(1, msg, 26)
    mov eax, 4      ; syscall number 4
    mov ebx, 1      ; file descriptor 1 (stdout)
    mov ecx, msg    ; message pointer
    mov edx, 26     ; message length
    int 0x80

    ; sys_exit()
    mov eax, 1      ; syscall number 1
    int 0x80

section .data
msg db "Hello from VibeOS Userland!", 0x0A
