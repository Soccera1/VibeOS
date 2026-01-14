; Multiboot 1 Header
MB_ALIGN     equ  1 << 0
MB_MEMINFO   equ  1 << 1
MB_VIDEO     equ  1 << 2
MB_FLAGS     equ  MB_ALIGN | MB_MEMINFO | MB_VIDEO
MB_MAGIC     equ  0x1BADB002
MB_CHECKSUM  equ  -(MB_MAGIC + MB_FLAGS)

section .multiboot_header
align 4
    dd MB_MAGIC
    dd MB_FLAGS
    dd MB_CHECKSUM
    ; Padding to get to offset 32 for video fields
    dd 0 ; header_addr
    dd 0 ; load_addr
    dd 0 ; load_end_addr
    dd 0 ; bss_end_addr
    dd 0 ; entry_addr
    ; Offset 32: Video fields
    dd 0    ; mode_type (0 = linear)
    dd 1024 ; width
    dd 768  ; height
    dd 32   ; depth

section .bss
align 16
stack_bottom:
    resb 16384 ; 16 KiB
stack_top:

section .text
global _start
_start:
    cli
    ; Set up stack
    mov esp, stack_top

    ; Pass Multiboot magic and info pointer to kernel_main
    push ebx
    push eax

    extern kernel_main
    call kernel_main

.halt:
    hlt
    jmp .halt