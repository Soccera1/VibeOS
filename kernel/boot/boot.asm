BITS 32

section .multiboot
align 8
mb2_header_start:
    dd 0xE85250D6                ; multiboot2 magic
    dd 0                         ; architecture (i386)
    dd mb2_header_end - mb2_header_start
    dd -(0xE85250D6 + 0 + (mb2_header_end - mb2_header_start))

    ; optional framebuffer tag
    align 8
    dw 5
    dw 1
    dd 20
    dd 1024
    dd 768
    dd 32

    ; end tag
    align 8
    dw 0
    dw 0
    dd 8
mb2_header_end:

section .text
global _start
extern kernel_main

_start:
    cli
    mov esp, boot_stack_top32
    mov [mb2_info_ptr], ebx

    call check_long_mode
    call setup_page_tables

    lgdt [gdt64_ptr]

    ; Enable PAE
    mov eax, cr4
    or eax, (1 << 5)
    mov cr4, eax

    ; Enable long mode in EFER
    mov ecx, 0xC0000080
    rdmsr
    or eax, (1 << 8)
    wrmsr

    ; Load PML4
    mov eax, pml4_table
    mov cr3, eax

    ; Enable paging
    mov eax, cr0
    or eax, (1 << 31)
    mov cr0, eax

    jmp 0x08:long_mode_entry

.hang:
    hlt
    jmp .hang

check_long_mode:
    mov eax, 0x80000000
    cpuid
    cmp eax, 0x80000001
    jb .unsupported

    mov eax, 0x80000001
    cpuid
    test edx, (1 << 29)
    jz .unsupported
    ret

.unsupported:
    hlt
    jmp .unsupported

setup_page_tables:
    mov edi, pml4_table
    mov ecx, (4096 * 6) / 4
    xor eax, eax
    rep stosd

    mov eax, pdpt_table
    or eax, 0x07
    mov dword [pml4_table], eax

    xor esi, esi
.pd_setup_loop:
    mov eax, pd_table0
    mov ebx, esi
    shl ebx, 12
    add eax, ebx
    or eax, 0x07
    mov [pdpt_table + esi * 8], eax
    mov dword [pdpt_table + esi * 8 + 4], 0
    inc esi
    cmp esi, 4
    jne .pd_setup_loop

    xor esi, esi
.pd_fill_loop:
    xor ebx, ebx
.map_loop:
    mov eax, esi
    shl eax, 30
    mov edx, ebx
    shl edx, 21
    add eax, edx
    or eax, 0x87                ; present + rw + user + 2MiB
    mov edx, esi
    shl edx, 12
    mov [pd_table0 + edx + ebx * 8], eax
    mov dword [pd_table0 + edx + ebx * 8 + 4], 0
    inc ebx
    cmp ebx, 512
    jne .map_loop
    inc esi
    cmp esi, 4
    jne .pd_fill_loop

    ret

BITS 64
long_mode_entry:
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax

    mov rsp, boot_stack_top64
    mov rdi, [mb2_info_ptr]
    call kernel_main

.halt64:
    hlt
    jmp .halt64

section .data
align 8
gdt64:
    dq 0x0000000000000000
    dq 0x00AF9A000000FFFF        ; 0x08 kernel code
    dq 0x00CF92000000FFFF        ; 0x10 kernel data
gdt64_end:

gdt64_ptr:
    dw gdt64_end - gdt64 - 1
    dd gdt64

section .bss
align 16
mb2_info_ptr: resq 1
align 4096
pml4_table: resb 4096
pdpt_table: resb 4096
pd_table0:  resb 4096
pd_table1:  resb 4096
pd_table2:  resb 4096
pd_table3:  resb 4096
align 16
boot_stack_bottom: resb 16384
boot_stack_top32:
boot_stack_top64:
