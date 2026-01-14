[bits 32]
section .text
global _start
extern main
extern exit

_start:
    ; The kernel should have pushed argc and argv onto the stack.
    ; For now, if it didn't, this might still be garbage, but let's assume it did.
    ; Standard x86 System V ABI for _start:
    ; [esp] = argc
    ; [esp+4] = argv[0]
    ; [esp+8] = argv[1]
    ; ...
    
    xor ebp, ebp    ; Mark end of stack frames
    
    pop eax         ; Get argc
    mov ecx, esp    ; argv is now pointing to argv[0]
    
    ; Push arguments for main(int argc, char **argv, char **envp)
    push 0          ; envp = NULL for now
    push ecx        ; argv
    push eax        ; argc
    
    call main
    
    ; Call exit(eax)
    push eax
    call exit

    ; Should not reach here
.halt:
    hlt
    jmp .halt
