.code

DirectSyscallBridge PROC
    mov r10, rcx
    mov eax, ecx            
    
    mov r10, rdx
    mov rdx, r8
    mov r8, r9
    mov r9, [rsp + 40]      
    
    syscall                 
    ret
DirectSyscallBridge ENDP

END
