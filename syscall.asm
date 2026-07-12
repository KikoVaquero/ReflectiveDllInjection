extern ssn:DWORD
extern retAddress:QWORD

.CODE
HellsGate PROC
	mov r10, rcx
	mov eax, ssn
	syscall
	ret
HellsGate ENDP

HalosGate PROC
	mov r10,rcx
	mov eax, ssn
	mov rbx, retAddress
	jmp retAddress
HalosGate ENDP
END