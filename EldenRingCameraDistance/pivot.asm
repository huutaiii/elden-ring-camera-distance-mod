.data

	extern InterpReturn : qword
	extern InterpSpeedMul : dword
	extern vInterpSpeedMul : xmmword
	extern InterpRetAlt : qword

	extern LoadingEndReturn : qword
	extern LoadingBeginReturn : qword

	bUseInterp byte 0

.code

	CameraInterp proc
		repeat 16
			nop
		endm

		mulss xmm4, [InterpSpeedMul]
		
		jmp qword ptr [InterpReturn]

	CameraInterp endp

	CamInterpAlt proc

		mulps xmm8, [vInterpSpeedMul]

		ret
	CamInterpAlt endp

	LoadingEnd proc
		;movsxd r8,dword ptr [rbx+48]
		;add r8,r8
		;mov rax,[rbx+10]
		;mov rdx,rsi
		;mov rcx,rbx
		repeat 14
			nop
		endm

		mov [bUseInterp], 1
		jmp qword ptr [LoadingEndReturn]
	LoadingEnd endp


	LoadingBegin proc
		;mov rax,rsp	
		;push rbp
		;push rsi
		;push rdi
		;push r12
		;push r13
		;push r14
		;push r15
		repeat 17
			nop
		endm

		mov [bUseInterp], 0
		jmp qword ptr [LoadingBeginReturn]
	LoadingBegin endp


end