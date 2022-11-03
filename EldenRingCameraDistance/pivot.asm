.data

	extern InterpReturn : qword
	extern LerpAlpha : dword
	extern LerpOneMinusAlpha : dword

	extern InterpEnableReturn : qword
	extern InterpDisableReturn : qword

	bUseInterp byte 0

.code

	CameraInterp proc
		repeat 30
			nop
		endm

		movdqa[rdi], xmm0
		jmp qword ptr [InterpReturn]
		nop

		movss xmm11, dword ptr [LerpOneMinusAlpha]
		movss xmm12, dword ptr [LerpAlpha]
		shufps xmm11, xmm11, 00h
		shufps xmm12, xmm12, 00h
		
		mulps xmm11, xmmword ptr [rax]
		mulps xmm12, xmmword ptr [rdi]
		
		addps xmm11, xmm12
		movdqa xmmword ptr [rdi], xmm11
		
		jmp qword ptr [InterpReturn]

	CameraInterp endp


	CameraInterpEnable proc
		;movsxd r8,dword ptr [rbx+48]
		;add r8,r8
		;mov rax,[rbx+10]
		;mov rdx,rsi
		;mov rcx,rbx
		repeat 14
			nop
		endm

		mov [bUseInterp], 1
		jmp qword ptr [InterpEnableReturn]
	CameraInterpEnable endp


	CameraInterpDisable proc
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
		jmp qword ptr [InterpDisableReturn]
	CameraInterpDisable endp


end