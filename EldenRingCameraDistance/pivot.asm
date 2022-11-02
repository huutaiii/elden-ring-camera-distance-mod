.data

	extern InterpReturn : qword
	extern LerpAlpha : dword
	extern LerpOneMinusAlpha : dword

.code

	CameraInterp proc
		repeat 2
			nop
		endm

		movss xmm0, dword ptr [LerpOneMinusAlpha]
		movss xmm1, dword ptr [LerpAlpha]
		shufps xmm0, xmm0, 00
		shufps xmm1, xmm1, 00

		mulps xmm0, xmmword ptr [rax]
		mulps xmm1, xmmword ptr [rdi]

		addps xmm0, xmm1
		movdqa xmmword ptr [rdi], xmm0

		; stolen bytes
		;movaps xmm0, [rax]
		;movdqa [rdi], xmm0
		movss xmm5, DWORD PTR [rbx + 190h]

		nop
		jmp qword ptr [InterpReturn]
	CameraInterp endp

end