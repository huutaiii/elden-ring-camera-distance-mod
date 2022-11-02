
.data
	extern ReturnAddress : qword
	extern CameraDistanceMul : dword
	extern CameraDistanceAdd : dword

	extern InterpReturn : qword
	extern LerpAlpha : dword
	extern LerpOneMinusAlpha : dword

.code
	CameraDistance proc

		movss xmm10, dword ptr [CameraDistanceMul]
		mulss xmm7, xmm10
		movss xmm10, dword ptr [CameraDistanceAdd]
		addss xmm7, xmm10

		; overwritten code
		movss DWORD PTR [rbx + 1B8h], xmm7 ; 8B
		mov eax, DWORD PTR [rbx + 1B8h] ; 6B

		jmp QWORD PTR [ReturnAddress] ; 5B
	CameraDistance endp

	CameraInterp proc
		movss xmm14, dword ptr [LerpAlpha]
		movss xmm11, dword ptr [LerpOneMinusAlpha]
		shufps xmm14, xmm14, 00
		shufps xmm11, xmm11, 00
		
		movaps xmm12, xmmword ptr [rax]
		mulps xmm12, xmm11
		movaps xmm13, xmmword ptr [rdi]
		mulps xmm13, xmm14

		addps xmm12, xmm13
		movaps xmmword ptr [rdi], xmm12

		; stolen bytes
		;movaps xmm0, [rax]
		;movdqa [rdi], xmm0
		movss xmm5, DWORD PTR [rbx + 190h]

		jmp qword ptr [InterpReturn]
	CameraInterp endp
end