
extern CalcPivotOffset : proto

.data

	extern InterpReturn : qword
	extern InterpSpeedMul : dword
	extern vInterpSpeedMul : xmmword
	extern InterpRetAlt : qword

	extern LoadingEndReturn : qword
	extern LoadingBeginReturn : qword

	; out
	extern PivotYaw : dword
	extern pvResolvedOffset : xmmword
	extern fCamMaxDistance : dword

	; in
	extern OffsetInterp : xmmword
	extern CollisionOffset : xmmword

	bUseInterp byte 0
	iCamOffset byte 0

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

	PivotOffset proc

		lea rsp,[rsp-10o-10h]
		movaps [rsp],xmm5
		;movaps [rsp],xmm6

		lea rsp,[rsp-10o]
		push rbp
		mov rbp, rsp

		call CalcPivotOffset

		mov rsp, rbp
		pop rbp
		lea rsp,[rsp+10o]

		movaps xmm5,[rsp]
		lea rsp,[rsp+10h+10o]

		addps xmm5,xmm0

		ret
	PivotOffset endp

	CameraCollisionOffset proc
		subps xmm5, [CollisionOffset]
		ret
	CameraCollisionOffset endp

	SetPivotYaw proc
		movaps xmm0,xmm8
		shufps xmm0,xmm0,93h
		movss dword ptr [PivotYaw],xmm0
		ret
	SetPivotYaw endp

	SetCameraCoords proc
		inc [iCamOffset]

		cmp [iCamOffset],3			; we can do whatever with the flags?
		jne continue

		movaps [pvResolvedOffset],xmm6
		mov [iCamOffset],0

		continue:
		ret
	SetCameraCoords endp

	SetCameraMaxDistance proc
		movss [fCamMaxDistance],xmm7
		ret
	SetCameraMaxDistance endp

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