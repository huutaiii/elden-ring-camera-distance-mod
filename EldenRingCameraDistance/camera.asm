
extern CalcCameraOffset : proto

extern ReturnAddress : qword
extern CameraDistanceMul : dword
extern CameraDistanceAdd : dword

extern FoVMul : dword
	
; out
extern PivotYaw : dword
extern pvPivotPosition : xmmword
extern pvPivotPositionNoInterp : xmmword
extern pvTargetPosition : xmmword
extern pvResolvedOffset : xmmword
extern fCamMaxDistance : dword
extern bHasTargetLock : byte
extern TalkAddress : qword
extern CamParamID : dword
extern SideSwitchDelta : dword
extern SideSwitchMax : dword

; in
extern OffsetInterp : xmmword
extern CollisionOffset : xmmword
extern bDoLockTargetOffset : dword
extern TargetOffset : xmmword

.data
	iCamOffset byte 0

.code

	CameraDistance proc
		repeat 14
			nop
		endm

		mulss xmm7, [CameraDistanceMul]
		addss xmm7, [CameraDistanceAdd]

		jmp [ReturnAddress]

	CameraDistance endp

	CameraDistanceAlt proc
		mulss xmm7, [CameraDistanceMul]
		addss xmm7, [CameraDistanceAdd]

		ret
	CameraDistanceAlt endp

	ModifyFoV proc
		mulss xmm12, [FoVMul]
		ret
	ModifyFoV endp


	CameraOffset proc
	
		push rbp
		mov rbp,rsp
		lea rsp,[rsp-20h]
		movdqa [rbp-10h],xmm0
		movdqa [rbp-20h],xmm1
		push rax
		push rbx
		push rcx
		push rdx
		push r8
		push r9
		push r10
		push r11

		call CalcCameraOffset

		pop r11
		pop r10
		pop r9
		pop r8
		pop rdx
		pop rcx
		pop rbx
		pop rax
		movdqa xmm0,[rbp-10h]
		movdqa xmm1,[rbp-20h]

		lea rsp,[rsp+20h]
		pop rbp

		addps xmm1,[OffsetInterp]
		ret
	CameraOffset endp

	CollisionEndOffset proc
		addps xmm0,[CollisionOffset]
		ret
	CollisionEndOffset endp

	TargetLockOffset proc
		movaps [pvTargetPosition],xmm0
		;subps xmm0,[OffsetInterp]		; re-center lock-on target
		subps xmm0,[TargetOffset]
		ret
	TargetLockOffset endp

	SetPivotYaw proc
		;movaps xmm0,xmm8
		;shufps xmm0,xmm0,93h
		;movss dword ptr [PivotYaw],xmm0

		movaps xmm1,[rsi+0D0h]			; there are multiple similar vectors, imma just pick the middle one
		movaps [pvPivotPosition],xmm1
		movaps xmm1,[rsi+0B0h]
		movaps [pvPivotPositionNoInterp],xmm1

		movaps xmm1,[rsi+150h]
		shufps xmm1,xmm1,93h
		movss dword ptr [PivotYaw],xmm1
		shufps xmm1,xmm1,93h
		; this leaves xmm1 with non-zero values in [32..127] which isn't in the original code

		ret
	SetPivotYaw endp

	SetCameraCoords proc
		inc [iCamOffset]

		cmp [iCamOffset],3	
		jne continue				; skip until every 3rd call of frame

		movaps [pvResolvedOffset],xmm6
		mov [iCamOffset],0

		continue:
		ret
	SetCameraCoords endp

	SetCameraMaxDistance proc
		movss [fCamMaxDistance],xmm7
		ret
	SetCameraMaxDistance endp

	SetTargetLockState proc
		setne [bHasTargetLock]
		ret
	SetTargetLockState endp

	SetTalkAddress proc
		mov [TalkAddress],rsi
		ret
	SetTalkAddress endp

	SetParamID proc
		mov [CamParamID],edx
		ret
	SetParamID endp

	SetSideSwitch proc
		movss [SideSwitchDelta],xmm2	; stores x rotation?
		movss [SideSwitchMax],xmm13
		xorps xmm4,xmm4
		ret
	SetSideSwitch endp
end