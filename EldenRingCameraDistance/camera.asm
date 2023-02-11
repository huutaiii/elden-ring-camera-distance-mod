
.data
	extern ReturnAddress : qword
	extern CameraDistanceMul : dword
	extern CameraDistanceAdd : dword
	extern CameraDistanceAddCtrl : dword

	extern FoVMul : dword

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
		addss xmm7, [CameraDistanceAddCtrl]

		ret
	CameraDistanceAlt endp

	ModifyFoV proc
		mulss xmm12, [FoVMul]
		ret
	ModifyFoV endp

end