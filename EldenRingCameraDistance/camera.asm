
.data
	extern ReturnAddress : qword
	extern CameraDistanceMul : dword
	extern CameraDistanceAdd : dword

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

end