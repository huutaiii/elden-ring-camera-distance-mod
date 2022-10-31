
.data
	extern ReturnAddress : qword
	extern CameraDistanceMul : dword
	extern CameraDistanceAdd : dword

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
end