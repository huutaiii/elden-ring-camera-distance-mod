
extern DeltaTime : dword

.code
	GetDeltaTime proc
		movss [DeltaTime],xmm1
		ret
	GetDeltatime endp
end
