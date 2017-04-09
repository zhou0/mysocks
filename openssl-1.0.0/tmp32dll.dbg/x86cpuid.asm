%ifidn __OUTPUT_FORMAT__,obj
section	code	use32 class=code align=64
%elifidn __OUTPUT_FORMAT__,win32
$@feat.00 equ 1
section	.text	code align=64
%else
section	.text	code
%endif
global	_OPENSSL_ia32_cpuid
align	16
_OPENSSL_ia32_cpuid:
L$_OPENSSL_ia32_cpuid_begin:
	push	ebp
	push	ebx
	push	esi
	push	edi
	xor	edx,edx
	pushfd
	pop	eax
	mov	ecx,eax
	xor	eax,2097152
	push	eax
	popfd
	pushfd
	pop	eax
	xor	ecx,eax
	bt	ecx,21
	jnc	NEAR L$000done
	xor	eax,eax
	cpuid
	mov	edi,eax
	xor	eax,eax
	cmp	ebx,1970169159
	setne	al
	mov	ebp,eax
	cmp	edx,1231384169
	setne	al
	or	ebp,eax
	cmp	ecx,1818588270
	setne	al
	or	ebp,eax
	jz	NEAR L$001intel
	cmp	ebx,1752462657
	setne	al
	mov	esi,eax
	cmp	edx,1769238117
	setne	al
	or	esi,eax
	cmp	ecx,1145913699
	setne	al
	or	esi,eax
	jnz	NEAR L$001intel
	mov	eax,2147483648
	cpuid
	cmp	eax,2147483656
	jb	NEAR L$001intel
	mov	eax,2147483656
	cpuid
	movzx	esi,cl
	inc	esi
	mov	eax,1
	cpuid
	bt	edx,28
	jnc	NEAR L$000done
	shr	ebx,16
	and	ebx,255
	cmp	ebx,esi
	ja	NEAR L$000done
	and	edx,4026531839
	jmp	NEAR L$000done
L$001intel:
	cmp	edi,4
	mov	edi,-1
	jb	NEAR L$002nocacheinfo
	mov	eax,4
	mov	ecx,0
	cpuid
	mov	edi,eax
	shr	edi,14
	and	edi,4095
L$002nocacheinfo:
	mov	eax,1
	cpuid
	cmp	ebp,0
	jne	NEAR L$003notP4
	and	ah,15
	cmp	ah,15
	jne	NEAR L$003notP4
	or	edx,1048576
L$003notP4:
	bt	edx,28
	jnc	NEAR L$000done
	and	edx,4026531839
	cmp	edi,0
	je	NEAR L$000done
	or	edx,268435456
	shr	ebx,16
	cmp	bl,1
	ja	NEAR L$000done
	and	edx,4026531839
L$000done:
	mov	eax,edx
	mov	edx,ecx
	pop	edi
	pop	esi
	pop	ebx
	pop	ebp
	ret
;extern	_OPENSSL_ia32cap_P
global	_OPENSSL_rdtsc
align	16
_OPENSSL_rdtsc:
L$_OPENSSL_rdtsc_begin:
	xor	eax,eax
	xor	edx,edx
	lea	ecx,[_OPENSSL_ia32cap_P]
	bt	DWORD [ecx],4
	jnc	NEAR L$004notsc
	rdtsc
L$004notsc:
	ret
global	_OPENSSL_instrument_halt
align	16
_OPENSSL_instrument_halt:
L$_OPENSSL_instrument_halt_begin:
	lea	ecx,[_OPENSSL_ia32cap_P]
	bt	DWORD [ecx],4
	jnc	NEAR L$005nohalt
dd	2421723150
	and	eax,3
	jnz	NEAR L$005nohalt
	pushfd
	pop	eax
	bt	eax,9
	jnc	NEAR L$005nohalt
	rdtsc
	push	edx
	push	eax
	hlt
	rdtsc
	sub	eax,DWORD [esp]
	sbb	edx,DWORD [4+esp]
	add	esp,8
	ret
L$005nohalt:
	xor	eax,eax
	xor	edx,edx
	ret
global	_OPENSSL_far_spin
align	16
_OPENSSL_far_spin:
L$_OPENSSL_far_spin_begin:
	pushfd
	pop	eax
	bt	eax,9
	jnc	NEAR L$006nospin
	mov	eax,DWORD [4+esp]
	mov	ecx,DWORD [8+esp]
dd	2430111262
	xor	eax,eax
	mov	edx,DWORD [ecx]
	jmp	NEAR L$007spin
align	16
L$007spin:
	inc	eax
	cmp	edx,DWORD [ecx]
	je	NEAR L$007spin
dd	529567888
	ret
L$006nospin:
	xor	eax,eax
	xor	edx,edx
	ret
global	_OPENSSL_wipe_cpu
align	16
_OPENSSL_wipe_cpu:
L$_OPENSSL_wipe_cpu_begin:
	xor	eax,eax
	xor	edx,edx
	lea	ecx,[_OPENSSL_ia32cap_P]
	mov	ecx,DWORD [ecx]
	bt	DWORD [ecx],1
	jnc	NEAR L$008no_x87
	bt	DWORD [ecx],26
	jnc	NEAR L$009no_sse2
	pxor	xmm0,xmm0
	pxor	xmm1,xmm1
	pxor	xmm2,xmm2
	pxor	xmm3,xmm3
	pxor	xmm4,xmm4
	pxor	xmm5,xmm5
	pxor	xmm6,xmm6
	pxor	xmm7,xmm7
L$009no_sse2:
dd	4007259865,4007259865,4007259865,4007259865,2430851995
L$008no_x87:
	lea	eax,[4+esp]
	ret
global	_OPENSSL_atomic_add
align	16
_OPENSSL_atomic_add:
L$_OPENSSL_atomic_add_begin:
	mov	edx,DWORD [4+esp]
	mov	ecx,DWORD [8+esp]
	push	ebx
	nop
	mov	eax,DWORD [edx]
L$010spin:
	lea	ebx,[ecx*1+eax]
	nop
dd	447811568
	jne	NEAR L$010spin
	mov	eax,ebx
	pop	ebx
	ret
global	_OPENSSL_indirect_call
align	16
_OPENSSL_indirect_call:
L$_OPENSSL_indirect_call_begin:
	push	ebp
	mov	ebp,esp
	sub	esp,28
	mov	ecx,DWORD [12+ebp]
	mov	DWORD [esp],ecx
	mov	edx,DWORD [16+ebp]
	mov	DWORD [4+esp],edx
	mov	eax,DWORD [20+ebp]
	mov	DWORD [8+esp],eax
	mov	eax,DWORD [24+ebp]
	mov	DWORD [12+esp],eax
	mov	eax,DWORD [28+ebp]
	mov	DWORD [16+esp],eax
	mov	eax,DWORD [32+ebp]
	mov	DWORD [20+esp],eax
	mov	eax,DWORD [36+ebp]
	mov	DWORD [24+esp],eax
	call	DWORD [8+ebp]
	mov	esp,ebp
	pop	ebp
	ret
global	_OPENSSL_cleanse
align	16
_OPENSSL_cleanse:
L$_OPENSSL_cleanse_begin:
	mov	edx,DWORD [4+esp]
	mov	ecx,DWORD [8+esp]
	xor	eax,eax
	cmp	ecx,7
	jae	NEAR L$011lot
	cmp	ecx,0
	je	NEAR L$012ret
L$013little:
	mov	BYTE [edx],al
	sub	ecx,1
	lea	edx,[1+edx]
	jnz	NEAR L$013little
L$012ret:
	ret
align	16
L$011lot:
	test	edx,3
	jz	NEAR L$014aligned
	mov	BYTE [edx],al
	lea	ecx,[ecx-1]
	lea	edx,[1+edx]
	jmp	NEAR L$011lot
L$014aligned:
	mov	DWORD [edx],eax
	lea	ecx,[ecx-4]
	test	ecx,-4
	lea	edx,[4+edx]
	jnz	NEAR L$014aligned
	cmp	ecx,0
	jne	NEAR L$013little
	ret
segment	.bss
common	_OPENSSL_ia32cap_P 4
segment	.CRT$XCU data align=4
extern	_OPENSSL_cpuid_setup
dd	_OPENSSL_cpuid_setup
