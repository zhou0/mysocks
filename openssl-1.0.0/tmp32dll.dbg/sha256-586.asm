%ifidn __OUTPUT_FORMAT__,obj
section	code	use32 class=code align=64
%elifidn __OUTPUT_FORMAT__,win32
$@feat.00 equ 1
section	.text	code align=64
%else
section	.text	code
%endif
global	_sha256_block_data_order
align	16
_sha256_block_data_order:
L$_sha256_block_data_order_begin:
	push	ebp
	push	ebx
	push	esi
	push	edi
	mov	esi,DWORD [20+esp]
	mov	edi,DWORD [24+esp]
	mov	eax,DWORD [28+esp]
	mov	ebx,esp
	call	L$000pic_point
L$000pic_point:
	pop	ebp
	lea	ebp,[(L$001K256-L$000pic_point)+ebp]
	sub	esp,16
	and	esp,-64
	shl	eax,6
	add	eax,edi
	mov	DWORD [esp],esi
	mov	DWORD [4+esp],edi
	mov	DWORD [8+esp],eax
	mov	DWORD [12+esp],ebx
align	16
L$002loop:
	mov	eax,DWORD [edi]
	mov	ebx,DWORD [4+edi]
	mov	ecx,DWORD [8+edi]
	mov	edx,DWORD [12+edi]
	bswap	eax
	bswap	ebx
	bswap	ecx
	bswap	edx
	push	eax
	push	ebx
	push	ecx
	push	edx
	mov	eax,DWORD [16+edi]
	mov	ebx,DWORD [20+edi]
	mov	ecx,DWORD [24+edi]
	mov	edx,DWORD [28+edi]
	bswap	eax
	bswap	ebx
	bswap	ecx
	bswap	edx
	push	eax
	push	ebx
	push	ecx
	push	edx
	mov	eax,DWORD [32+edi]
	mov	ebx,DWORD [36+edi]
	mov	ecx,DWORD [40+edi]
	mov	edx,DWORD [44+edi]
	bswap	eax
	bswap	ebx
	bswap	ecx
	bswap	edx
	push	eax
	push	ebx
	push	ecx
	push	edx
	mov	eax,DWORD [48+edi]
	mov	ebx,DWORD [52+edi]
	mov	ecx,DWORD [56+edi]
	mov	edx,DWORD [60+edi]
	bswap	eax
	bswap	ebx
	bswap	ecx
	bswap	edx
	push	eax
	push	ebx
	push	ecx
	push	edx
	add	edi,64
	sub	esp,32
	mov	DWORD [100+esp],edi
	mov	eax,DWORD [esi]
	mov	ebx,DWORD [4+esi]
	mov	ecx,DWORD [8+esi]
	mov	edi,DWORD [12+esi]
	mov	DWORD [4+esp],ebx
	mov	DWORD [8+esp],ecx
	mov	DWORD [12+esp],edi
	mov	edx,DWORD [16+esi]
	mov	ebx,DWORD [20+esi]
	mov	ecx,DWORD [24+esi]
	mov	edi,DWORD [28+esi]
	mov	DWORD [20+esp],ebx
	mov	DWORD [24+esp],ecx
	mov	DWORD [28+esp],edi
align	16
L$00300_15:
	mov	ebx,DWORD [92+esp]
	mov	ecx,edx
	ror	ecx,6
	mov	edi,edx
	ror	edi,11
	mov	esi,DWORD [20+esp]
	xor	ecx,edi
	ror	edi,14
	xor	ecx,edi
	mov	edi,DWORD [24+esp]
	add	ebx,ecx
	mov	DWORD [16+esp],edx
	xor	esi,edi
	mov	ecx,eax
	and	esi,edx
	mov	edx,DWORD [12+esp]
	xor	esi,edi
	mov	edi,eax
	add	ebx,esi
	ror	ecx,2
	add	ebx,DWORD [28+esp]
	ror	edi,13
	mov	esi,DWORD [4+esp]
	xor	ecx,edi
	ror	edi,9
	add	edx,ebx
	xor	ecx,edi
	mov	edi,DWORD [8+esp]
	add	ebx,ecx
	mov	DWORD [esp],eax
	mov	ecx,eax
	sub	esp,4
	or	eax,esi
	and	ecx,esi
	and	eax,edi
	mov	esi,DWORD [ebp]
	or	eax,ecx
	add	ebp,4
	add	eax,ebx
	add	edx,esi
	add	eax,esi
	cmp	esi,3248222580
	jne	NEAR L$00300_15
	mov	ebx,DWORD [152+esp]
align	16
L$00416_63:
	mov	esi,ebx
	mov	ecx,DWORD [100+esp]
	shr	ebx,3
	ror	esi,7
	xor	ebx,esi
	ror	esi,11
	mov	edi,ecx
	xor	ebx,esi
	shr	ecx,10
	mov	esi,DWORD [156+esp]
	ror	edi,17
	xor	ecx,edi
	ror	edi,2
	add	ebx,esi
	xor	edi,ecx
	add	ebx,edi
	mov	ecx,edx
	add	ebx,DWORD [120+esp]
	ror	ecx,6
	mov	edi,edx
	ror	edi,11
	mov	esi,DWORD [20+esp]
	xor	ecx,edi
	ror	edi,14
	mov	DWORD [92+esp],ebx
	xor	ecx,edi
	mov	edi,DWORD [24+esp]
	add	ebx,ecx
	mov	DWORD [16+esp],edx
	xor	esi,edi
	mov	ecx,eax
	and	esi,edx
	mov	edx,DWORD [12+esp]
	xor	esi,edi
	mov	edi,eax
	add	ebx,esi
	ror	ecx,2
	add	ebx,DWORD [28+esp]
	ror	edi,13
	mov	esi,DWORD [4+esp]
	xor	ecx,edi
	ror	edi,9
	add	edx,ebx
	xor	ecx,edi
	mov	edi,DWORD [8+esp]
	add	ebx,ecx
	mov	DWORD [esp],eax
	mov	ecx,eax
	sub	esp,4
	or	eax,esi
	and	ecx,esi
	and	eax,edi
	mov	esi,DWORD [ebp]
	or	eax,ecx
	add	ebp,4
	add	eax,ebx
	mov	ebx,DWORD [152+esp]
	add	edx,esi
	add	eax,esi
	cmp	esi,3329325298
	jne	NEAR L$00416_63
	mov	esi,DWORD [352+esp]
	mov	ebx,DWORD [4+esp]
	mov	ecx,DWORD [8+esp]
	mov	edi,DWORD [12+esp]
	add	eax,DWORD [esi]
	add	ebx,DWORD [4+esi]
	add	ecx,DWORD [8+esi]
	add	edi,DWORD [12+esi]
	mov	DWORD [esi],eax
	mov	DWORD [4+esi],ebx
	mov	DWORD [8+esi],ecx
	mov	DWORD [12+esi],edi
	mov	eax,DWORD [20+esp]
	mov	ebx,DWORD [24+esp]
	mov	ecx,DWORD [28+esp]
	mov	edi,DWORD [356+esp]
	add	edx,DWORD [16+esi]
	add	eax,DWORD [20+esi]
	add	ebx,DWORD [24+esi]
	add	ecx,DWORD [28+esi]
	mov	DWORD [16+esi],edx
	mov	DWORD [20+esi],eax
	mov	DWORD [24+esi],ebx
	mov	DWORD [28+esi],ecx
	add	esp,352
	sub	ebp,256
	cmp	edi,DWORD [8+esp]
	jb	NEAR L$002loop
	mov	esp,DWORD [12+esp]
	pop	edi
	pop	esi
	pop	ebx
	pop	ebp
	ret
align	64
L$001K256:
dd	1116352408,1899447441,3049323471,3921009573
dd	961987163,1508970993,2453635748,2870763221
dd	3624381080,310598401,607225278,1426881987
dd	1925078388,2162078206,2614888103,3248222580
dd	3835390401,4022224774,264347078,604807628
dd	770255983,1249150122,1555081692,1996064986
dd	2554220882,2821834349,2952996808,3210313671
dd	3336571891,3584528711,113926993,338241895
dd	666307205,773529912,1294757372,1396182291
dd	1695183700,1986661051,2177026350,2456956037
dd	2730485921,2820302411,3259730800,3345764771
dd	3516065817,3600352804,4094571909,275423344
dd	430227734,506948616,659060556,883997877
dd	958139571,1322822218,1537002063,1747873779
dd	1955562222,2024104815,2227730452,2361852424
dd	2428436474,2756734187,3204031479,3329325298
db	83,72,65,50,53,54,32,98,108,111,99,107,32,116,114,97
db	110,115,102,111,114,109,32,102,111,114,32,120,56,54,44,32
db	67,82,89,80,84,79,71,65,77,83,32,98,121,32,60,97
db	112,112,114,111,64,111,112,101,110,115,115,108,46,111,114,103
db	62,0
