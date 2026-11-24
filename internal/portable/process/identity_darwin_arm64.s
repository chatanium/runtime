//go:build darwin && arm64 && !ios

#include "textflag.h"

TEXT portable_fgetattrlist_trampoline<>(SB),NOSPLIT,$0-0
	JMP	libc_portable_fgetattrlist(SB)

TEXT ·darwinAttrListAddr(SB),NOSPLIT,$0-8
	MOVD	$portable_fgetattrlist_trampoline<>(SB), R0
	MOVD	R0, ret+0(FP)
	RET
