;  This file is used to test gpdasm with the 12 bit enhanced instruction set.

	list p=16f527

F	EQU	1
W	EQU	0

insn macro file
	ADDWF	file, F
	ANDLW	0xff
	ANDWF	file, F
	BCF	file, 7
	BSF	file, 7
	BTFSC	file, F
	BTFSS	file, F
	CALL	0xff
	CLRF	file
	CLRW
	CLRWDT
	COMF	file, F
	DECF	file, F
	DECFSZ	file, F
	GOTO	0x100
	INCF	file, F
	INCFSZ	file, F
	IORLW	0xff
	IORWF	file, F
	MOVF	file, F
	MOVLB	7
	MOVLW	0xff
	MOVWF	file
	NOP
	OPTION
	RETFIE
	RETLW	0
	RETURN
	RLF	file, F
	RRF	file, F
	SLEEP
	SUBWF	file, F
	SWAPF	file, F
	TRIS	6
	XORLW	0xff
	XORWF	file, F
    endm

	org	0
	insn	.10

	org	0x100
	insn	.20

	org	0x200
	insn	.25
    end