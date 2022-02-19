	processor p16f887
	radix	dec

	org 0
v equ 5
    if (v==5)
	movlw	5
    elif (v!=0)
	movlw	0
    endif
	end
