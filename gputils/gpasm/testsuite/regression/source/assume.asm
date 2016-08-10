	processor 18f24k50
	include <p18f24k50.inc>

	cblock	__BANK_15
	    Bank15:0
	endc

	org	0x0000
	banksel	Bank15
	goto	start

    if (__ACTIVE_BANK_ADDR != __BANK_INV)
	error "__ACTIVE_BANK_ADDR is #v(__ACTIVE_BANK_ADDR) and not #v(__BANK_INV)!"
    endif

	org	0x0100
start:
	assume	Bank15
	banksel	Bank15
loop:
	bra	loop

	end
