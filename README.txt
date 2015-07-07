###################################################################################
## [Name]: xor-ror-feedback-encoder.py -- shellcode encoder
##---------------------------------------------------------------------------------
## [Author]: Re4son re4son [at] whitedome.com.au
##---------------------------------------------------------------------------------
## [Details]:
## Uses a random integer as initialisation vecor to xor the first byte of shellcode
## then uses the un-encoded previous byte and ror's it
## (encoded previous byte + initialisation vector) times - the result is used
## to xor the next byte
## the initialisation vectore will be attached to the shellcode as eol marker prior
## to encoding.
##
## Output:
## 1. the encoded payload only
## 2. the entire shellcode (stub and payload)
## 3. The nasm code of the stub containing the payload
##
## A warning will be displayed if bad characters are deteced inside the
## encoded shellcode - just run it again.
##
## A bigger warning will be displayed if the stub cotains a bad char
##---------------------------------------------------------------------------------
## [Usage]:
## Insert your shellcode into SHELLCODE constant, define bad chars
## run python xor-ror-feedback-encoder
###################################################################################
