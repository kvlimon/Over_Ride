# Welcome to wil's crappy number storage service !

On this level we are provided with a program which has the function of saving passwords at a given index.
As usual we will focus on vulnerabilities.

The first idea could be on **`fgets()`**, but it limits our writing on the stack to 20 bytes.

But let's not lose this idea, because we have places in our application that accept user input, let's find the one that is vulnerable. The index input allows to write on a very wide range of the stack without verification upstream, it's an excellent source of vulnerability, if we manage to point it in the right place. 

The **`store_number()`** function is called with the buffer as argument which contains all the numbers saved by storage.

Below I show you several small sections in the assembly code, the index input is saved at **`$ebp-0xc`** and then an assignment takes place with the number.

```
08048630 <store_number>:
...
8048666:	e8 7c ff ff ff       	call   80485e7 <get_unum>
804866b:	89 45 f4             	mov    DWORD PTR [ebp-0xc],eax
...
80486c2:	8b 45 f4             	mov    eax,DWORD PTR [ebp-0xc]
80486c5: c1 e0 02              shl    eax,0x2
80486c8:	03 45 08             	add    eax,DWORD PTR [ebp+0x8]
80486cb:	8b 55 f0             	mov    edx,DWORD PTR [ebp-0x10]
80486ce:	89 10                	mov    DWORD PTR [eax],edx
```

Input restrictions :

- The index must have a rest after a % 3.
- The number >> 0x18 == 0xb7, should not satisfy this condition.


```
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
...
in store_number function

(gdb) x $ebp+0x08
0xffffd430:	0xffffd454

Buffer that holds numbers 0xffffd454 = 4294956116
EIP location in main stack frame 0xffffd61c = 4294956572

4294956572 - 4294956116 = 456

OFFSET WILL BE 456
456 >> 2 = 114 or 456 / 4 = 114
```

> flag: 
