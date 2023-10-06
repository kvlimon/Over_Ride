# Reverse decrypt

In this level we are provided with a program which takes a password as input.

Let's take a closer look at what happens after our input is captured by **`scanf()`**, the data is sent to a **`test()`** function.

```
0804885a <main>:
...
80488c6:	8b 44 24 1c          	mov    eax,DWORD PTR [esp+0x1c]
80488ca:	c7 44 24 04 0d d0 37 	mov    DWORD PTR [esp+0x4],0x1337d00d
80488d1:	13 
80488d2:	89 04 24             	mov    DWORD PTR [esp],eax
80488d5:	e8 6d fe ff ff       	call   8048747 <test>
```

**`test()`** is called with the address of the scanf buffer and a hexadecimal value **0x1337d00d** which will subsequently be the subtractor of all the values in the buffer :

```
08048747 <test>:
8048747:	55                   	push   ebp
8048748:	89 e5                	mov    ebp,esp
804874a:	83 ec 28             	sub    esp,0x28
804874d:	8b 45 08             	mov    eax,DWORD PTR [ebp+0x8]
8048750:	8b 55 0c             	mov    edx,DWORD PTR [ebp+0xc]
8048753:	89 d1                	mov    ecx,edx
8048755:	29 c1                	sub    ecx,eax
```


The result of this subtraction will be subject to mass verification, which is the equivalent of a switch.
In each case the  **`decrypt()`**  function will be called, if the value is from **1 to 15**, the argument sent will be the difference obtained recently, otherwise it will be the RTVL of **`rand()`**.

In the **`decrypt()`** function, we see this line, which will arbitrarily assign a new value to rax to each new process, and a **xor** which is applied to the register itself :
```
 8048668:	65 a1 14 00 00 00    	mov    eax,gs:0x14
 804866e:	89 45 f4             	mov    DWORD PTR [ebp-0xc],eax
 8048671:	31 c0                	xor    eax,eax
```

These lines store a string on a range in the stack, if we do the conversion with our python script from the previous level we obtain **Q}|u`sfg~sf{}|a3** :

```
8048673:	c7 45 e3 51 7d 7c 75 	mov    DWORD PTR [ebp-0x1d],0x757c7d51
804867a:	c7 45 e7 60 73 66 67 	mov    DWORD PTR [ebp-0x19],0x67667360
8048681:	c7 45 eb 7e 73 66 7b 	mov    DWORD PTR [ebp-0x15],0x7b66737e
8048688:	c7 45 ef 7d 7c 61 33 	mov    DWORD PTR [ebp-0x11],0x33617c7d
804868f:	c6 45 f3 00          	mov    BYTE PTR [ebp-0xd],0x0
```

Now let's focus on the condition that allows us to access the **`system('/bin/sh')`**.
