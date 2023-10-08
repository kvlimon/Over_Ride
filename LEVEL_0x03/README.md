
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

**`test()`** is called with a hexadecimal value **0x1337d00d** & the value of the **`scanf()`** buffer which will subsequently be the subtractor  :

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
In each case the  **`decrypt()`**  function will be called, if the value is from **1 to 9** or  **16 to 21**, the argument sent will be the difference obtained recently, otherwise it will be the RTVL of **`rand()`**.

These lines store a string on a range in the stack, if we do the conversion with our python script from the previous level we obtain **Q}|u`sfg~sf{}|a3** :

```
08048660 <decrypt>:
...
8048673:	c7 45 e3 51 7d 7c 75 	mov    DWORD PTR [ebp-0x1d],0x757c7d51
804867a:	c7 45 e7 60 73 66 67 	mov    DWORD PTR [ebp-0x19],0x67667360
8048681:	c7 45 eb 7e 73 66 7b 	mov    DWORD PTR [ebp-0x15],0x7b66737e
8048688:	c7 45 ef 7d 7c 61 33 	mov    DWORD PTR [ebp-0x11],0x33617c7d
804868f:	c6 45 f3 00          	mov    BYTE PTR [ebp-0xd],0x0
```

The **`decrypt()`** function applies an **XOR** of each character in the crypted string with the received input **`RBP+0x08`**.
If this condition is satisfied then the program spawns a shell with admin rights.

```
; ebp - 0x1d = crypted string ("Q}|u`sfg~sf{}|a3")
; ebp + 0x08 = first arg (0x1337d00d - USER INPUT)
; ebp - 0x28 = for counting in the crypted string

08048660 <decrypt>:
...
80486c7:	8d 45 e3             	lea    eax,[ebp-0x1d]
80486ca:	03 45 d8             	add    eax,DWORD PTR [ebp-0x28]
80486cd:	0f b6 00             	movzx  eax,BYTE PTR [eax]
80486d0:	89 c2                	mov    edx,eax
80486d2:	8b 45 08             	mov    eax,DWORD PTR [ebp+0x8]
80486d5:	31 d0                	xor    eax,edx
80486d7:	89 c2                	mov    edx,eax
80486d9:	8d 45 e3             	lea    eax,[ebp-0x1d]
80486dc:	03 45 d8             	add    eax,DWORD PTR [ebp-0x28]
80486df:	88 10                	mov    BYTE PTR [eax],dl
80486e1:	83 45 d8 01          	add    DWORD PTR [ebp-0x28],0x1
80486e5:	8b 45 d8             	mov    eax,DWORD PTR [ebp-0x28]
80486e8:	3b 45 dc             	cmp    eax,DWORD PTR [ebp-0x24]
80486eb:	72 da                	jb     80486c7 <decrypt+0x67>
...
8048700:	f3 a6                	repz   cmps BYTE PTR ds:[esi],BYTE PTR es:[edi]
8048702:	0f 97 c2             	seta   dl
8048705:	0f 92 c0             	setb   al
8048708:	89 d1                	mov    ecx,edx
804870a:	28 c1                	sub    cl,al
804870c:	89 c8                	mov    eax,ecx
804870e:	0f be c0             	movsx  eax,al
8048711:	85 c0                	test   eax,eax
8048713:	75 0e                	jne    8048723 <decrypt+0xc3>
8048715:	c7 04 24 d4 89 04 08 	mov    DWORD PTR [esp],0x80489d4
804871c:	e8 bf fd ff ff       	call   80484e0 <system@plt>
```


The solution would be to brute force all possibilities, so that **`322424845 - X = (1 to 9) or (16 to 21)`** because **`Crypted_String XOR PreviousResult = "Congratulations!"`**

Here is a C++ script to get these values

```cpp
#include <iostream>

int main()
{
    for (int x = 322424845 - 21; x <= 322424845; X++)
    {
        int res = 322424845 - x;
        if ((res >= 1 && res <= 9) || (res >= 16 && res <= 21))
        {
            std::cout << x << std::endl;
        }
    }
    return 0;
}
```
It works with this value : **322424827**

> flag : kgv3tkEb9h2mLkRsPkXRfc2mHbjMxQzvb2FrgKkf
