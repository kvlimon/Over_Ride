# Thanks gdb

## Program summary
On this level we are provided with a authentification program. First it asks us for a login, and then we are asked to enter a serial number. This data will be sent to an **`auth()`** function, if this returns us 0, we will be authenticated & a shell will spawn for us.


```
; 1st arg: login buffer addr
; 2th arg: serial number val
08048879 <main>:
...
8048932:	8b 44 24 28          	mov    eax,DWORD PTR [esp+0x28]
8048936:	89 44 24 04          	mov    DWORD PTR [esp+0x4],eax
804893a:	8d 44 24 2c          	lea    eax,[esp+0x2c]
804893e:	89 04 24             	mov    DWORD PTR [esp],eax
8048941:	e8 02 fe ff ff       	call   8048748 <auth>
...
8048946:	85 c0                	test   eax,eax
8048948:	75 1f                	jne    8048969 <main+0xf0>
804894a:	c7 04 24 52 8b 04 08 	mov    DWORD PTR [esp],0x8048b52
8048951:	e8 3a fc ff ff       	call   8048590 <puts@plt>
8048956:	c7 04 24 61 8b 04 08 	mov    DWORD PTR [esp],0x8048b61
804895d:	e8 3e fc ff ff       	call   80485a0 <system@plt>
```

Now a certain **`auth()`** function is called, it will receive two parameters (login & serial).

In the **`auth()`** function we observe two operations, a first will be carried out by the **`strcspn()`** function, it parses our first string trying to find an occurrence in the second & a **`strnlen()`** is performed on this same string, if the return value is below **length 6** we will not be able to access the spawn of a shell.

Here below I post the authentication code, as you can see there is a lot of gymnastics in the code.

```c
undefined4
auth(char  *param_1,  uint  param_2)
{
	size_t sVar1;
	undefined4 uVar2;
	long lVar3;
	int local_18;
	uint local_14;

	sVar1 =  strcspn(param_1,"\n");
	param_1[sVar1]  =  '\0';
	sVar1 =  strnlen(param_1,0x20);

	if  ((int)sVar1 <  6)
	{
		uVar2 =  1;
	}
	else
	{
		lVar3 =  ptrace(PTRACE_TRACEME);
		if  (lVar3 ==  -1)
		{
			puts("\x1b[32m.---------------------------.");
			puts("\x1b[31m| !! TAMPERING DETECTED !! |");
			puts("\x1b[32m\'---------------------------\'");
			uVar2 =  1;
		}
		else
		{
			local_14 =  ((int)param_1[3]  ^  0x1337U)  +  0x5eeded;
			for  (local_18 =  0; local_18 <  (int)sVar1; local_18 = local_18 +  1)
			{
				if  (param_1[local_18]  <  '  ')
				{
					return  1;
				}
				local_14 = local_14 +  ((int)param_1[local_18]  ^ local_14)  %  0x539;
			}
			if  (param_2 == local_14)
			{
				uVar2 =  0;
			}
			else
			{
				uVar2 =  1;
			}
		}
	}
	return uVar2;
}
```

## Vulnerability
The vulnerability lies in the fact that in the program we can precisely recover the password at a specific moment.

## Attack design
Let's go as simple as possible, we want 0 as a return value from **`auth()`**, and to get 0 we have to satisfy this condition -> `if (param_2 == local_14)`, let's use gdb to obtain the number obtained at this time.
```
(gdb) b *0x80487ba
Breakpoint 1 at 0x80487ba
(gdb) b *0x8048866
Breakpoint 2 at 0x8048866
(gdb) run
Starting program: /home/users/level06/level06
***********************************
*		level06		  *
***********************************
-> Enter Login: aschiffe
***********************************
***** NEW ACCOUNT DETECTED ********
***********************************
-> Enter Serial: 0
(gdb) set $eax=1
(gdb) c
Continuing.
Breakpoint 2, 0x08048866 in auth ()
(gdb) x/d $ebp-0x10
0xffffd5a8:	6234511
...
-> Enter Serial: 6234511
Authenticated!
$ cat /home/users/level07/.pass
GbcPDRgsFK77LNnnuh7QyFYA2942Gp8yKj9KrWD8
```

> Flag : `GbcPDRgsFK77LNnnuh7QyFYA2942Gp8yKj9KrWD8`
