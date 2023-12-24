# OverRide - Reconstruct & Search Vuln in binaries
![enter image description here](https://i.ibb.co/7vCqzmk/Screenshot-from-2023-10-05-10-24-16.png)
## Introduction
This project is the continuation of RainFall with the aim of learning binary exploitation (type ***EL0xfffffff***)

## **Security properties of binary files in Linux**
On each level we have this command which is launched on our executable :

**`checksec --file=./[EXECUTABLE]`**

Checksec is **a shell script that can be used to check the properties of binary files in Linux**. This can be used to check for several mitigation techniques such as ***PIE***, ***RELRO***, ***NX***, ***Stack Canaries***, ***ASLR***, and others.

```
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
Partial RELRO   No canary found   NX enabled    PIE enabled     No RPATH   No RUNPATH   /home/users/
```

### *RELRO*
Relocation Read-Only. RELRO is **a protection to stop any GOT overwrites from taking place**, and it does so very effectively. Here is my article related to GOT Overwriting [WIP].

### *STACK CANARY*
Stack canaries, named for their analogy to a canary in a coal mine, are **used to detect a stack buffer overflow before execution of malicious code can occur**. This method works by placing a small integer, the value of which is randomly chosen at program start, in memory just before the stack return pointer.

### *NX*

***NX*** stands for "***non-executable***." It's often enabled at the CPU level, so an operating system with ***NX*** enabled can mark certain areas of memory as non-executable. Often, buffer-overflow exploits put code on the stack and then try to execute it. However, making this writable area non-executable can prevent such attacks.

### *PIE* 
PIE stands for **Position Independent Executable**, which means that every time you run the file it gets **loaded into a different memory address**. This means you cannot hardcode values such as function addresses and gadget locations without finding out where they are.


