# First level

## Program summary
Nothing special, a comparison takes place on the element retrieved by **`scanf()`**. In the conclusive case we obtain a shell spawn with root privileges, otherwise a password refusal log.

```c
bool main(void)
{
  int local_14 [4];
  puts("***********************************");
  puts("* \t     -Level00 -\t\t  *");
  puts("***********************************");
  printf("Password:");
  __isoc99_scanf(&DAT_08048636,local_14);
  if (local_14[0] != 0x149c) {
    puts("\nInvalid Password!");
  }
  else {
    puts("\nAuthenticated!");
    system("/bin/sh");
  }
  return local_14[0] != 0x149c; // 5276
}
```

## Vulnerability
The program's vulnerability lies in a comparison takes place on the element retrieved by **`scanf()`**, so you have to enter 0x149c / 5276.

## Attack design
Enter 0x149c / 5276 at the password prompt.

> Flag : `uSq2ehEGT6c9S24zbshexZQBXUGrncxn5sD5QfGL`
