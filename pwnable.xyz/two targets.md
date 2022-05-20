看名字，似乎有两种解题方法？

ghidra查看代码
```c
void main(void)

{
  char cVar1;
  int iVar2;
  long in_FS_OFFSET;
  undefined local_48 [32];
  undefined auStack40 [16];
  undefined8 local_18;
  undefined8 local_10;
  
  local_10 = *(undefined8 *)(in_FS_OFFSET + 0x28);
  setup();
  memset(local_48,0,0x38);
LAB_00400b36:
  do {
    while( true ) {
      while( true ) {
        print_menu();
        iVar2 = read_int32();
        if (iVar2 != 2) break;
        printf("nationality: ");
        __isoc99_scanf(&DAT_00401d63,auStack40);
      }
      if (2 < iVar2) break;
      if (iVar2 == 1) {
        printf("name: ");
        __isoc99_scanf("%32s",local_48);                    // A
      }
      else {
LAB_00400c0c:
        puts("Invalid");
      }
    }
    if (iVar2 != 3) {
      if (iVar2 != 4) goto LAB_00400c0c;
      cVar1 = auth(local_48);
      if (cVar1 != '\0') {
        win();
      }
      goto LAB_00400b36;
    }
    printf("age: ");
    __isoc99_scanf(&DAT_00401d6e,local_18);
  } while( true );
}

void read_int32(void)

{
  long in_FS_OFFSET;
  undefined8 local_28;
  undefined8 local_20;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_28 = 0;
  local_20 = 0;
  read(0,&local_28,0x10);
  atoi((char *)&local_28);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}

bool auth(long param_1)

{
  int iVar1;
  long in_FS_OFFSET;
  uint local_40;
  undefined8 local_38;
  undefined8 local_30;
  undefined8 local_28;
  undefined8 local_20;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_38 = 0;
  local_30 = 0;
  local_28 = 0;
  local_20 = 0;
  for (local_40 = 0; local_40 < 0x20; local_40 = local_40 + 1) {                      // B
    *(byte *)((long)&local_38 + (long)(int)local_40) =
         (byte)main[(int)local_40] ^
         (*(char *)(param_1 + (int)local_40) << 4 | *(byte *)(param_1 + (int)local_40) >> 4);
  }
  iVar1 = strncmp((char *)&local_38,&DAT_00401d28,0x20);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return iVar1 == 0;
}

void win(void)

{
  system("cat flag");
  return;
}


```

A处读取一个字符串，在B处做验证，成功后则拿到flag

验证所需要的信息：
```shell
pwndbg> x/32bx main
0x400b04 <main>:        0x55    0x48    0x89    0xe5    0x48    0x83    0xec    0x50
0x400b0c <main+8>:      0x64    0x48    0x8b    0x04    0x25    0x28    0x00    0x00
0x400b14 <main+16>:     0x00    0x48    0x89    0x45    0xf8    0x31    0xc0    0xe8
0x400b1c <main+24>:     0x24    0xfe    0xff    0xff    0x48    0x8d    0x45    0xc0

pwndbg> x/32bx 0x401d28
0x401d28:       0x11    0xde    0xcf    0x10    0xdf    0x75    0xbb    0xa5
0x401d30:       0x43    0x1e    0x9d    0xc2    0xe3    0xbf    0xf5    0xd6
0x401d38:       0x96    0x7f    0xbe    0xb0    0xbf    0xb7    0x96    0x1d
0x401d40:       0xa8    0xbb    0x0a    0xd9    0xbf    0xc9    0x0d    0xff
```

脚本：
```
from pwn import *

arr1 = [0x11, 0xde, 0xcf, 0x10, 0xdf, 0x75, 0xbb, 0xa5, 0x43, 0x1e, 0x9d, 0xc2, 0xe3, 0xbf, 0xf5,
        0xd6, 0x96, 0x7f, 0xbe, 0xb0, 0xbf, 0xb7, 0x96, 0x1d, 0xa8, 0xbb, 0x0a, 0xd9, 0xbf, 0xc9, 0x0d, 0xff]
arr2 = [0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x50, 0x64, 0x48, 0x8b, 0x04, 0x25, 0x28, 0x00,
        0x00, 0x00, 0x48, 0x89, 0x45, 0xf8, 0x31, 0xc0, 0xe8, 0x24, 0xfe, 0xff, 0xff, 0x48, 0x8d, 0x45, 0xc0]


def read32(n):
    return str.encode('%-16s' % (n))


def getPayload():
    payload = read32(1)
    for i in range(len(arr1)):
        v = arr1[i] ^ arr2[i]
        u = ((v << 4) | (v >> 4)) & 0xff
        payload += p8(u)
    payload += read32(4)
    return payload


p = remote('svc.pwnable.xyz', 30031)
# p = process('./challenge')
payload = getPayload()
p.recvuntil(b'>')
p.send(payload)
p.interactive()


```
