
# Co-che-hoat-dong-cua-ma-doc - challenge 5 CTF Write up
```html
ELF x86 - Stack buffer overflow basic 4: ssh -p 2222 app-systeme-ch8@challenge02.root-me.org 
```

![image](https://user-images.githubusercontent.com/64201705/120130184-bac8d300-c1ef-11eb-9a06-2c075e009029.png)

## Write up

```Text
Sau khi SSH vào server thì ta dùng lệnh cat để in code trong file source code ra
app-systeme-ch8@challenge02:~$ cat ch8.c
```
Ta sẽ được như này:
```C
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>

struct EnvInfo
{
  char home[128];
  char username[128];
  char shell[128];
  char path[128];
};


struct EnvInfo GetEnv(void)
{
  struct EnvInfo env;
  char *ptr;

  if((ptr = getenv("HOME")) == NULL)
    {
      printf("[-] Can't find HOME.\n");
      exit(0);
    }
  strcpy(env.home, ptr);
  if((ptr = getenv("USERNAME")) == NULL)
    {
      printf("[-] Can't find USERNAME.\n");
      exit(0);
    }
  strcpy(env.username, ptr);
  if((ptr = getenv("SHELL")) == NULL)
    {
      printf("[-] Can't find SHELL.\n");
      exit(0);
    }
  strcpy(env.shell, ptr);
  if((ptr = getenv("PATH")) == NULL)
    {
      printf("[-] Can't find PATH.\n");
      exit(0);
    }
  strcpy(env.path, ptr);
  return env;
}

int main(void)
{
  struct EnvInfo env;

  printf("[+] Getting env...\n");
  env = GetEnv();

  printf("HOME     = %s\n", env.home);
  printf("USERNAME = %s\n", env.username);
  printf("SHELL    = %s\n", env.shell);
  printf("PATH     = %s\n", env.path);

  return 0;
}
```
Đối với challenge này, ta thấy chương trình sẽ load biến môi trường lên và sử dụng hàm `strcpy` để thực hiện copy env đó qua con trỏ ptr. Vì thế, ta sẽ nghĩ tới việc chương trình sẽ load đoạn shell code do ta chuẩn bị nằm trong biến môi trường và copy qua con trỏ. Sau đó sẽ ghi đè câu lệnh return 0 để gọi tới hàm có địa chỉ nằm trong shell code.
Đầu tiên ta thấy chương trình cần biến môi trường `USERNAME` cho nên ta sẽ export biến này trước: `export USERNAME=AAAA`
Sau khi gọi hàm Getenv() và gần tới câu lệnh return, stack sẽ có dạng:
```
            +----------------------------+
            |      HOME env variable     |     %ebp - 540
            +----------------------------+
            |    USERNAME env variable   |     %ebp - 412
            +----------------------------+
            |      SHELL env variable    |     %ebp - 284
            +----------------------------+
            |      PATH env variable     |     %ebp - 156
            +----------------------------+
            |           saved ebp        |
            +----------------------------+
            |        return address      |     %ebp + 4
            +----------------------------+
            |   rep movsl dest. address  |     %ebp + 8
            +----------------------------+  
```
