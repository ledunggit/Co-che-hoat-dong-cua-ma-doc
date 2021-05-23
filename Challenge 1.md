# Co-che-hoat-dong-cua-ma-doc - challenge CTF Write up
```html
ELF x86 - Stack buffer overflow basic 1 :  ssh -p 2222 app-systeme-ch13@challenge02.root-me.org
```

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
