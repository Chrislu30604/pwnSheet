- [BASIC](#basic)
	- [BufferOverFlow](#bufferoverflow)
		- [Vunerability](#vunerability)
		- [Application](#application)
	- [GOT Hijacking](#got-hijacking)
	- [ROP (Return Oriented Programming)](#rop-return-oriented-programming)
	- [Fmt (Format String Attack)](#fmt-format-string-attack)
		- [Introduction](#introduction)
		- [Fmt write](#fmt-write)
		- [Fmt Reference](#fmt-reference)
- [Advanced](#advanced)
	- [Fastbin Dup Attack](#fastbin-dup-attack)
		- [Vunerability](#vunerability-1)
		- [Application](#application-1)
		- [__malloc_hook](#mallochook)
	- [Unsafe Unlink](#unsafe-unlink)
		- [Unsafe Unlink](#unsafe-unlink-1)
		- [Application](#application-2)
		- [__free_hook](#freehook)

# BASIC

## BufferOverFlow

### Vunerability

- 誤用沒檢查**input_size**的function, 如**get**,**cin**
	```C++
	int main() {
		char buf[1024];
		cout << "BOF";
		cin >> buf;
		cout << buf << endl;
	}
	```

	```
	0000| 0x7fffffffdb98 ('1' <repeats 41 times>)
    0008| 0x7fffffffdba0 ('1' <repeats 33 times>)
    0016| 0x7fffffffdba8 ('1' <repeats 25 times>)
    0024| 0x7fffffffdbb0 ('1' <repeats 17 times>)
    0032| 0x7fffffffdbb8 ("111111111")  # return address
    0040| 0x7fffffffdbc0 --> 0x31 ('1')
    0048| 0x7fffffffdbc8 --> 0x424f7cc5205bcf17 
    0056| 0x7fffffffdbd0 --> 0x555555554870 (<_start>:      xor    ebp,ebp)
	```

- Canary : stack上return前會安插一個隨機值, 來確保程式沒有被惡意操作

### Application
- BOF-ret2Code
	```C
	#include <stdio.h>
	#include <stdlib.h>

	void spawn_shell() {
		system("sh");
	}
	
	int main(int argc, char const *argv[]){
		char buffer[16];
		gets(buffer)
		return 0;
	}
	```
	
	- Find address
		1. **% objdump** -M -d shell | less</div>
		2. **gdb-peda$** p shell</div>
		3. **r2$** afl ~shell</div>

- BOF-ret2Libc
	- 透過libc不會用到的函式**system, execve**, get_shell
	- leak libc ?
    	- stack上
    	- GOT_Hijacking


## GOT Hijacking
- 改寫**GOT**區段
- 不能是**FULL RELRO Protection**

## ROP (Return Oriented Programming)
- 串接code區段所有....ret 的組語
- 配合有限的BOF使用 (可能return到system時, 某些條件尚未滿足)
	```C
	# X86 syscall of system
	rax = 0x3b
	rdi = address ->'/bin/sh\x00'
	rsi = 0
	rdx = 0
	```

## Fmt (Format String Attack)

### Introduction
- Format string
	```C
	int printf(const char *format, ...);
	int fprintf(FILE *stream, const char *format,...);
	int printf(const char *format, va_list arg);
	int vfprintf(FILE *stream, const char *format, va_list arg)
	int vdprintf(int fd, const char *format, va_list ap);
	int dprintf(int fd, const char *format, ...);
	```

- fmt Format
	```C
	printf(buf)
	```

- fmt sequence
    - rdi, rsi, rdx, rcx, r8, r9, STACK
	- %d, %p, %s, %c, %x -> read data on stack 

- Example 
	```C
    #include <stdio.h> 
    #include <stdlib.h> 

    int main(int argc, char *argv[]) 
    { 
        char bof[0x100]; 

        printf("Enter your fmt\n"); 
        scanf("%s", bof); 
        printf(bof); 
        return 0; 
    } 
	```
	<img src='https://i.imgur.com/lqW2LpJ.png' width=800px></img>


### Fmt write
- <div class='word'>%n</div> : 將已輸出的**字元數目**當成Integer值(4 bytes) 寫入address.

	```C
	#include <stdio.h>
	int main(int argc, char *argv[]){
	    int a = 0;
	    printf("a = %d\n", a);
	    printf("Hi%n\n", &a);
	    printf("a = %d\n", a);
	    return 0;
	}
	/** Output
	a = 0
	Hi
	a = 2
	*/
	```

- <div class='word'>%100c%n</div> 寫入4 bytes\x64\x00\x00\x00
- <div class='word'>%100c%hn</div> 寫入 2 bytes \x64\x00
- <div class='word'>%100c%hhn</div> 寫入 1 bytes \x64


### Fmt Reference
- <div class='word'>%ref%p</div> leak
- <div class='word'>%ref%n</div> write

```python
payload = ('%45068c%22$hn%19138c%23$hnAAA%8$p.%9$pAAA%24$s')
```

# Advanced

## Fastbin Dup Attack

### Vunerability
- free時沒有清空pointer或做檢查
- 藉由 <div class='word'>free(a); free(b); free(a);	</div> 繞過double free檢查
	```C
	void *p1 = malloc(0x48);
	void *p2 = malloc(0x48);
	free(p1);
	free(p2);
	free(p1);
	```
### Application
- 此時在malloc相同chuck大小時, 可以任意malloc在**相同chuck**大小位置
	```C
	malloc(0x48, fake_address);
	malloc(0x48, 'aaa');
	malloc(0x48, 'aaa');
	malloc(0x48, your_payload_in_fake_address);
	```

### __malloc_hook
- 在每次malloc時, 會確認malloc_hook是否有值,如果有值會call malloc_hook所存的address,因此可以藉由faskbin dup attack 將function address寫到malloc hook

## Unsafe Unlink
- 條件
	1. 一個指向Heap內的指標
	2. 放該指標的位置已知
	3. 可對該指標寫入多次（可以寫到其他Chunk)

### Unsafe Unlink
- <div class='word'>p->fd=&p-0x18</div>
- <div class='word'>p->bk=&p-0x10</div>

### Application
1. 欺騙它前面Chuck被free掉 -> 對前chuck做unlink
	```
	// chuck 1
	0x603000: 0x0000000000000000 0x0000000000000111
	0x603010: 0x6161616161616161 0x6161616161616161
	0x603020: 0x6161616161616161 0x6161616161616161
	0x603030: 0x6161616161616161 0x6161616161616161
	0x603040: 0x6161616161616161 0x6161616161616161
	0x603050: 0x6161616161616161 0x6161616161616161
	0x603060: 0x6161616161616161 0x6161616161616161
	0x603070: 0x6161616161616161 0x6161616161616161
	0x603080: 0x6161616161616161 0x6161616161616161
	0x603090: 0x6161616161616161 0x6161616161616161
	0x6030a0: 0x6161616161616161 0x6161616161616161
	0x6030b0: 0x6161616161616161 0x6161616161616161
	0x6030c0: 0x6161616161616161 0x6161616161616161
	0x6030d0: 0x6161616161616161 0x6161616161616161
	0x6030e0: 0x6161616161616161 0x6161616161616161
	0x6030f0: 0x6161616161616161 0x6161616161616161
	0x603100: 0x6161616161616161 0x6161616161616161
	// chuck 2
	0x603110: 0x0000000000000110 0x0000000000000110
	```
2. 假設全域pointer指向0x603010-> 必須改寫fake chunk, 並寫入fd bk , p-0x18, p-0x10 where p=0x602040
	```
		```
	// chunk 1
	0x603000: 0x0000000000000000 0x0000000000000111
	0x603010: 0x0000000000000000 0x0000000000000101
	0x603020: 0x0000000000602028 0x0000000000602030
	0x603030: 0x6161616161616161 0x6161616161616161
	0x603040: 0x6161616161616161 0x6161616161616161
	0x603050: 0x6161616161616161 0x6161616161616161
	0x603060: 0x6161616161616161 0x6161616161616161
	0x603070: 0x6161616161616161 0x6161616161616161
	0x603080: 0x6161616161616161 0x6161616161616161
	0x603090: 0x6161616161616161 0x6161616161616161
	0x6030a0: 0x6161616161616161 0x6161616161616161
	0x6030b0: 0x6161616161616161 0x6161616161616161
	0x6030c0: 0x6161616161616161 0x6161616161616161
	0x6030d0: 0x6161616161616161 0x6161616161616161
	0x6030e0: 0x6161616161616161 0x6161616161616161
	0x6030f0: 0x6161616161616161 0x6161616161616161
	0x603100: 0x6161616161616161 0x6161616161616161
	// chunk 2
	0x603110: 0x0000000000000100 0x0000000000000110
	```
3. free掉chunk 2後, 此時此pointer就指向0x602028

### __free_hook
- __free_hook為當free時, 會呼叫的function
- __free_hook前方幾乎都是0
