# jakshoo
LD_PRELOAD rootkit

## To-do

- [ ] PAM sniffing (Get SSH, LDAP, etc.. passwords) / Remote exfiltration
- [ ] File content tampering
- [ ] Anti-debugging / Anti-forensics
- [ ] File hiding
- [ ] Network hiding
- [ ] Process hiding
- [ ] backdoor (blind / reverse)

## Usage
### File content tampering
Hide file contents by using tags.

Real file:
```
[victim:~]$ cat test.c                                                                                                                   
#include <stdio.h>
int main(){
	//obfuscate_start
	printf("this is code");
	//obfuscate_stop
	return 0;
}

```

Tampered file:
```
[victim:~]$ export LD_PRELOAD=./libjakshoo.so                                                                                               
[victim:~]$ cat test.c                                                                                                                     
#include <stdio.h>
int main(){
	return 0;
}
[victim:~]$ gcc test.c -o test                                                                                                           
[victim:~]$ ./test                                                                                                                       
this is code%  
```
