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
- [ ] clipper malware
- [ ] rootkit cloaking
- [ ] keylogging

## Usage
### File content tampering
### Current state: 
- Done with stack based binaries, issues with data stored on heap
- To-do: hook implementations for `libstdc++.so.6`

Hide file contents by using tags.

Real file:
```
[victom]$ cat program.c                                                                                                                   
#include <stdio.h>
//obfuscate_start
void malicious_func(){
	printf("Evil func!");
}
//obfuscate_stop
int main(){
	printf("nice code!");
	//obfuscate_start
	printf("malicious code >:) muahaha");
	malicious_func();
	//obfuscate_stop
	printf("nice code, again! xD");
	return 0;
}
```

Tampered file:
```
[victim]$ export LD_PRELOAD=./libjakshoo.so                                                                                             
[victim]$ cat test.c                                                                                                                   
#include <stdio.h>
int main(){
	printf("nice code!\n");
	printf("nice code, again! xD\n");
	return 0;
}
[victim]$ gcc test.c -o test                                                                                                           
[victim]$ ./test                                                                                                                       
nice code!
malicious code >:) muahaha
Evil func!
nice code, again! xD

```
