#ifndef INFO_H
#define INFO_H
#include <stdio.h>


void informationUsageHelp(IN char* argv[]){ 
    printf("Usage: %s --injection <method> --payload <value>\n", argv[0]);
    printf("Example: %s --injection rsc --payload calc\n", argv[0]);
}

void injectionMethodsHelp(void){
    printf("Injection Methods\n");
    printf("-------------------\n");
    printf("1. CreateRemoteThread\n");
    printf("2. <dll> Dll Injection\n");
    printf("3. rdll - Remote DLL\n");
    printf("4. ldll - Local DLL\n");
    printf("5. rsc - Remote Shellcode\n");
    printf("6. lsc - Local Shellcode\n");
    printf("7. apc - Asynchronous Procedure Call\n");
    printf("8. ebapc - Early Bird Asynchronous Procedure Call\n");
    printf("9. lm - Local Mapping\n");
    printf("10. rm - Remote Mapping\n");
    printf("11. lfs - Local Function Stomping\n");
    printf("12. rfs - Remote Function Stomping\n");
    printf("13. lpe - Local PE\n");
    printf("14. redll - Reflective DLL\n");
    printf("15. tl - Threadless\n");
    printf("16. gp - Ghost Process\n");
    printf("17. gh - Ghost Hollowing\n");
    printf("18. hrp - Herpaderping\n");
    printf("19. hrph - Herpaderping Hollowing\n");
    printf("20. ph - Process Hypnosis\n");
    printf("21. kcp - Known Cache Poisoning\n");
    printf("22. ca - Cross Architecture\n");
    printf("23. ab - Atom Bombing\n");
}

void payloadsHelp(void){
    printf("Payloads\n");
    printf("-------------------\n");
    printf("1. <rs> Reverse Shell\n");
    printf("2. <mb> Message Box\n");
    printf("3. <calc> Calculator\n");
}

void defaultHelp(char* argv[]){
    informationUsageHelp(&argv[0]);
    injectionMethodsHelp();
    payloadsHelp();
}

#endif // INFO_H
