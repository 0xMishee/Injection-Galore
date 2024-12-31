#ifndef INFO_H
#define INFO_H
#include <stdio.h>


void informationUsageHelp(IN char* argv[]){ 
    printf("Usage: %s --injection <method> --payload <value> --encryption <type> --enumeration <option>\n", argv[0]);
    printf("Example: <dll> <calc>\n");
}

void injectionMethodsHelp(void){
    printf("-------------------\n");
    printf("1. CreateRemoteThread\n");
    printf("2. <dll> Dll Injection\n");
}

void payloadsHelp(void){
    printf("-------------------\n");
    printf("1. <rs> Reverse Shell\n");
    printf("2. <mb> Message Box\n");
    printf("3. <calc> Calculator\n");
}

void encryptionDecryptionMethodsHelp(void){
    printf("-------------------\n");
    printf("1. XOR\n");
    printf("2. AES\n");
    printf("3. RSA\n");
}

void enumerationMethodsHelp(void){
    printf("-------------------\n");
    printf("1. SnapShot\n");

}

void defaultHelp(char* argv[]){
    informationUsageHelp(&argv[0]);
    injectionMethodsHelp();
    payloadsHelp();
    encryptionDecryptionMethodsHelp();
    enumerationMethodsHelp();
}

#endif // INFO_H
