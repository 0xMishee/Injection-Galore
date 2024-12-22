#ifndef INFO_H
#define INFO_H
#include <stdio.h>


void informationUsageHelp() {
    printf("Usage: <injection> <payload> <encryption> <>\n");
    printf("Example: <dll> <calc>\n");
}

void injectionMethodsHelp(){
    printf("1. CreateRemoteThread\n");
    printf("2. <dll> Dll Injection\n");
}

void payloadsHelp(){
    printf("1. Reverse Shell\n");
    printf("2. Message Box\n");
    printf("3. <calc> Calculator\n");
}

void encryptionDecryptionMethodsHelp(){
    printf("1. XOR\n");
    printf("2. AES\n");
    printf("3. RSA\n");
}

void enumerationMethodsHelp(){
    printf("1. SnapShot\n");

}


#endif // INFO_H
