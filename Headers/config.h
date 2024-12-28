#ifndef CONFIG_H
#define CONFIG_H

const char *injectionMethodsValue[] = {
    "rdll", 
    "ldll",
    "rsc", 
    "lsc",
    "apc",
    "ebapc",
    "lm",
    "rm",
    "lfs",
    "rfs",
    "lpe",
    "redll",
    "tl",
    "gp",
    "gh",
    "hrp",
    "hrph",
    "ph",
    "kcp",
    "ca",
};

const char *payloadsValue[] = {
    "Reverse Shell",
    "Message Box",
    "Calculator"
};

const char *encryptionDecryptionMethodsValue[] = {
    "XOR",
    "AES",
    "RSA"
};

const char *enumerationMethodsValue[] = {
    "SnapShot"
};


#endif // CONFIG_H