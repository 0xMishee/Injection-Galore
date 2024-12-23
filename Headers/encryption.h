#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <stdio.h>
#include <Windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

#include "error.h"

#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)
#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)

#define IVSIZE 16
#define KEYSIZE 32

typedef struct _AES {

	PBYTE	pPlainText;        
	DWORD	dwPlainSize;       

	PBYTE	pCipherText;       
	DWORD	dwCipherSize;      

	PBYTE	pKey;             
	PBYTE	pIV;              

} AES, *PAES;

// AES Encryption
BOOL EncrypAesData(PAES pAes){

    BOOL                bState          = TRUE;

    BCRYPT_ALG_HANDLE   hAesAlg         = NULL;
    BCRYPT_KEY_HANDLE   hKeyHandle      = NULL;

    ULONG               cbResult        = 0;

    DWORD               dwBlockSize     = 0,
                        cbKeyObject     = 0,
                        cbCipherText    = 0;

    PBYTE               pbCipherText    = NULL,
                        pbKeyObject     = NULL;  

    NTSTATUS            status          = 0;


    // Initialize the BCRYPT provider
    status = BCryptOpenAlgorithmProvider(&hAesAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(status)){
        handleError(ERROR_BCRYPT_FAILED, "BCryptOpenAlgorithmProvider failed");
        bState = FALSE;
        goto Cleanup;
    };

    // Get size of key
    status = BCryptGetProperty(hAesAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(DWORD), &cbResult, 0);
    if (!NT_SUCCESS(status)){
        handleError(ERROR_BCRYPT_FAILED, "BCryptGetProperty failed");
        bState = FALSE;
        goto Cleanup;
    };

    // Get size of block
    status = BCryptGetProperty(hAesAlg, BCRYPT_BLOCK_LENGTH, (PBYTE)&dwBlockSize, sizeof(DWORD), &cbResult, 0);
    if (!NT_SUCCESS(status)){
        handleError(ERROR_BCRYPT_FAILED, "BCryptGetProperty failed");
        bState = FALSE;
        goto Cleanup;
    };

    // Check block size
    if (dwBlockSize != 16){
        handleError(ERROR_BCRYPT_FAILED, "Block size is incorrect");
        bState = FALSE;
        goto Cleanup;
    };

    // Allocate memory for key object
    pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
    if (pbKeyObject == NULL) {
        handleError(ERROR_FAILED_TO_ALLOCATE_MEMORY, "Failed to allocate memory for key object");
        bState = FALSE;
        goto Cleanup;
    }

    // Select Mode to CBC
    status = BCryptSetProperty(hAesAlg, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!NT_SUCCESS(status)){
        handleError(ERROR_BCRYPT_FAILED, "BCryptSetProperty failed");
        bState = FALSE;
        goto Cleanup;
    };

    // Generate key from supplied key bytes
    status = BCryptGenerateSymmetricKey(hAesAlg, &hKeyHandle, pbKeyObject, cbKeyObject, (PBYTE)pAes->pKey, KEYSIZE, 0);
    if (!NT_SUCCESS(status)){
        handleError(ERROR_BCRYPT_FAILED, "BCryptGenerateSymmetricKey failed");
        bState = FALSE;
        goto Cleanup;
    };

    // Run with NULL to get output size
    status = BCryptEncrypt(hKeyHandle, (PUCHAR)pAes->pPlainText, (ULONG)pAes->dwPlainSize, NULL, pAes->pIV, IVSIZE, NULL, 0, &cbCipherText, BCRYPT_BLOCK_PADDING);
    if (!NT_SUCCESS(status)){
        handleError(ERROR_BCRYPT_FAILED, "BCryptEncrypt failed");
        bState = FALSE;
        goto Cleanup;
    };

    // Allocate memory for cipher text
    pbCipherText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbCipherText);
    if (pbCipherText == NULL){
        handleError(ERROR_FAILED_TO_ALLOCATE_MEMORY, "Failed to allocate memory for cipher text");
        bState = FALSE;
        goto Cleanup;
    };

    // Encrypt the data
    status = BCryptEncrypt(hKeyHandle, (PUCHAR)pAes->pPlainText, (ULONG)pAes->dwPlainSize, NULL, pAes->pIV, IVSIZE, pbCipherText, cbCipherText, &cbResult, BCRYPT_BLOCK_PADDING);
    if (!NT_SUCCESS(status)){
        handleError(ERROR_BCRYPT_FAILED, "BCryptEncrypt failed");
        bState = FALSE;
        goto Cleanup;
    };

    Cleanup:
    if (hKeyHandle){
        BCryptDestroyKey(hKeyHandle);
    };
    if (hAesAlg){
        BCryptCloseAlgorithmProvider(hAesAlg, 0);
    };
    if (pbKeyObject){
        HeapFree(GetProcessHeap(), 0, pbKeyObject);
    };
    if (pbCipherText != NULL && bState){
        pAes->pCipherText = pbCipherText;
        pAes->dwCipherSize = cbCipherText;
    }

    return bState;
};

BOOL AesEncryptionInit(IN PBYTE pPlainTextData, IN DWORD sPlainTextSize, IN PBYTE pKey, IN PBYTE pIV, OUT PVOID* pCipherTextData, OUT DWORD* sCipherTextSize){
    
    if (pPlainTextData == NULL || sPlainTextSize == 0 || pKey == NULL || pIV == NULL ){
        handleError(ERROR_AES_INIT_FAILED, "One or more arguments returned NULL");
        return FALSE;
    }

    AES aes;
    aes.pKey = pKey;
    aes.pIV = pIV;
    aes.pPlainText = pPlainTextData;
    aes.dwPlainSize = sPlainTextSize;
    
    if (!EncrypAesData(&aes)){
        handleError(ERROR_AES_INSTALL_FAILED, "Failed to encrypt data");
        return FALSE;
    }

    *pCipherTextData = aes.pCipherText;
    *sCipherTextSize = aes.dwCipherSize;

    return TRUE;
    
};


#endif // ENCRYPTION_H