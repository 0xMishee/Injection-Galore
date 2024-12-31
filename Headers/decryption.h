#ifndef DECRIPTION_H
#define DECRIPTION_H

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

// AES Decryption
BOOL DecryptAesData(PAES pAes) {
    BOOL bState = TRUE;

    BCRYPT_ALG_HANDLE hAesAlg = NULL;
    BCRYPT_KEY_HANDLE hKeyHandle = NULL;

    ULONG cbResult = 0;

    PBYTE pbKeyObject = NULL,
          pbPlainText = NULL;

    DWORD dwBlockSize = 0,
          cbKeyObject = 0,
          cbPlainText = 0;

    NTSTATUS status;

    // Initialize the BCRYPT provider
    status = BCryptOpenAlgorithmProvider(&hAesAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(status)) {
        handleError(ERROR_BCRYPT_FAILED, "BCryptOpenAlgorithmProvider failed");
        bState = FALSE;
        goto Cleanup;
    }

    // Get size of key
    status = BCryptGetProperty(hAesAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(DWORD), &cbResult, 0);
    if (!NT_SUCCESS(status)) {
        handleError(ERROR_BCRYPT_FAILED, "BCryptGetProperty failed");
        bState = FALSE;
        goto Cleanup;
    }

    // Get size of block
    status = BCryptGetProperty(hAesAlg, BCRYPT_BLOCK_LENGTH, (PBYTE)&dwBlockSize, sizeof(DWORD), &cbResult, 0);
    if (!NT_SUCCESS(status)) {
        handleError(ERROR_BCRYPT_FAILED, "BCryptGetProperty failed");
        bState = FALSE;
        goto Cleanup;
    }

    // Check block size
    if (dwBlockSize != 16) {
        handleError(ERROR_BCRYPT_FAILED, "Block size is incorrect");
        bState = FALSE;
        goto Cleanup;
    }

    // Allocate Memory for key object
    pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
    if (pbKeyObject == NULL) {
        handleError(ERROR_FAILED_TO_ALLOCATE_MEMORY, "Failed to allocate memory for key object");
        bState = FALSE;
        goto Cleanup;
    }

    // Select Mode to CBC
    status = BCryptSetProperty(hAesAlg, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!NT_SUCCESS(status)) {
        handleError(ERROR_BCRYPT_FAILED, "BCryptSetProperty failed");
        bState = FALSE;
        goto Cleanup;
    }

    // Generate key from supplied key bytes
    status = BCryptGenerateSymmetricKey(hAesAlg, &hKeyHandle, pbKeyObject, cbKeyObject, (PBYTE)pAes->pKey, KEYSIZE, 0);
    if (!NT_SUCCESS(status)) {
        handleError(ERROR_BCRYPT_FAILED, "BCryptGenerateSymmetricKey failed");
        bState = FALSE;
        goto Cleanup;
    }

    // Run with NULL to get output size
    status = BCryptDecrypt(hKeyHandle, (PUCHAR)pAes->pCipherText, (ULONG)pAes->dwCipherSize, NULL, pAes->pIV, IVSIZE, NULL, 0, &cbPlainText, BCRYPT_BLOCK_PADDING);
    if (!NT_SUCCESS(status)) {
        handleError(ERROR_BCRYPT_FAILED, "BCryptDecrypt failed");
        bState = FALSE;
        goto Cleanup;
    }

    // Allocate memory for plain text
    pbPlainText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbPlainText); 
    if (pbPlainText == NULL) {
        handleError(ERROR_FAILED_TO_ALLOCATE_MEMORY, "Failed to allocate memory for plain text");
        bState = FALSE;
        goto Cleanup;
    }

    // Decrypt the data
    status = BCryptDecrypt(hKeyHandle, (PUCHAR)pAes->pCipherText, (ULONG)pAes->dwCipherSize, NULL, pAes->pIV, IVSIZE, pbPlainText, cbPlainText, &cbResult, BCRYPT_BLOCK_PADDING);
    if (!NT_SUCCESS(status)) {
        handleError(ERROR_BCRYPT_FAILED, "BCryptDecrypt failed second time");
        bState = FALSE;
        goto Cleanup;
    }

    // Null-terminate the decrypted string
    pbPlainText[cbPlainText] = '\0';

Cleanup:
    if (hKeyHandle) {
        BCryptDestroyKey(hKeyHandle);
    }
    if (hAesAlg) {
        BCryptCloseAlgorithmProvider(hAesAlg, 0);
    }
    if (pbKeyObject) {
        HeapFree(GetProcessHeap(), 0, pbKeyObject);
    }
    if (pbPlainText != NULL && bState) {
        pAes->pPlainText = pbPlainText;
        pAes->dwPlainSize = cbPlainText;
    }

    return bState;
}

BOOL AesDecryptionInit(IN PBYTE pCipherTextData, IN DWORD sCipherTextSize, IN PBYTE pKey, IN PBYTE pIV, OUT PVOID* pPlainTextData, OUT DWORD* sPlainTextSize){

    if (pCipherTextData == NULL || sCipherTextSize == 0 || pKey == NULL || pIV == NULL ){
        handleError(ERROR_AES_INIT_FAILED, "One or more arguments returned NULL");
        return FALSE;
    }

    AES aes = {0};
    aes.pKey = pKey;
    aes.pIV = pIV;
    aes.pCipherText = pCipherTextData;
    aes.dwCipherSize = sCipherTextSize;
    
    if (!DecryptAesData(&aes)){
        handleError(ERROR_AES_INSTALL_FAILED, "Failed to decrypt AES data");
        return FALSE;
    }

    *pPlainTextData = aes.pPlainText;
    *sPlainTextSize = aes.dwPlainSize;
    
    return TRUE;
};



#endif // DECRIPTION_H
