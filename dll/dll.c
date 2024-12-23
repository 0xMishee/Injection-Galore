#include <stdio.h>
#include <windows.h>

void ShowMessageBox() {
    MessageBoxA(NULL, "This is a message box", "Message Box", MB_OK | MB_ICONINFORMATION);
}

BOOL APIENTRY DllMain (HMODULE hModule, DWORD dwReason, LPVOID lpReserved){


    switch (dwReason){
        case DLL_PROCESS_ATTACH: {
            ShowMessageBox();
            break;
        };
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            break;
    }

    return TRUE;
}