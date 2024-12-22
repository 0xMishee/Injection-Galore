#ifndef PROCESS_H
#define PROCESS_H

#include <windows.h>

typedef struct {
    char processName[MAX_PATH];
    DWORD processID;
} processInfo, *pProcessInfo;

static const char* antiAnalysisProcesses[] = {
    "ollydbg.exe",
    "wireshark.exe",
    "tcpview.exe",
    "autoruns.exe",
    "autorunsc.exe",
    "filemon.exe",
    "procmon.exe",
    "regmon.exe",
    "procexp.exe",
    "idaq.exe",
    "idaq64.exe",
    "idag.exe",
    "idag64.exe",
    "idaw.exe",
    "idaw64.exe",
    "ida.exe",
    "idau.exe",
    "idau64.exe",
    "idaq.exe",
    "ImmunityDebugger.exe",
    "dumpcap.exe",
    "HookExplorer.exe",
    "ImportREC.exe",
    "PEiD.exe",
    "LordPE.exe",
    "dumpcap.exe",
    "SysInspector.exe",
    "proc_analyzer.exe",
    "sysAnalyzer.exe",
    "sniff_hit.exe",
    "windbg.exe",
    "joeboxcontrol.exe",
    "joeboxserver.exe",
    "joeboxserver_svc.exe",
    "vmtoolsd.exe",
    "vmwareuser.exe",
    "vmacthlp.exe",
    "vmtoolsd.exe",
    "vmrawdsk.exe",
    "vmusrvc.exe",
    "Discord.exe", // Testing
    "WeChat.exe" // Testing
};

#endif // PROCESS_H