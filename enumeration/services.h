#ifndef SERVICES_H
#define SERVICES_H

typedef struct {
    char serviceName[MAX_PATH];
    DWORD serviceType;
    DWORD serviceState;
} serviceInfo, *pServiceInfo;

static const char* antiAnalysisServices[] = {
    "vmtoolsd",
    "vmwareuser",
    "vmacthlp",
    "vmtoolsd",
    "vmrawdsk",
    "vmusrvc",
};


#endif // SERVICES_H
