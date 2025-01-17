#ifndef PAYLOADS_H
#define PAYLOADS_H

#include <stdio.h>

/*
Since the payloadsize are const and external, we need to define them here. 
Otherwise the compiler will scream about trying to figoure out the size of the array before it's initialized.
I don't like this solution, but it works for now. 
*/

// Payloads
extern const unsigned char payloadCalc[];
extern const unsigned char payloadBindShell[];

// Payload sizes
#define PAYLOAD_CALC_SIZE 354
#define PAYLOAD_BIND_SHELL_SIZE 341



#endif // PAYLOADS_H
