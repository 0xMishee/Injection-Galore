#ifndef HASH_TABLE_H
#define HASH_TABLE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Hash Table
typedef struct {
    char *key;
    char *value;
} hashTable, *pHashTable;


#endif // HASH_TABLE_H