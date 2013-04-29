
#ifndef _HASHTABLE_H
#define _HASHTABLE_H


#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <pthread.h>
#include <errno.h>

#include "assert.h"
#include "sdbg.h"
#include "defs.h"


// hashtable types
#define HT_KEY_STR      10
#define HT_KEY_UINT     11

#define HT_VAL_INT      12
#define HT_VAL_UINT     13
#define HT_VAL_VOIDP    14


// structures

// hashtable node
typedef struct _hashTableNode {
    union _key {
        char *skey;
        unsigned int ukey;
    }key;
    
    union _val {
        unsigned int uval;
        int ival;
        void *vval;
    }val;
    
    int valsize;
    
    struct _hashTableNode *pnext;
}HT_NODE;


// hashtable itself
typedef struct _hashtable {
    int htKeyType;
    int htValType;
    HT_NODE **phtNodes;
    unsigned int uSize;
    pthread_mutex_t muAccess;
}HTABLE;


// functions
unsigned int _hashu(unsigned int tablesize, unsigned int key);
unsigned int _hashs(unsigned int tablesize, const char *key, int keysize);

BOOL HT_fCreate(HTABLE **pHTableOut, int nTableSize, int keyType, int valType);
BOOL HT_fDestroy(HTABLE *phtable);

BOOL HT_fInsert(HTABLE *phtable, void *pvkey, int keySize, void *pval, int valSize);
BOOL HT_fFind(HTABLE *phtable, void *pvkey, int keySize, void *pval, int *pvalsize);
BOOL HT_fRemove(HTABLE *phtable, void *pvkey, int keySize);
void HT_vDumpTable(HTABLE *phtable);

#endif // _HASHTABLE_H
