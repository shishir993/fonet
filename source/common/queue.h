
#ifndef _QUEUE_H
#define _QUEUE_H


#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <pthread.h>
#include <errno.h>

#include "assert.h"
#include "sdbg.h"
#include "defs.h"


// structures

// a queue item
typedef struct _queueNode {
    void *pval;
    int valsize;
    struct _queueNode *pnext;
}QNODE;


// the queue itself
typedef struct _queue {
    int numElems;
    struct _queueNode *pfront;
    struct _queueNode *prear;
    pthread_mutex_t muAccess;
    
}QUEUE;


// functions
BOOL Q_fCreate(QUEUE **pQueueOut);
BOOL Q_fDestroy(QUEUE *pQueue);

BOOL Q_fInsert(QUEUE *pQueue, void *pval, unsigned int valsize);
BOOL Q_fDelete(QUEUE *pQueue, void *pvalbuf, unsigned int valbufsize);

#endif //_QUEUE_H
