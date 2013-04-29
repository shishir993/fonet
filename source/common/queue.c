
#include "queue.h"


static void vDeleteNode(QNODE *pnode);


BOOL Q_fCreate(QUEUE **pQueueOut)
{
    ASSERT(pQueueOut);
    
    QUEUE *pnewQ = NULL;
    
    
    if( (pnewQ = (QUEUE*)malloc(sizeof(QUEUE))) == NULL )
    {
        logerr("Q_fCreate(): malloc() ");
        goto error_return;
    }
    
    memset(pnewQ, 0, sizeof(QUEUE));
    pthread_mutex_init(&pnewQ->muAccess, NULL);
    *pQueueOut = pnewQ;
    return TRUE;
    
    error_return:
    *pQueueOut = NULL;
    return FALSE;
    
}// Q_fCreate()


BOOL Q_fDestroy(QUEUE *pQueue)
{
    ASSERT(pQueue);
    
    int nelems;
    QNODE *pcurnode;
    QNODE *pnextnode;
    
    if(pthread_mutex_lock(&pQueue->muAccess) != 0)
    {
        logerr("Q_fDestroy(): mutex lock ");
        return FALSE;
    }

    pcurnode = pQueue->pfront;
    while(pcurnode && pcurnode != pQueue->prear)
    {
        pnextnode = pcurnode->pnext;
        vDeleteNode(pcurnode);
        pcurnode = pnextnode;
    }// while pcurnode
    
    if(pcurnode)
        vDeleteNode(pcurnode);
    
    pthread_mutex_destroy(&pQueue->muAccess);
    DBG_MEMSET(pQueue, sizeof(QUEUE));
    free(pQueue);
    return TRUE;
    
}// Q_fDestroy()


static void vDeleteNode(QNODE *pnode)
{
    if(pnode->pval) free(pnode->pval);
#ifdef _DEBUG
    memset(pnode, 0xCC, sizeof(QNODE));
#endif
    free(pnode);

}// vDeleteNode()


BOOL Q_fInsert(QUEUE *pQueue, void *pval, unsigned int valsize)
{
    ASSERT(pQueue && pval);
    
    QNODE *pnewnode;
    QNODE *pfront, *prear;
    BOOL fLocked = FALSE;
    
    
    if((pnewnode = (QNODE*)malloc(sizeof(QNODE))) == NULL)
    {
        logerr("Q_fInsert(): malloc() ");
        goto error_return;
    }
    
    if((pnewnode->pval = malloc(valsize)) == NULL)
    {
        logerr("Q_fInsert(): malloc() ");
        goto error_return;
    }
    memcpy(pnewnode->pval, pval, valsize);
    pnewnode->valsize = valsize;
    pnewnode->pnext = NULL;
    
    if(pthread_mutex_lock(&pQueue->muAccess) != 0)
    {
        logerr("Q_fDestroy(): mutex lock ");
        return FALSE;
    }
    fLocked = TRUE;
    
    if(pQueue->numElems == 0)
    {
        pQueue->pfront = pnewnode;
        pQueue->prear = pnewnode;
        pQueue->numElems = 1;
    }// if numElems == 0
    else
    {
        pQueue->prear->pnext = pnewnode;
        pQueue->prear = pnewnode;
        pQueue->numElems += 1;
    }
    
    if(pthread_mutex_unlock(&pQueue->muAccess) != 0)
    {
        logerr("HT_fInsert_UV(): mutex unlock ");
        goto delete_newnode;
    }
    return TRUE;
    
    
    delete_newnode:
    vDeleteNode(pnewnode);
    
    error_return:
    if(fLocked && pthread_mutex_unlock(&pQueue->muAccess) != 0)
        logerr("HT_fInsert_UV(): mutex unlock ");
    return FALSE;
    
    
}// Q_fInsert()


BOOL Q_fDelete(QUEUE *pQueue, void *pvalbuf, unsigned int valbufsize)
{
    ASSERT(pQueue && pvalbuf);
    
    QNODE *pdelnode;
    BOOL fLocked = FALSE;
    

    if(pthread_mutex_lock(&pQueue->muAccess) != 0)
    {
        logerr("Q_fDelete(): mutex lock ");
        return FALSE;
    }
    fLocked = TRUE;
    
    if(pQueue->numElems == 0)
    {
        logwarn("Q_fDelete(): Underflow!");
        goto error_return;
    }// if numElems == 0
    else if(pQueue->numElems == 1)
    {
        pdelnode= pQueue->pfront;
        if(!fCopyVal(pdelnode, pvalbuf, valbufsize))
        {
            logwarn("Q_fDelete(): Not enough buffer memory");
            goto error_return;
        }
        vDeleteNode(pdelnode);
        pQueue->pfront = pQueue->prear = NULL;
        pQueue->numElems = 0;
    }
    else
    {
        pdelnode= pQueue->pfront;
        if(!fCopyVal(pdelnode, pvalbuf, valbufsize))
        {
            logwarn("Q_fDelete(): Not enough buffer memory");
            goto error_return;
        }
        pdelnode = pQueue->pfront;
        pQueue->pfront = pQueue->pfront->pnext;
        vDeleteNode(pdelnode);
        pQueue->numElems -= 1;
    }
    
    if(pthread_mutex_unlock(&pQueue->muAccess) != 0)
    {
        logerr("Q_fDelete(): mutex unlock ");
        goto error_return;
    }
    return TRUE;
    
    error_return:
    if(fLocked && pthread_mutex_unlock(&pQueue->muAccess) != 0)
        logerr("Q_fDelete(): mutex unlock ");
    return FALSE;
    
}// Q_fDelete()


BOOL fCopyVal(QNODE *pnode, void *pbuf, int bufsize)
{
    ASSERT(pnode && pbuf);
    
    int valsize = pnode->valsize;
    
    if(bufsize < valsize)
        return FALSE;
    
    memcpy(pbuf, pnode->pval, valsize);
    return TRUE;
    
}//
