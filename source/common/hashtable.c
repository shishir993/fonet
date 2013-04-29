

#include "hashtable.h"

/* Prime numbers from 
 * https://en.wikipedia.org/wiki/List_of_prime_numbers#Centered_heptagonal_primes
 */
unsigned int hashSizes[] = {43,     197,    547,    1471,
                            4663,   8233,   11173,  14561,  
                            20483};

static void vDeleteNode(int ktype, int vtype, HT_NODE *pnode);


unsigned int _hashu(unsigned int tablesize, unsigned int key)
{
    ASSERT(tablesize > 0);
    
    return key % tablesize;
}


unsigned int _hashs(unsigned int tablesize, const char *key, int keysize)
{
    ASSERT(tablesize > 0);
    
    unsigned long hash = 5381;
    int c;
    int i = 0;

    /* hash function from
     * http://www.cse.yorku.ca/~oz/hash.html
     */

    while ((c = *key) && i < keysize)
    {
      hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
      ++i;
      ++key;
    }

    return (unsigned int)(hash % tablesize);
}


BOOL HT_fCreate(HTABLE **pHTableOut, int nTableSize, int keyType, int valType)
{
    ASSERT(pHTableOut);
    ASSERT(nTableSize >= 0 && nelems_array(hashSizes));
    ASSERT(keyType == HT_KEY_STR || keyType == HT_KEY_UINT);
    ASSERT(valType >= HT_VAL_INT && valType <= HT_VAL_VOIDP);
    
    int newTableSize = hashSizes[nTableSize];
    HTABLE *pnewtable = NULL;

    
    if((pnewtable = (HTABLE*)malloc(sizeof(HTABLE))) == NULL)
    {
        logerr("HT_fCreate(): malloc() ");
        goto error_return;
    }
    
    pnewtable->uSize = newTableSize;
    pnewtable->htKeyType = keyType;
    pnewtable->htValType = valType;
    pthread_mutex_init(&pnewtable->muAccess, NULL);
    
    pnewtable->phtNodes = (HT_NODE**)calloc(1, newTableSize * sizeof(HT_NODE*));
    if(pnewtable->phtNodes == NULL)
    {
        logerr("HT_fCreate(): calloc() ");
        goto error_return;
    }

    *pHTableOut = pnewtable;
    return TRUE;
    
    error_return:
    if(pnewtable->phtNodes) free(pnewtable->phtNodes);
    if(pnewtable) free(pnewtable);
    *pHTableOut = NULL;
    return FALSE;
    
}// HT_fCreate()


BOOL HT_fDestroy(HTABLE *phtable)
{
    ASSERT(phtable);
    
    int i = 0;
    int limit;
    int ktype, vtype;
    HT_NODE **phtnodes = NULL;
    HT_NODE *pcurnode = NULL;
    HT_NODE *pnextnode = NULL;
    
    if(pthread_mutex_lock(&phtable->muAccess) != 0)
    {
        logerr("HT_fDestroy(): mutex lock ");
        return FALSE;
    }
    
    ktype = phtable->htKeyType;
    vtype = phtable->htValType;
    limit = phtable->uSize;
    phtnodes = phtable->phtNodes;
    
    if(!phtnodes)
    {
        free(phtable);
        return TRUE;
    }
    
    for( ; i < limit; ++i)
    {
        pcurnode = phtnodes[i];
        while(pcurnode)
        {
            pnextnode = pcurnode->pnext;
            vDeleteNode(ktype, vtype, pcurnode);
            pcurnode = pnextnode;
        }// while pcurnode
        
    }// for
    
    pthread_mutex_destroy(&phtable->muAccess);
    DBG_MEMSET(phtable, sizeof(HTABLE));
    free(phtable);
    return TRUE;
    
}// HT_Destroy()


static void vDeleteNode(int ktype, int vtype, HT_NODE *pnode)
{
    ASSERT(pnode);
    
    switch(ktype)
    {
        case HT_KEY_UINT: break;
        
        case HT_KEY_STR:
            if(pnode->key.skey) free(pnode->key.skey);
            break;
        
        default: logwarn("Incorrect keytype %d", ktype); break;
    }
    
    switch(vtype)
    {
        case HT_VAL_INT:
        case HT_VAL_UINT:
            break;
            
        case HT_VAL_VOIDP:
            // create memory for holding val
            if(pnode->val.vval) free(pnode->val.vval);
            break;
        
        default: logwarn("Incorrect valtype %d", vtype); break;
    }
    
    DBG_MEMSET(pnode, sizeof(HT_NODE));
    free(pnode);
    
    return;
}// vDeleteNode()



BOOL HT_fInsert(HTABLE *phtable, void *pvkey, int keySize, void *pval, int valSize)
{
    ASSERT(phtable && pvkey);
    ASSERT(pval && valSize > 0);
    
    unsigned int index;
    HT_NODE *pnewnode = NULL;
    
    BOOL fLocked = FALSE;
    
    char *pszkey = NULL;
    unsigned int ukey = 0;
    
    
    // create a new hashtable node
    if( (pnewnode = (HT_NODE*)malloc(sizeof(HT_NODE))) == NULL )
    { logerr("HT_fInsert(): malloc() "); goto error_return; }
    
    switch(phtable->htKeyType)
    {
        case HT_KEY_STR:
            if((pnewnode->key.skey = (char*)malloc(keySize)))
            { logerr("HT_fInsert(): malloc() "); goto delete_newnode; }
            memcpy(pnewnode->key.skey, pvkey, keySize);
            pszkey = (char*)pvkey;
            break;
        
        case HT_KEY_UINT:
            memcpy(&pnewnode->key.ukey, pvkey, sizeof(unsigned int));
            memcpy(&ukey, pvkey, sizeof(unsigned int));
            break;
        
        default: logwarn("Incorrect keytype %d", phtable->htKeyType); goto delete_newnode;
    }
    
    switch(phtable->htValType)
    {
        case HT_VAL_INT:
            if(valSize < sizeof(int))
            { logwarn("Valsize not enough"); goto delete_newnode; }
            memcpy(&pnewnode->val.ival, pval, sizeof(int));
            pnewnode->valsize = sizeof(int);
            break;
            
        case HT_VAL_UINT:
            if(valSize < sizeof(unsigned int))
            { logwarn("Valsize not enough"); goto delete_newnode; }
            memcpy(&pnewnode->val.uval, pval, sizeof(unsigned int));
            pnewnode->valsize = sizeof(unsigned int);
            break;
            
        case HT_VAL_VOIDP:
            // create memory for holding val
            if( (pnewnode->val.vval = malloc(valSize)) == NULL )
            { logerr("HT_fInsert(): malloc() "); goto delete_newnode; }
            memcpy(pnewnode->val.vval, pval, valSize);
            pnewnode->valsize = valSize;
            break;
        
        default: logwarn("Incorrect valtype %d", phtable->htValType); goto delete_newnode;
    }
    
    // insert into hashtable
    if(pthread_mutex_lock(&phtable->muAccess) != 0)
    { logerr("HT_fInsert(): mutex lock "); goto delete_newnode; }
    fLocked = TRUE;
    
    ASSERT(phtable->uSize > 0);
    if(phtable->htKeyType == HT_KEY_UINT)
        index = _hashu(phtable->uSize, ukey);
    else
        index = _hashs(phtable->uSize, pszkey, keySize);
    
    // connect to head
    pnewnode->pnext = phtable->phtNodes[index];
    phtable->phtNodes[index] = pnewnode;
    
    if(pthread_mutex_unlock(&phtable->muAccess) != 0)
    {
        logerr("HT_fInsert(): mutex unlock ");
        fLocked = FALSE;
        goto delete_newnode;
    }
    return TRUE;
    
    delete_newnode:
    if(pnewnode) free(pnewnode);
    if(phtable->htValType == HT_VAL_VOIDP && pnewnode->val.vval) free(pnewnode->val.vval);
    phtable->phtNodes[index] = NULL;
    
    error_return:
    if(fLocked && pthread_mutex_unlock(&phtable->muAccess) != 0)
        logerr("HT_fInsert_UV(): mutex unlock ");
    return FALSE;
    
}// HT_fInsert()



BOOL HT_fFind(HTABLE *phtable, void *pvkey, int keySize, void *pval, int *pvalsize)
{
    ASSERT(phtable);
    ASSERT(pvkey && keySize > 0);
    ASSERT(pval);
    
    int index = 0;
    HT_NODE *phtFoundNode = NULL;
    
    BOOL fLocked = FALSE;
    
    char *pszkey = NULL;
    unsigned int ukey = 0;
    
    
    switch(phtable->htKeyType)
    {
        case HT_KEY_STR:
            pszkey = (char*)pvkey;
            break;
        
        case HT_KEY_UINT:
            memcpy(&ukey, pvkey, sizeof(unsigned int));
            break;
        
        default: logwarn("Incorrect keytype %d", phtable->htKeyType); goto not_found;
    }
    
    if(pthread_mutex_lock(&phtable->muAccess) != 0)
    { logerr("HT_fFind(): mutex lock "); goto not_found; }
    fLocked = TRUE;
    
    ASSERT(phtable->uSize > 0);
    if(phtable->htKeyType == HT_KEY_UINT)
        index = _hashu(phtable->uSize, ukey);
    else
        index = _hashs(phtable->uSize, pszkey, keySize);
    
    phtFoundNode = phtable->phtNodes[index];
    if(!phtFoundNode) goto not_found;
    
    switch(phtable->htValType)
    {
        case HT_VAL_INT:
            if(pval) memcpy(pval, &phtFoundNode->val.ival, sizeof(int));
            if(pvalsize) *pvalsize = sizeof(int);
            break;
            
        case HT_VAL_UINT:
            if(pval) memcpy(pval, &phtFoundNode->val.uval, sizeof(unsigned int));
            if(pvalsize) *pvalsize = sizeof(unsigned int);
            break;
            
        case HT_VAL_VOIDP:
            if(pval) memcpy(pval, &phtFoundNode->val.vval, sizeof(void*));
            if(pvalsize) *pvalsize = phtFoundNode->valsize;
            break;
        
        default: logwarn("Incorrect valtype %d", phtable->htValType); goto not_found;
    }
    
    if(pthread_mutex_unlock(&phtable->muAccess) != 0)
    {
        logerr("HT_fFind(): mutex unlock ");
        fLocked = FALSE;
        goto not_found;
    }

    return TRUE;
    
    not_found:
    if(pvalsize) *pvalsize = 0;
    if(fLocked && pthread_mutex_unlock(&phtable->muAccess) != 0)
        logerr("HT_fInsert(): mutex unlock ");
    return FALSE;
    
}// HT_fFind()



BOOL HT_fRemove(HTABLE *phtable, void *pvkey, int keySize)
{
    ASSERT(phtable && pvkey);
    ASSERT(keySize > 0);
    
    int index = 0;
    HT_NODE *phtFoundNode = NULL;
    
    BOOL fLocked = FALSE;
    
    char *pszkey = NULL;
    unsigned int ukey = 0;
    
    
    switch(phtable->htKeyType)
    {
        case HT_KEY_STR:
            pszkey = (char*)pvkey;
            break;
        
        case HT_KEY_UINT:
            memcpy(&ukey, pvkey, sizeof(unsigned int));
            break;
        
        default: logwarn("Incorrect keytype %d", phtable->htKeyType); goto error_return;
    }
    
    if(pthread_mutex_lock(&phtable->muAccess) != 0)
    { logerr("HT_fRemove(): mutex lock "); goto error_return; }
    fLocked = TRUE;
    
    ASSERT(phtable->uSize > 0);
    if(phtable->htKeyType == HT_KEY_UINT)
        index = _hashu(phtable->uSize, ukey);
    else
        index = _hashs(phtable->uSize, pszkey, keySize);
    
    phtFoundNode = phtable->phtNodes[index];
    phtable->phtNodes[index] = NULL;
    
    if(!phtFoundNode) goto error_return;
    
    switch(phtable->htValType)
    {
        case HT_VAL_INT:
        case HT_VAL_UINT:
            break;
            
        case HT_VAL_VOIDP:
            if(phtFoundNode->val.vval) free(phtFoundNode->val.vval);
            break;
        
        default: logwarn("Incorrect valtype %d", phtable->htValType); goto error_return;
    }
    
    DBG_MEMSET(phtFoundNode, sizeof(HT_NODE));
    free(phtFoundNode);
    
    if(pthread_mutex_unlock(&phtable->muAccess) != 0)
    {
        logerr("HT_fRemove(): mutex unlock ");
        fLocked = FALSE;
        goto error_return;
    }
    
    return TRUE;
    
    error_return:
    if(fLocked && pthread_mutex_unlock(&phtable->muAccess) != 0)
        logerr("HT_fRemove(): mutex unlock ");  
    return FALSE;
    
}// HT_fRemove()


void HT_vDumpTable(HTABLE *phtable)
{
    ASSERT(phtable && phtable->uSize > 0);
    
    int i = 0;
    int nNodes = 0;
    unsigned int uTableSize = phtable->uSize;
    BOOL fLocked = FALSE;
    
    int keyType = phtable->htKeyType;
    int valType = phtable->htValType;
    
    HT_NODE **phtNodes = NULL;
    HT_NODE *phtCurNode = NULL;
    
    
    if(pthread_mutex_lock(&phtable->muAccess) != 0)
    { logerr("HT_vDumpTable(): mutex lock "); goto fend; }
    fLocked = TRUE;
    
    phtNodes = phtable->phtNodes;
    
    printf("hashtable dump::");
    printf("key  :  val  :  valsize\n");
    
    if(!phtNodes)
    {
        printf("Hastable empty");
        goto fend;
    }
    
    for(; i < uTableSize; ++i)
    {
        if((phtCurNode = phtNodes[i]) == NULL) continue;
        
        while(phtCurNode)
        {
            ++nNodes;
            
            // print the key
            switch(keyType)
            {
                case HT_KEY_STR: printf("%s:", phtCurNode->key.skey); break;
                case HT_KEY_UINT:printf("%u:", phtCurNode->key.ukey); break;
                default: printf("Invalid keytype %d:", keyType); break;
            }

            // print the value
            switch(valType)
            {
                case HT_VAL_INT: printf("%d:", phtCurNode->val.ival); break;
                case HT_VAL_UINT: printf("%u:", phtCurNode->val.uval); break;
                case HT_VAL_VOIDP: printf("0x%08x:", phtCurNode->val.vval); break;
                default: logwarn("Incorrect valtype %d", valType); break;
            }

            // print the valsize
            printf("%d\n", phtCurNode->valsize);

            phtCurNode = phtCurNode->pnext;
        
        }// while phtCurNode
        
    }// for i
    
    printf("Hashtable stats:\n");
    printf("    Total size : %u\n", uTableSize);
    printf("    Occupied   : %d\n", nNodes);
        
    fend:
    if(fLocked && pthread_mutex_unlock(&phtable->muAccess) != 0)
        logerr("HT_vDumpTable(): mutex unlock ");  
    return FALSE;
    
}// HT_vDumpTable
