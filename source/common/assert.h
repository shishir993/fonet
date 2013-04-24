
#ifndef _ASSERT_H
#define _ASSERT_H

#include <stdio.h>
#include <stdlib.h>

#ifdef _DEBUG
    #define ASSERT(x)                   \
        if(x)                               \
        { }                                 \
        else                                \
            vMyAssert(__FILE__, __LINE__)

    // vMyAssert(): Print error message and exit
    // In: pszFile, iLine
    // Out: none
    // Ret: none
    void vMyAssert(const char *pszFile, int iLine);
#else
    #define ASSERT(x)
#endif

#endif // _ASSERT_H
