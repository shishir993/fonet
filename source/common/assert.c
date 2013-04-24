
/* File: assert.c
 * Definition of the function vMyAssert()
 * Shishir K Prasad
 */

#include "assert.h"

void vMyAssert(const char *pszFile, int iLine)
{
    fprintf(stderr, "SKP assertion in file %s at line %d\n", pszFile, iLine);
    exit(1);

}// vMyAssert()
