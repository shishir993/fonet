/* 
 * File:   scomm.h
 * Author: shishir
 *
 * Created on April 24, 2013, 11:34 PM
 */

#ifndef _SCOMM_H
#define	_SCOMM_H

#include "aninclude.h"


BOOL fConnectToServer();
void vServCloseSocket();
BOOL fSendToServer(void *pvPacket, int nPacketSize);
BOOL fRecvFromServer(void *pvBuffer, int nBufSize);

#endif	/* SCOMM_H */

