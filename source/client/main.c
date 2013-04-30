/* 
 * File:   main.c
 * Author: charanraj
 *
 * Created on April 26, 2013, 7:48 PM
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

#include "../common/packet.h"
#include "../common/cutils.h"
#include "../common/helpers.h"



int sock;
char usr[20];
char pwd[20];
char message[1024];
char reply[1024];
struct sockaddr_in accessaddr;
int rtnval;
int accessport;

//void *Communicate(void *);
//void *Receive(void *);


void socket_connection(int accessport, char* accessIP)
{
    //printf("%d%s\n",accessport,accessIP);
    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0)
        printf("error in socket");
    memset(&accessaddr, 0, sizeof (accessaddr));
    accessaddr.sin_family = AF_INET;
    rtnval = inet_pton(AF_INET, accessIP, &accessaddr.sin_addr);
    if (rtnval == 0)
        printf("Not a valid address");
    else if (rtnval < 0)
        printf("inet_pton() failed");
    accessaddr.sin_port = htons(accessport);
    if (connect(sock, (struct sockaddr*) &accessaddr, sizeof (accessaddr)) < 0) 
    {
        printf("Could not connect");
        
    }
}
/*void hanshake(char* serverIP)
{
    // include packet.h it has a structure 
    char hello[20]="hello";
    printf("%s",hello);
    
    //HANDSHAKE h;
    //h.u32Challenge
    
}*/
int main(int argc, char *argv[]) {
    if (argc != 4) {
        printf("Type in the Access Node IP, Access Node's Port and then IP Address of the Server");
    }
    char *accessIP = argv[1];
    int accessport=atoi(argv[2]);
    char *serverIP=argv[3];
    //pthread_t tid1,tid2;
    //printf("%s%d%s",accessIP,accessport,serverIP);
    printf("Enter Username and Password to login");
    printf("USERNAME:");
    scanf("%s",&usr);
    printf("PASSWORD:");
    scanf("%s",&pwd);
    socket_connection(accessport,accessIP);
    //handshake(serverIP);
    /*sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0)
        printf("error in socket");
    memset(&accessaddr, 0, sizeof (accessaddr));
    accessaddr.sin_family = AF_INET;
    rtnval = inet_pton(AF_INET, accessIP, &accessaddr.sin_addr);
    if (rtnval == 0)
        printf("Not a valid address");
    else if (rtnval < 0)
        printf("inet_pton() failed");
    accessaddr.sin_port = htons(accessport);
    if (connect(sock, (struct sockaddr*) &accessaddr, sizeof (accessaddr)) < 0) 
    {
        printf("Could not connect");
        return 1;
    }*/
   /* while (1) {
        char buf[512];
        int err;
        memset(buf, 0, sizeof (buf));
        printf("Enter the message");
        gets(buf);
        if (send(sock, buf, sizeof (buf), 0) < 0) {
            printf("Send Failed");
        }
        if (recv(sock, buf, sizeof (buf), 0) < 0);
        {
            printf("Received Failed %s", strerror(errno));
        }
        printf("MESSAGE RECEIVED:%s", buf);
    }*/
    
    //ret=pthread_create(&tid1,NULL,Communicate,(void *)0);
    //if(ret<0)
    //	printf("error in creating thread");
    //ret=pthread_create(&tid2,NULL,Receive,(void *)0);
    //if(ret<0)
    //	printf("error in creating thread");
    //pthread_join(tid1,NULL);
    close(sock);
    exit(0);
}


/*void *Communicate(void *thread_arg)
{
        int echostringlen;
        ssize_t numbytes;
        int MAXSTRINGLENGTH = 500;
        struct sockaddr_storage fromAddr;
        int numbytesrecv;
        char buffer[MAXSTRINGLENGTH + 1];
        printf("Please enter a value :");
while(1)
        {

        scanf("%s",echostring);
        echostringlen=strlen(echostring);
        printf("In to the thread %s %d\n", echostring,echostringlen);
        numbytes=sendto(sock,echostring,echostringlen,0,(struct sockaddr*) &proxyaddr,sizeof(proxyaddr));
        if(numbytes<0)
                printf("send() failed");
        else if(numbytes!=echostringlen)
                fputs("sent unexpected number of bytes",stdout);
        }
        pthread_exit(NULL);
}

/*void *Receive(void *thread_arg)
{
        int MAXSTRINGLENGTH = 500;
        struct sockaddr_storage fromAddr;
        int numbytesrecv;
        char buffer[MAXSTRINGLENGTH + 1];
        printf("in receive thread \n");
        socklen_t fromAddrLen=sizeof(fromAddr);
        while(1)
        {
        numbytesrecv = recvfrom(sock,buffer,MAXSTRINGLENGTH,0,(struct sockaddr *) &fromAddr, &fromAddrLen);
        if (numbytesrecv<0)
                printf("recvfrom() failed");
        printf("Received :%s \n", buffer);
        memset(buffer,0,sizeof(buffer));
        }
        pthread_exit(NULL);
}*/
