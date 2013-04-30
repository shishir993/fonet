
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>

#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<netdb.h>

#include "../common/packet_exchange.h"


int listener;// listening socket descriptor
int newfd;// newly accept()ed socket descriptor
struct sockaddr_in remoteaddr; // client address	
socklen_t addrlen;
char buf[512];
int nbytes;// buffer for client data
char remoteIP[INET_ADDRSTRLEN];
int yes=1;
int i, j, rv;
char sendbuffer[1024], receivebuffer[1024];
struct sockaddr_in servaddr;


void socket_connection(int PORT)
{
    //in_port_t PORT = atoi(argv[1]);
    // for setsockopt() SO_REUSEADDR, below
    listener=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
	if(listener<0)
		printf("socket() failed");
	memset(&servaddr, 0, sizeof (servaddr));
	servaddr.sin_family=AF_INET;
	servaddr.sin_addr.s_addr=htonl(INADDR_ANY);
	servaddr.sin_port=htons(PORT);
	if(bind(listener,(struct sockaddr*) &servaddr,sizeof(servaddr)) < 0) 
	{
		printf("bind failed");
	}
        if (listen(listener, 10) == -1)
	{
		printf("listen() failed");
	}
        else 
        {
            printf("Waiting for connections...\n");
        }
        addrlen = sizeof (remoteaddr);
	newfd = accept(listener,(struct sockaddr *)&remoteaddr,&addrlen);
	if (newfd == -1) 
	{
	printf("Accept Failed");
	} 
        else
        {
            printf("Accepting connection..");
        }
}


void communication()
{
    while(1)
	{
        printf("Enter the message");
        scanf("%s",sendbuffer);
        PE_fSendPacket(newfd, sendbuffer, strlen(sendbuffer)+1, 0);

        PE_fRecvPacket(newfd, receivebuffer, sizeof(receivebuffer), 0);

        printf("MESSAGE RECEIVED:%s",receivebuffer);	
	}
                                                                //switch();
}

int main(int argc, char *argv[])
{
	if (argc != 3)
    {
        printf("First give port number and then the IP of the access node");
        return 0;
    }
        int PORT = atoi(argv[1]);
        char *AccessIP=argv[2];
        printf("%s\n",AccessIP);
                                                        //loadclientpassword();
        socket_connection(PORT);
        communication();
        
        
	//in_port_t PORT = atoi(argv[1]);
        //fd_set master;// master file descriptor list
	//fd_set read_fds;// temp file descriptor list for select()
	//int fdmax;// maximum file descriptor number
	//int listener;// listening socket descriptor
	int newfd;// newly accept()ed socket descriptor
	/*struct sockaddr_in remoteaddr; // client address	
	socklen_t addrlen;
	char buf[512];
	int nbytes;// buffer for client data
	char remoteIP[INET6_ADDRSTRLEN];
	int yes=1;
	int i, j, rv;
	struct sockaddr_in servaddr;// for setsockopt() SO_REUSEADDR, below*/
	//FD_ZERO(&master);// clear the master and temp sets
	//FD_ZERO(&read_fds);// get us a socket and bind it
	/*listener=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
	if(listener<0)
		printf("socket() failed");
	memset(&servaddr, 0, sizeof (servaddr));
	servaddr.sin_family=AF_INET;
	servaddr.sin_addr.s_addr=htonl(INADDR_ANY);
	servaddr.sin_port=htons(PORT);
	if(bind(listener,(struct sockaddr*) &servaddr,sizeof(servaddr)) < 0) 
	{
		printf("bind failed");
	}
	if (listen(listener, 10) == -1)
	{
		printf("listen() failed");
	}*/
	/*FD_SET(listener, &master);// add the listener to the master set
	fdmax = listener; //keep track of the biggest file descriptor so far, it's this one		
	// main loop
	for(;;) 
	{
		read_fds = master; // copy it
	if (select(fdmax+1, &read_fds, NULL, NULL, NULL) == -1)
		{
		printf("select() failed");
		}
	// run through the existing connections looking for data to read
	for(i = 0; i <= fdmax; i++)
	{
		if (FD_ISSET(i, &read_fds)) 
			{ // we got one!!
				if (i == listener)
					{
					// handle new connections
					addrlen = sizeof (remoteaddr);
					newfd = accept(listener,(struct sockaddr *)&remoteaddr,&addrlen);
					if (newfd == -1) 
						{
							perror("accept");
						} 
					else
						{
							FD_SET(newfd, &master); // add to master set
						if (newfd > fdmax) {
							// keep track of the max
							fdmax = newfd;
									}
						}
						} 
					else {
					// handle data from a client
                                    memset(buf, 0, sizeof(buf));
				if ((nbytes = recv(newfd, buf, sizeof(buf), 0)) <= 0) {
				// got error or connection closed by client
			if (nbytes == 0) {
			// connection closed
				printf("selectserver: socket %d hung up\n", i);
			} 
			else {
				perror("recv");
			}
			close(i); // bye!
			FD_CLR(i, &master); // remove from master set
			}
			 else
			 {
			puts(buf);
                        send(newfd,buf,sizeof(buf),0);
			// we got some data from a client
			//for(j = 0; j <= fdmax; j++) {
			// send to everyone!
			//	if (FD_ISSET(j, &master)) {
			// except the listener and ourselves
//			if (j != listener && j != i) {
//						if (send(j, buf, nbytes, 0) == -1) {
//							perror("send");
//						}
//					}
//				}
//			}
//		}
//	} // END handle data from client
//	} // END got new incoming connection
//} // END looping through file descriptors
//} // END for(;;)--and you thought it would never end!*/
}// main()

