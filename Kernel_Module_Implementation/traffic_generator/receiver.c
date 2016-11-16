#include        "myunp.h"
unsigned long MAXLINE2 = 8192;


int my_read2(int fd,void *buffer,int length) 

{ 

int bytes_left; 

int bytes_read; 

char *ptr; 

bytes_left=length; 

while(bytes_left>0) 

{ 

     bytes_read=read(fd,ptr,bytes_left); 

     if(bytes_read<0) 

     { 

       if(errno==EINTR) 

          bytes_read=0; 

       else 

          return(-1); 

     } 

     else if(bytes_read==0) //????
         break; 

      bytes_left-=bytes_read; 

      ptr+=bytes_read; 

} 

return(length-bytes_left); 

}



void str_echo2(int sockfd)
{
	ssize_t n;
	char line[MAXLINE2];
	for(; ;){
		if((n = read(sockfd, line, MAXLINE2)) == 0)
			return;
//		printf("received %u\n", n);
		//Writen(sockfd, line, n);
	}


}

int
main(int argc, char **argv)
{
	int					listenfd, connfd;
	pid_t				childpid;
	socklen_t			clilen;
	struct sockaddr_in	cliaddr, servaddr;

	listenfd = Socket(AF_INET, SOCK_STREAM, 0);

	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family      = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port        = htons(SERV_PORT);

	Bind(listenfd, (SA *) &servaddr, sizeof(servaddr));

	Listen(listenfd, LISTENQ);

	for ( ; ; ) {
		clilen = sizeof(cliaddr);
		connfd = Accept(listenfd, (SA *) &cliaddr, &clilen);

		if ( (childpid = fork()) == 0) {	/* child process */
			close(listenfd);	/* close listening socket */
			str_echo2(connfd);	/* process the request */
			exit(0);
		}
		close(connfd);			/* parent closes connected socket */
	}
}
