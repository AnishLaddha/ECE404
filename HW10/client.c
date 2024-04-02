/*
/ file : client.c
/----------------------------------
/ This is a client socket program.
*/

#include <stdio.h> 
#include <stdlib.h> 
#include <errno.h> 
#include <string.h> 
#include <netdb.h> 
#include <sys/types.h> 
#include <netinet/in.h> 
#include <sys/socket.h> 
//#include <arpa/inet.h>
//#include <unistd.h>

#define PORT 9000
#define MAX_DATA_SIZE 4096

int isHexChar(char c);
 
int main(int argc, char *argv[])
{
	int sockfd;
	int recvSize;  
	unsigned char buff[MAX_DATA_SIZE];
	unsigned char sendDataBefore[MAX_DATA_SIZE];
	unsigned char sendDataAfter[MAX_DATA_SIZE];
	struct sockaddr_in servAddr; 

	if (argc != 2) {
		fprintf(stderr,"Usage: %s <host IP address>\n", argv[0]);
		exit(1);
	}

	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		perror("socket");
		exit(1);
	}

	servAddr.sin_family = AF_INET;      
	servAddr.sin_port = htons(PORT);    
	servAddr.sin_addr.s_addr = inet_addr(argv[1]);
	bzero(&(servAddr.sin_zero), 8);     

	if (connect(sockfd, (struct sockaddr *)&servAddr, sizeof(servAddr)) == -1) {
		perror("connect failed");
		exit(1);
	}

	if ((recvSize = recv(sockfd, buff, 30, 0)) == -1) {
		perror("recv failed");
		exit(1);
	}

	buff[recvSize] = '\0';

	char one[3];
	char two[2];

	/* repeat until "exit" input */
	while(1){		printf("Say something: ");
		fgets(sendDataBefore, MAX_DATA_SIZE, stdin);
		int i;
		int j = 0;
		for(i = 0; i < MAX_DATA_SIZE ; i++){
		/*Allows hexstrings of the format \xXX (where XX is the hexadecimal number) to be sent */
			if((sendDataBefore[i] == '\\') && (sendDataBefore[i+1] == 'x') && (sendDataBefore[i+2] != '\n') && (isHexChar(sendDataBefore[i+2])) && (isHexChar(sendDataBefore[i+3]))){
				one[0] = sendDataBefore[i+2];
				one[1] = '\0';
				two[0] = sendDataBefore[i+3];
				two[1] = '\0';
				sendDataAfter[j] = (unsigned char) strtol(strcat(one,two),NULL,16);
				i+=3;
			}
			else{
				sendDataAfter[j] = sendDataBefore[i];
			}
			j++;
		}
		/* if input is "exit", terminate this program */
		if(!strncmp(sendDataAfter, "exit", 4)) break;

		if (send(sockfd, sendDataAfter, strlen(sendDataAfter), 0) == -1) {
			perror("send failed");
			close(sockfd);
			exit(1);
		}

		if ((recvSize = recv(sockfd, buff, MAX_DATA_SIZE, 0)) == -1) {
			perror("recv failed");
			exit(1);
		}
		buff[recvSize] = '\0';
		printf("You Said: %s\n", buff);
	}
	close(sockfd);

	return 0;
}

int isHexChar(char c){
	if(c <= '9' && c >= '0'){
		return 1;
	}
	else if(c <= 'F' && c >= 'A'){
		return 1;
	}
	else if(c <= 'f' && c >= 'a'){
		return 1;
	}
	else{
		return 0;
	}
}	
