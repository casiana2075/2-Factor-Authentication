/*
Receive from clientAd a struct with the app name, username, choice,
code entered/phone number entered by the user and first check if the username
is the database(if yes then send to the client that he is logged in and to the
other server send a struct)(else send back to client the message "Log in failed.")
compile: gcc -Wall serverAd.c -lsqlite3 -o serverAd
run: ./serverAd

*/

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <arpa/inet.h>
#include <sqlite3.h>

#define PORT 2080
//length of 2FA code 
#define MAX_NAME_LEN 100

extern int errno;

int clientNumber = 0;

struct UserInfo
{ // received from client
	char appName[MAX_NAME_LEN];
	char userName[MAX_NAME_LEN];
	int choice;
	char code[10];
	char phoneNumber[20];
};
char rspToClientAd[100]; // response sent to client

// function that compare each row from db with my username
static int callback(void *data, int argc, char **argv, char **azColName)
{
	struct UserInfo *userInfo = (struct UserInfo *)data;

	if ( strcmp(userInfo->userName, argv[0]) == 0)
	{
		// found a match
		return 1; // ret a non-zero value to stop the query
	}

	return 0;
}

int main()
{

	//create connection with clients 
	struct sockaddr_in serverAd; // structure used by server to receive from clients
	struct sockaddr_in from;
	struct UserInfo userInfo;
	int sd, logged = 0;

	sqlite3 *db;
	char *errMsg = 0;
	int rc;
	char *sql;

	// open database to get usernames
	rc = sqlite3_open("databaseUsers.db", &db);
	if (rc)
	{
		fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
		return 0;
	}
	else
	{
		fprintf(stderr, "Opened database successfully\n");
	}

	// select app names, usernames
	sql = "SELECT username FROM Users";

	//create socket 
	if ((sd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
	{
		perror("[server]Error at first socket().\n");
		return errno;
	}

	//prepare data structures
	bzero(&serverAd, sizeof(serverAd));
	bzero(&from, sizeof(from));

	// socket family setting
	serverAd.sin_family = AF_INET;
	// accept any adress
	serverAd.sin_addr.s_addr = htonl(INADDR_ANY);
	// we use a user port 
	serverAd.sin_port = htons(PORT);

	// attach the socket 
	if (bind(sd, (struct sockaddr *)&serverAd, sizeof(struct sockaddr)) == -1)
	{
		perror("[server]Error at bind() with client.\n");
		return errno;
	}

	// listen 
	if (listen(sd, 1) == -1)
	{
		perror("[server]Error at listen() with client.\n");
		return errno;
	}

	// concurent... 
	while (1)
	{
		int client;
		unsigned int length = sizeof(from);

		printf("\n[server]Wait at port %d...\n", PORT);
		fflush(stdout);

		// accept a client (blocking state until the connection is established) 
		client = accept(sd, (struct sockaddr *)&from, &length);

		if (client < 0)
		{
			perror("[server]Error at accept() with client.\n");
			continue;
		}

		clientNumber++;
		int pidC;
		if ((pidC = fork()) == -1)
		{
			close(client);
			continue;
		}
		else if (pidC > 0)
		{
			// parent proc
			close(client);
			while (waitpid(-1, NULL, WNOHANG))
				;
			continue;
		}
		else if (pidC == 0)
		{
			// child proc
			close(sd);

			// wait for the message 
			bzero(&userInfo, sizeof(userInfo));
			printf("[server]Wait the message from client...\n");
			fflush(stdout);

			// read the message
			if (read(client, &userInfo, sizeof(userInfo)) <= 0)
			{
				perror("[server]Error at read() from client.\n");
				close(client); // close connection with client 
				continue;	   // continue to listen 
			}

			printf("[server]Message received from %s, with username %s and choice is %d\n", userInfo.appName, userInfo.userName, userInfo.choice);
	
			// prepare the msg to response
			bzero(rspToClientAd, sizeof(rspToClientAd));

			// execute sql command
			rc = sqlite3_exec(db, sql, callback, (void *)&userInfo, &errMsg);
			if (rc == SQLITE_ABORT)
			{
				logged = 1;
				// printf("[server]You are logged in, %s!\n", userInfo.userName);
			}
			else if (rc != SQLITE_OK)
			{
				fprintf(stderr, "SQL error: %s\n", errMsg);
				sqlite3_free(errMsg);
			}
			else
			{
				strcpy(rspToClientAd, "Username is not found! Please try again.");
				// printf("[server]Username '%s' is not found for %s!\n", userInfo.userName, userInfo.appName);
			}

			// close database
			sqlite3_close(db);

			
			if (logged) // send to serv2FA the struct
			{
				int sdToS, port2FA = 2090; // socket descr to server, port from 2FA server
				struct sockaddr_in server2FA; // structure used for connection
				char rspFrom2FA[100];      //response from server2FA

				// create socket
				if ((sdToS = socket(AF_INET, SOCK_STREAM, 0)) == -1)
				{
					perror("[server2]Error at socket() to server.\n");
					return errno;
				}
				
				// fill the structure to create the connection with server2FA
				// socket family 
				server2FA.sin_family = AF_INET; 
				// IP adress of server
				server2FA.sin_addr.s_addr = inet_addr("127.0.0.1");
				// connection port 
				server2FA.sin_port = htons(port2FA);

				

				if (connect(sdToS, (struct sockaddr *)&server2FA, sizeof(struct sockaddr)) == -1)
				{
					perror("[server2]Error at connect() with server.\n");
					return errno;
				}
				

				// send the msg to server 
				if (write(sdToS, &userInfo, sizeof(userInfo)) <= 0)
				{
					perror("[server2]Error at write() to server.\n");
					return errno;
				}

				// read the response from server
	 			//(call blocking until the server responds) 
				bzero(rspFrom2FA, sizeof(rspFrom2FA));

				if (read(sdToS, rspFrom2FA, sizeof(rspFrom2FA)) < 0)
				{
					perror("[server2]Error at read() from server.\n");
					return errno;
				}

				printf("[server2]Message received from serv2FA: %s\n", rspFrom2FA);
				strcpy(rspToClientAd, rspFrom2FA);

				//close the connection between servers
				close(sdToS);
			}

			

			printf("[server]Sending response back to clientAd: \"%s\"\n", rspToClientAd);

			if (write(client, rspToClientAd, sizeof(rspToClientAd)) <= 0)
			{
				perror("[server]Error at write() to client.\n");
				continue; // continue to listen
			}
			else
				printf("[server]Message sent successfully to client.\n");

			// we re done with this client, closed
			close(client);
			exit(0);
		}

	} // while 
} // main 