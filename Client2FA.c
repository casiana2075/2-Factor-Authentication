/*
receive from serv2FA an approval request  and send back a message
"Accepted"/"Not accepted"
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
#include <ctype.h>
#include <arpa/inet.h>
#include <sqlite3.h>

#define PORT_SERV_CLI2FA 2100 // port user for serv2FA-cli2FA
#define MAX_NAME_LEN 100

char approvalRequest[2];

struct UserInfo
{ // received from server2FA
	char appName[MAX_NAME_LEN];
	char userName[MAX_NAME_LEN];
	int choice;
	char code[10];
	char phoneNumber[20];
};

// function that compare each row from db with my username and app name
static int callback(void *data, int argc, char **argv, char **azColName)
{
	struct UserInfo *userInfo = (struct UserInfo *)data;

	if (strcmp(userInfo->appName, argv[0]) == 0 && strcmp(userInfo->userName, argv[1]) == 0)
	{
		// found a match
		return 1; // ret a non-zero value to stop the query
	}

	return 0;
}

int main()
{

	// create server2FA-client2FA connection
	struct sockaddr_in client2FA; // structure used by client2FA to receive from server2FA
	struct sockaddr_in from1;
	struct UserInfo userInfo;
	int sdToserv2FA;

	sqlite3 *db;
	char *errMsg = 0;
	int rc;
	char *sql;

	// open database to get names of apps and usernames linked
	rc = sqlite3_open("database.db", &db);
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
	sql = "SELECT ClientAppName, username FROM ClientApp";

	// create socket
	if ((sdToserv2FA = socket(AF_INET, SOCK_STREAM, 0)) == -1)
	{
		perror("[client2FA]Error at socket() with server2FA.\n");
		return errno;
	}

	// prepare data structures
	bzero(&client2FA, sizeof(client2FA));
	bzero(&from1, sizeof(from1));

	// socket family setting
	client2FA.sin_family = AF_INET;
	// accept any adress
	client2FA.sin_addr.s_addr = htonl(INADDR_ANY);
	// we use a user port
	client2FA.sin_port = htons(PORT_SERV_CLI2FA);

	// attach the socket
	if (bind(sdToserv2FA, (struct sockaddr *)&client2FA, sizeof(struct sockaddr)) == -1)
	{
		perror("[client2FA]Error at bind() with server2FA.\n");
		return errno;
	}

	// listen
	if (listen(sdToserv2FA, 1) == -1)
	{
		perror("[client2FA]Error at listen() with server2FA.\n");
		return errno;
	}

	// concurent...
	while (1)
	{
		int serv2FA;
		unsigned int length = sizeof(from1);

		printf("[client2FA]Wait at port %d...\n", PORT_SERV_CLI2FA);
		fflush(stdout);

		// accept a client (blocking state until the connection is established)
		serv2FA = accept(sdToserv2FA, (struct sockaddr *)&from1, &length);

		if (serv2FA < 0)
		{
			perror("[client2FA]Error at accept() with server2FA.\n");
			continue;
		}

		int pid;
		if ((pid = fork()) == -1)
		{
			close(serv2FA);
			continue;
		}
		else if (pid > 0)
		{
			// parent proc
			close(serv2FA);
			while (waitpid(-1, NULL, WNOHANG))
				;
			continue;
		}
		else if (pid == 0)
		{
			// child proc
			close(sdToserv2FA);

			// wait for the message
			bzero(&userInfo, sizeof(userInfo));
			

			// read the message
			if (read(serv2FA, &userInfo, sizeof(userInfo)) <= 0)
			{
				perror("[server]Error at read() from server2FA.\n");
				close(serv2FA); // close connection with client
				continue;		// continue to listen
			}

			// printf("[client2FA]Message received from %s, with username %s and choice is %d\n", userInfo.appName, userInfo.userName, userInfo.choice);

			// prepare the msg to response
			bzero(approvalRequest, sizeof(approvalRequest));

			// execute sql command
			rc = sqlite3_exec(db, sql, callback, (void *)&userInfo, &errMsg);
			if (rc == SQLITE_ABORT)
			{
				strcpy(approvalRequest, "1");
				printf("Request approved for user '%s' in app '%s'!", userInfo.userName, userInfo.appName);
				fflush(stdout);
			}
			else if (rc != SQLITE_OK)
			{
				fprintf(stderr, "SQL error: %s\n", errMsg);
				sqlite3_free(errMsg);
			}
			else
			{
				strcpy(approvalRequest, "0");

				printf("Request denied for user %s in app '%s'!", userInfo.userName, userInfo.appName);
				fflush(stdout);
			}

			// close database
			sqlite3_close(db);

			if (write(serv2FA, approvalRequest, sizeof(approvalRequest)) <= 0)
			{
				perror("[server]Error at write() to server2FA.\n");
				continue; // continue to listen
			}
			else
				
				close(serv2FA);
			    exit(0);
		}
	} // while
	return 0;
}
