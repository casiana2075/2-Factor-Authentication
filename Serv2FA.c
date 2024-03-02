/* servTcpConc.c - Example of server TCP concurent
   Wait for a message of type 'notification, request.';
   send to client 2FA code generated generat if it was requested.
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
#include <sqlite3.h>
#include <pthread.h>
#include <arpa/inet.h>

#define PORT_CLIAPP_SERV 2070 // port used for serv-cli
#define PORT_SERV_SERV 2090	  // port used for serv2FA-servAd
#define PORT_SERV_CLI2FA 2100 // port user for serv2FA-cli2FA
#define CODE_LENGTH 6		  // length of 2FA code
#define MAX_NAME_LEN 100

extern int errno;

int clientAppNumber = 0, serverNumber = 0;

struct UserInfo
{ // received from serverAd
	char appName[MAX_NAME_LEN];
	char userName[MAX_NAME_LEN];
	int choice;
	char code[10];
	char phoneNumber[20];
};
char rspToServerAd[100]; // response sent to serverAd

char msgFromClientApp[300]; // message received from client
char rspToClientApp[100];	// response sent to client

char approvalRequest[2]; // this variable tell me if my request is approved

int fd[2]; // file descriptor used to comunicate between child & parent proc

// function that fetch a random four-byte value from /dev/random
void randomize()
{
	uint32_t seed = 0;
	FILE *devrnd = fopen("/dev/random", "r");
	fread(&seed, 4, 1, devrnd);
	fclose(devrnd);
	srand(seed);
}

// function that generate a 6 digit random code
int generate_code()
{
	randomize();
	int random_number = rand();
	while (!(99999 < random_number && random_number < 1000000))
	{
		randomize();
		random_number = rand();
	}
	return random_number;
}

// encryption
void encryptData(char *code)
{
	char symbolMap[10] = {'@', '#', '$', '%', '^', '&', '*', '(', ')', '!'};
	for (int i = 0; code[i] != '\0'; i++)
	{
		if (code[i] >= '0' && code[i] <= '9')
		{
			int digit = code[i] - '0';
			code[i] = symbolMap[digit];
		}
	}
}
//decryption
void decryptData(char *code)
{
	char symbolMapping[10] = {'@', '#', '$', '%', '^', '&', '*', '(', ')', '!'};
	for (int i = 0; code[i] != '\0'; i++)
	{
		for (int j = 0; j < 10; j++)
		{
			if (code[i] == symbolMapping[j])
			{
				code[i] = '0' + j;
				break;
			}
		}
	}
}


void *socketWithServAd()
{
	// create server2FA-serverAd connection
	struct sockaddr_in servAd; // structure used by server to receive from serverAd
	struct sockaddr_in from0;
	struct UserInfo userInfo;
	int sdToServAd;

	// create socket
	if ((sdToServAd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
	{
		perror("[server]Error socket() with serverAd.\n");
		exit(EXIT_FAILURE);
	}

	// prepare data structures
	bzero(&servAd, sizeof(servAd));
	bzero(&from0, sizeof(from0));

	// socket family setting
	servAd.sin_family = AF_INET;
	// accept any adress
	servAd.sin_addr.s_addr = htonl(INADDR_ANY);
	// we use a user port
	servAd.sin_port = htons(PORT_SERV_SERV);

	// attach the socket
	if (bind(sdToServAd, (struct sockaddr *)&servAd, sizeof(struct sockaddr)) == -1)
	{
		perror("[server]Error at bind() with serverAd.\n");
		exit(EXIT_FAILURE);
	}

	// listen
	if (listen(sdToServAd, 1) == -1)
	{
		perror("[server]Error at listen() with serverAd.\n");
		exit(EXIT_FAILURE);
	}

	// concurent
	while (1)
	{
		int servAd;
		unsigned int length = sizeof(from0);

		printf("\n[server]Wait for serverAd at port %d...\n", PORT_SERV_SERV);
		fflush(stdout);

		// accept a client (blocking state until the connection is established)
		servAd = accept(sdToServAd, (struct sockaddr *)&from0, &length);

		if (servAd < 0)
		{
			perror("[server]Error at accept() with serverAd.\n");
			continue;
		}

		serverNumber++;

		int pidS;
		if ((pidS = fork()) == -1)
		{
			close(servAd);
			continue;
		}
		else if (pidS > 0)
		{
			// parent proc
			close(servAd);
			while (waitpid(-1, NULL, WNOHANG))
				;
			continue;
		}
		else if (pidS == 0)
		{
			// child proc
			close(sdToServAd);

			// wait for the message
			bzero(&userInfo, sizeof(userInfo));
			printf("[server]Wait for the message...\n");
			fflush(stdout);

			// read the message and then request an authentication approval
			if (read(servAd, &userInfo, sizeof(userInfo)) > 0)
			{
				// sent a authentication approval request to Client2FA
				int sdToCli2FA;
				struct sockaddr_in serverCli2FA;

				// create socket
				if ((sdToCli2FA = socket(AF_INET, SOCK_STREAM, 0)) == -1)
				{
					perror("Eroare la socket().\n");
					exit(EXIT_FAILURE);
				}

				// fill the structure to create the connection with server
				// socket family
				serverCli2FA.sin_family = AF_INET;
				// IP adress of server
				serverCli2FA.sin_addr.s_addr = inet_addr("127.0.0.1");
				// connection port
				serverCli2FA.sin_port = htons(PORT_SERV_CLI2FA);

				if (connect(sdToCli2FA, (struct sockaddr *)&serverCli2FA, sizeof(serverCli2FA)) == -1)
				{
					perror("[serv2FA-cli2FA]Error at connect() with client2FA.\n");
					exit(EXIT_FAILURE);
				}

				// send structure userInfo to cli2FA to verify it
				if (write(sdToCli2FA, &userInfo, sizeof(userInfo)) <= 0)
				{
					perror("[serv2FA-cli2FA]Error at write() to client2FA.\n");
					exit(EXIT_FAILURE);
				}

				// read the response from the client2FA
				bzero(approvalRequest, sizeof(approvalRequest));

				if (read(sdToCli2FA, approvalRequest, sizeof(approvalRequest)) < 0)
				{
					perror("[serv2FA-cli2FA]Error at read() from client2FA.\n");
					exit(EXIT_FAILURE);
				}

				printf("[serv2FA-cli2FA]Received approval from client2FA: %s\n", approvalRequest);
				// in function of resppnse send the message back to servAd
				close(sdToCli2FA);
			}
			else
			{
				perror("[server]Error at read() from serverAd.\n");
				close(servAd); // close connection with servAd
				continue;	   // continue to listen
			}

			// prepare the msg to response to serverAd
			bzero(rspToServerAd, sizeof(rspToServerAd));

			if (strcmp(approvalRequest, "1") == 0)
			{
				// check code or phone number from database. Note: they're encrypted
				if (userInfo.choice == 1)
				{
					// we have to check the phone number
					char phoneNumberFromDB[11];

					sqlite3 *dbs;
					sqlite3_stmt *stmt;
					int rc;

					// open the database
					rc = sqlite3_open("database.db", &dbs);
					if (rc != SQLITE_OK)
					{
						fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(dbs));
						sqlite3_close(dbs);
						exit(0);
					}

					// SQL query
					const char *sql = "SELECT AuthenticationNotification FROM ClientApp WHERE userName = ? AND ClientAppName = ?";
					rc = sqlite3_prepare_v2(dbs, sql, -1, &stmt, NULL);
					if (rc != SQLITE_OK)
					{
						fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(dbs));
						sqlite3_close(dbs);
						exit(0);
					}

					sqlite3_bind_text(stmt, 1, userInfo.userName, -1, SQLITE_STATIC);
					sqlite3_bind_text(stmt, 2, userInfo.appName, -1, SQLITE_STATIC);

					// exec query and fetch result
					if (sqlite3_step(stmt) == SQLITE_ROW)
					{
						const char *result = (const char *)sqlite3_column_text(stmt, 0);
						if (result)
						{
							strncpy(phoneNumberFromDB, result, sizeof(phoneNumberFromDB));
							phoneNumberFromDB[sizeof(phoneNumberFromDB) - 1] = '\0'; // Ensure null termination
						}
					}
					else
					{
						fprintf(stderr, "No matching record found or error occurred\n");
					}

					sqlite3_finalize(stmt);
					sqlite3_close(dbs);

					decryptData(userInfo.phoneNumber);

					if (strcmp(phoneNumberFromDB, userInfo.phoneNumber) == 0)
					{

						strcpy(rspToServerAd, "Idenity verified successfully. Successfully authenticated.");
					}
					else
					{
						strcpy(rspToServerAd, "Incorrect phone number. Authentication failed.");
					}
				}
				else if (userInfo.choice == 2)
				{
					// we have to check the code
					char codeFromDB[10];

					sqlite3 *dbs;
					sqlite3_stmt *stmt;
					int rc;

					// open the database
					rc = sqlite3_open("database.db", &dbs);
					if (rc != SQLITE_OK)
					{
						fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(dbs));
						sqlite3_close(dbs);
						exit(0);
					}

					// SQL query
					const char *sql = "SELECT Code2FA FROM ClientApp WHERE userName = ? AND ClientAppName = ?";
					rc = sqlite3_prepare_v2(dbs, sql, -1, &stmt, NULL);
					if (rc != SQLITE_OK)
					{
						fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(dbs));
						sqlite3_close(dbs);
						exit(0);
					}

					sqlite3_bind_text(stmt, 1, userInfo.userName, -1, SQLITE_STATIC);
					sqlite3_bind_text(stmt, 2, userInfo.appName, -1, SQLITE_STATIC);

					// execute query and fetch result
					if (sqlite3_step(stmt) == SQLITE_ROW)
					{
						const char *result = (const char *)sqlite3_column_text(stmt, 0);
						if (result)
						{
							strncpy(codeFromDB, result, sizeof(codeFromDB));
							codeFromDB[sizeof(codeFromDB) - 1] = '\0'; // null termination
						}
					}
					else
					{
						fprintf(stderr, "No matching record found or error occurred\n");
					}

					sqlite3_finalize(stmt);
					sqlite3_close(dbs);

					if (strcmp(codeFromDB, userInfo.code) == 0)
					{

						strcpy(rspToServerAd, "Correct code. Successfully authenticated.");
					}
					else
					{
						strcpy(rspToServerAd, "Incorrect code. Authentication failed.");
					}
				}
			}
			else
			{
				strcpy(rspToServerAd, "Authentication request denied.");
			}

			printf("[server]Sending response back to serverAd: \"%s\"\n", rspToServerAd);

			if (write(servAd, rspToServerAd, sizeof(rspToServerAd)) <= 0)
			{
				perror("[server]Error at write() to serverAd.\n");
				continue; // continue to listen
			}
			else
				printf("[server]Message sent successfully to clientAd.\n");

			// we re done with this client, closed
			close(servAd);
			exit(0);
		}
	}
}

void *socketWithClientApp()
{
	// create client-server2FA connection
	struct sockaddr_in server2FA; // structure used by server to receive from cliApp
	struct sockaddr_in from;
	int sdToCliApp;

	// create socket
	if ((sdToCliApp = socket(AF_INET, SOCK_STREAM, 0)) == -1)
	{
		perror("[server2FA]Error at socket() with clientApp.\n");
		exit(EXIT_FAILURE);
	}

	// prepare data structures
	bzero(&server2FA, sizeof(server2FA));
	bzero(&from, sizeof(from));

	// socket family setting
	server2FA.sin_family = AF_INET;
	// accept any adress
	server2FA.sin_addr.s_addr = htonl(INADDR_ANY);
	// we use a user port
	server2FA.sin_port = htons(PORT_CLIAPP_SERV);

	// attach the socket
	if (bind(sdToCliApp, (struct sockaddr *)&server2FA, sizeof(struct sockaddr)) == -1)
	{
		perror("[server2FA]Error at bind() with clientApp.\n");
		exit(EXIT_FAILURE);
	}

	// listen
	if (listen(sdToCliApp, 1) == -1)
	{
		perror("[server2FA]Error at listen() with clientApp.\n");
		exit(EXIT_FAILURE);
	}

	// concurent...
	while (1)
	{
		int clientApp;
		unsigned int length = sizeof(from);

		printf("\n[server2FA]Wait for CliApp at port %d...\n", PORT_CLIAPP_SERV);
		fflush(stdout);

		// accept a client (blocking state until the connection is established)
		clientApp = accept(sdToCliApp, (struct sockaddr *)&from, &length);

		if (clientApp < 0)
		{
			perror("[server2FA]Error at accept() with clientApp.\n");
			close(clientApp); // to avoid the loop in server2FA
			exit(0);
		}

		clientAppNumber++;

		// create a pipe
		if (pipe(fd) == -1)
		{
			perror("pipe");
			exit(EXIT_FAILURE);
		}

		int pid;
		if ((pid = fork()) == -1)
		{
			close(clientApp);
			continue;
		}
		else if (pid == 0)
		{
			// child proc
			close(sdToCliApp);

			// wait for the message
			bzero(msgFromClientApp, sizeof(msgFromClientApp));
			printf("[server2FA]Wait for message from clientApp...\n");
			fflush(stdout);

			// read the message
			if (read(clientApp, msgFromClientApp, sizeof(msgFromClientApp)) <= 0)
			{
				perror("[server2FA]Error at read() from clientApp.\n");
				close(clientApp); // close connection with client
				continue;		  // continue to listen
			}

			printf("[server2FA]Message received from clientApp... %s.\n", msgFromClientApp);

			// prepare the msg to response
			bzero(rspToClientApp, sizeof(rspToClientApp));

			// generate the random code
			int rand_value = generate_code();
			char code_string[CODE_LENGTH + 1]; // +1 for null terminator

			// int to string using sprintf
			snprintf(code_string, sizeof(code_string), "%d", rand_value);

			if (strstr(msgFromClientApp, "yes") != NULL || strstr(msgFromClientApp, "Yes") != NULL)
			{
				strcpy(rspToClientApp, code_string);
			}
			else if (strstr(msgFromClientApp, "no") != NULL || strstr(msgFromClientApp, "No") != NULL)
			{
				strcpy(rspToClientApp, "You requested no code.");
			}
			else
			{
				strcpy(rspToClientApp, "Request format not recognized.");
			}

			printf("[server2FA]Send message back to clientApp...\"%s\"\n", rspToClientApp);

			if (isdigit(rspToClientApp[0]))
			{
				// store in db the code (encrypted)
				encryptData(rspToClientApp);
			}

			if (write(clientApp, rspToClientApp, sizeof(rspToClientApp)) <= 0)
			{
				perror("[server]Error at write() to clientApp.\n");
				continue; // continue to listen
			}
			else
				printf("[server]Message sent successfully to clientApp.\n\n");

			// we re done with this client, closed
			close(clientApp);
			exit(0);
		}

		// parent process
		close(clientApp);
		while (waitpid(-1, NULL, WNOHANG))
			;
		continue;
	}
}

int main()
{
	// creating two threads so that the sockets can work in parallel
	pthread_t t1, t2;
	if (pthread_create(&t1, NULL, &socketWithServAd, NULL) != 0)
	{
		perror("Error at creating thread1.\n");
	}
	if (pthread_create(&t2, NULL, &socketWithClientApp, NULL) != 0)
	{
		perror("Error at creating thread2.\n");
	}

	if (pthread_join(t1, NULL) != 0)
	{
		perror("Error while wainting for thread1.\n");
	}
	if (pthread_join(t2, NULL) != 0)
	{
		perror("Error while wainting for thread2.\n");
	}

	return 0;
}
