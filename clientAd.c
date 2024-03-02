/*
This program send a struct with the app name, username, choice,
code entered/phone number entered by the user and send it to serverAd
compile: gcc -Wall clientAd.c -lsqlite3 -o clientAd
run: ./clientAd 0 2080
*/
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <string.h>
#include <arpa/inet.h>
#include <sqlite3.h>

#define MAX_NAME_LEN 100

extern int errno;

int port;

struct UserInfo
{ // sent to server
  char appName[MAX_NAME_LEN];
  char userName[MAX_NAME_LEN];
  int choice;
  char code[10];
  char phoneNumber[20];
};
char rsp[100]; // response from server

// loggin function
void login(char *appName, char *userName)
{
  printf("Logging into %s with username %s\n", appName, userName);
}

static int createListNames(void *data, int argc, char **argv, char **azColName)
{
  char *appsList = (char *)data;
  strcat(appsList, "'");
  strcat(appsList, argv[0]);
  strcat(appsList, "', ");
  return 0;
}

// encryption
void encryptData(char *code)
{
  char symbolMapping[10] = {'@', '#', '$', '%', '^', '&', '*', '(', ')', '!'};
  for (int i = 0; code[i] != '\0'; i++)
  {
    if (code[i] >= '0' && code[i] <= '9')
    {
      int digit = code[i] - '0';
      code[i] = symbolMapping[digit];
    }
  }
}

int main(int argc, char *argv[])
{
  int sd;
  struct sockaddr_in server; // structure used for connection
  struct UserInfo userInfo;

  sqlite3 *db;
  char *errMsg = 0;
  int rc;
  char *sql;
  char appsList[2048] = "";

  // checking arguments
  if (argc != 3)
  {
    printf("Syntax: %s <adress_server> <port>\n", argv[0]);
    return -1;
  }

  // set the port
  port = atoi(argv[2]);

  // Open database to get names of my apps
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

  // SQL statement to select distinct app names
  sql = "SELECT DISTINCT ClientAppName FROM ClientApp";

  // Execute SQL statement
  rc = sqlite3_exec(db, sql, createListNames, (void *)appsList, &errMsg);
  if (rc != SQLITE_OK)
  {
    fprintf(stderr, "SQL error: %s\n", errMsg);
    sqlite3_free(errMsg);
  }
  else
  {
    appsList[strlen(appsList) - 2] = '\0';
  }

  do
  {
    // get app name and username
    do
    {
      printf("Enter the application name you want to log in: ");
      fgets(userInfo.appName, sizeof(userInfo.appName), stdin);
      userInfo.appName[strcspn(userInfo.appName, "\n")] = 0; // rmove newline character
      if (strstr(appsList, userInfo.appName) != NULL)
      {
        break;
      }
      else
      {
        printf("Invalid app name. Choose between %s\n", appsList);
      }
    } while (true);

    // close database
    sqlite3_close(db);

    do
    {
      printf("Enter your username: ");
      fgets(userInfo.userName, sizeof(userInfo.userName), stdin);
      userInfo.userName[strcspn(userInfo.userName, "\n")] = 0; // rmove newline character
      if (strlen(userInfo.userName) >= 4)
      {
        break;
      }
      else
      {
        printf("Invalid username. Username should have at least 4 letters.\n");
      }
    } while (true);

    login(userInfo.appName, userInfo.userName);

    // type 1 or 2
    do
    {
      printf("Type 1 if you want a notification or 2 if you have a code: ");
      scanf("%d", &userInfo.choice);
      getchar(); // del newline character

      if (userInfo.choice == 1)
      {
        do
        {
          printf("Enter your phone number(ro) to verify your identity: ");
          fgets(userInfo.phoneNumber, sizeof(userInfo.phoneNumber), stdin);
          userInfo.phoneNumber[strcspn(userInfo.phoneNumber, "\n")] = 0; // remove newline

          if (strlen(userInfo.phoneNumber) == 10 && strncmp(userInfo.phoneNumber, "07", 2) == 0)
          {
            encryptData(userInfo.phoneNumber); // encrypt the phone number
            break;
          }
          else
          {
            printf("Invalid phone number. Please enter a valid phone number starting with '07'.\n");
          }
        } while (true);
      }

      else if (userInfo.choice == 2)
      {
        do
        {
          printf("Enter a six-digit code: ");
          if (fgets(userInfo.code, sizeof(userInfo.code), stdin) != NULL)
          {
            char *newline = strchr(userInfo.code, '\n');
            if (newline != NULL)
            {                  // i have newline
              *newline = '\0'; // replace with terminator
            }
            else
            {
              // imput too long, clear buffer
              scanf("%*[^\n]");
              scanf("%*c");
            }

            // check if the input length is valid
            if (strlen(userInfo.code) == 6)
            {
              encryptData(userInfo.code); // encrypt 2FAcode
              break;
            }
            else
            {
              printf("Invalid code. Please enter a valid code with 6 digits:\n");
            }
          }
          else
          {
            printf("Error reading input.\n");
            break;
          }
        } while (true);
      }

    } while (userInfo.choice != 1 && userInfo.choice != 2);

    // create socket
    if ((sd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
      perror("Eroare la socket().\n");
      return errno;
    }

    // fill the structure to create the connection with server
    // socket family
    server.sin_family = AF_INET;
    // IP adress of server
    server.sin_addr.s_addr = inet_addr(argv[1]);
    // connection port
    server.sin_port = htons(port);

    if (connect(sd, (struct sockaddr *)&server, sizeof(struct sockaddr)) == -1)
    {
      perror("[client]Error at connect().\n");
      return errno;
    }

    // send the msg to server
    if (write(sd, &userInfo, sizeof(userInfo)) <= 0)
    {
      perror("[client]Error at write() to server.\n");
      return errno;
    }

    // read the response from server
    //(call blocking until the server responds)
    bzero(rsp, sizeof(rsp));

    if (read(sd, rsp, sizeof(rsp)) < 0)
    {
      perror("[client]Error at read() from server.\n");
      return errno;
    }

    //response from serverAd
    printf("%s\n", rsp);

    // close the connection
    close(sd);

  } while (strcmp(rsp, "Username is not found! Please try again.") == 0);
}