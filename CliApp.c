#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sqlite3.h>
#include <ctype.h>

extern int errno;

int port;
char msg[300];       // message sent to server
char rsp[100];       // response from server
char userInput[100]; // what i type from stdin

// decryption
void decryptCode(char *code) {
    char symbolMapping[10] = {'@', '#', '$', '%', '^', '&', '*', '(', ')', '!'};
    for (int i = 0; code[i] != '\0'; i++) {
        for (int j = 0; j < 10; j++) {
            if (code[i] == symbolMapping[j]) {
                code[i] = '0' + j;
                break;
            }
        }
    }
}


int main(int argc, char *argv[])
{
  if (argc != 3)
  {
    printf("Syntax: %s <server_address> <port>\n", argv[0]);
    return -1;
  }

  port = atoi(argv[2]);

  sqlite3 *db;
  int rc = sqlite3_open("database.db", &db);

  if (rc != SQLITE_OK)
  {
    fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
    sqlite3_close(db);
    return 1;
  }

  sqlite3_stmt *stm;
  const char *sql = "SELECT ClientAppName, AuthenticationNotification, ID FROM ClientApp";
  rc = sqlite3_prepare_v2(db, sql, -1, &stm, NULL);

  if (rc != SQLITE_OK)
  {
    fprintf(stderr, "Failed to execute statement: %s\n", sqlite3_errmsg(db));
    sqlite3_close(db);
    return 1;
  }

  while (sqlite3_step(stm) == SQLITE_ROW)
  {
    int sd = socket(AF_INET, SOCK_STREAM, 0);
    if (sd == -1)
    {
      perror("Error at socket().\n");
      continue;
    }

    struct sockaddr_in server;
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = inet_addr(argv[1]);
    server.sin_port = htons(port);

    if (connect(sd, (struct sockaddr *)&server, sizeof(server)) == -1)
    {
      perror("[client]Error at connect().\n");
      close(sd);
      continue;
    }

    // Format the message
    const char *clientAppName = (const char *)sqlite3_column_text(stm, 0);
    const char *authNotification = (const char *)sqlite3_column_text(stm, 1);
    const char *ID = (const char *)sqlite3_column_text(stm, 2);

    snprintf(msg, sizeof(msg), "%s, %s", clientAppName, authNotification);

    printf("[client %s]Type yes/no to request or not a 2FA code: ", ID);
    fflush(stdout);
    fgets(userInput, sizeof(userInput), stdin);
    userInput[strcspn(userInput, "\n")] = 0;
    strncat(msg, ", ", sizeof(msg) - strlen(msg) - 1);
    strncat(msg, userInput, sizeof(msg) - strlen(msg) - 1);

    // Send the message to the server
    if (write(sd, msg, sizeof(msg)) <= 0)
    {
      perror("[client]Error at write() to server.\n");
      close(sd);
      continue;
    }

    // Read the response from the server
    bzero(rsp, sizeof(rsp));
    if (read(sd, rsp, sizeof(rsp)) < 0)
    {
      perror("[client]Error at read() from server.\n");
      close(sd);
      continue;
    }

    //store the code in db encrypted
    sqlite3_stmt *update_stm;
    char update_sql[512];

    snprintf(update_sql, sizeof(update_sql), "UPDATE ClientApp SET Code2FA = ? WHERE ID = ?");
    rc = sqlite3_prepare_v2(db, update_sql, -1, &update_stm, NULL);

    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "Failed to prepare update statement: %s\n", sqlite3_errmsg(db));
    }
    else
    {
        sqlite3_bind_text(update_stm, 1, rsp, -1, SQLITE_STATIC);
        sqlite3_bind_text(update_stm, 2, ID, -1, SQLITE_STATIC);

        if (sqlite3_step(update_stm) != SQLITE_DONE)
        {
            fprintf(stderr, "Failed to execute update statement: %s\n", sqlite3_errmsg(db));
        }

        sqlite3_finalize(update_stm);
    }


    decryptCode(rsp);
    printf("[client]Received message: %s\n", rsp);
    close(sd);
  }

  sqlite3_finalize(stm);
  sqlite3_close(db);
  return 0;
}
