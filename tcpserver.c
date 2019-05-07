#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include "cryptotest.h"

struct client
{
    char username[20];
    int socket;
    unsigned char key[32];
    unsigned char iv[16];
    int admin;
};

int main(int argc, char **argv)
{
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    fd_set sockets;
    FD_SET(sockfd, &sockets);
    struct client clients[10];
    int totalClients = 0;
    unsigned char *privfilename = "RSApriv.pem";
    unsigned char ciphertext[1024];
    unsigned char decryptedtext[1024];
    int decryptedtext_len, ciphertext_len;
    EVP_PKEY *privkey;
    OpenSSL_add_all_algorithms();
    FILE *privf = fopen(privfilename, "rb");
    privkey = PEM_read_PrivateKey(privf, NULL, NULL, NULL);

    //setting all clients to empty
    for (int i = 0; i < 11; i++)
    {
        strcpy(clients[i].username, "empty");
        clients[i].socket = -1;
        clients[i].admin = 0;
    }

    //asking user for port number
    printf("Enter a port number: \n");
    char input[5000];
    fgets(input, 5000, stdin);
    int port = atoi(input);

    struct sockaddr_in serveraddr, clientaddr;
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_port = htons(port);
    serveraddr.sin_addr.s_addr = INADDR_ANY;

    bind(sockfd, (struct sockaddr *)&serveraddr,
         sizeof(serveraddr));
    listen(sockfd, 10);

    FD_ZERO(&sockets);
    FD_SET(sockfd, &sockets);

    while (1)
    {

        fd_set tmpset = sockets;
        int n = select(FD_SETSIZE, &tmpset, NULL, NULL, NULL);

        for (int ii = 0; ii < FD_SETSIZE; ii++)
        {
            if (FD_ISSET(ii, &tmpset))
            {
                if (ii == sockfd)
                { //new client
                    char first[500];
                    unsigned char key[32];
                    unsigned char vector[16];
                    unsigned char decrypted_key[32];
                    unsigned char encrypted_key[256];

                    int len = sizeof(clientaddr);

                    int clientsocket = accept(sockfd,
                                              (struct sockaddr *)&clientaddr, &len);

                    FD_SET(clientsocket, &sockets);

                    int n = recv(clientsocket, first, sizeof(first), 0);

                    //add client to list
                    clients[totalClients].socket = clientsocket;
                    strcpy(clients[totalClients].username, first);

                    printf("*** New user connected: %s\n", first);

                    int ky = recv(clientsocket, encrypted_key, 256, 0);

                    if (ky > 0)
                    {
                        printf("\nrecieved encrypted symmetric key: \n");
                        BIO_dump_fp(stdout, (const char *)encrypted_key, 256);
                    }

                    //decrypt symmetric key
                    int decryptedkey_len = rsa_decrypt(encrypted_key, 256, privkey, decrypted_key);

                    printf("\ndecrypted symmetric key: \n");
                    BIO_dump_fp(stdout, (const char *)decrypted_key, 32);

                    memcpy(clients[totalClients].key, &decrypted_key, 32);

                    //recieving vector
                    int v = recv(clientsocket, vector, 16, 0);

                    if (v > 0)
                    {
                        printf("\nrecieved initialization vector: \n");
                        BIO_dump_fp(stdout, (const char *)vector, 16);
                        memcpy(clients[totalClients].iv, &vector, 16);
                    }

                    printf("\ncopied vector: \n");
                    BIO_dump_fp(stdout, (const char *)clients[totalClients].iv, 16);

                    totalClients++;

                    printf("\n\n***** client is ready to go *****\n\n");
                }
                else
                {
                    char line[1000];
                    bzero(line, 1000);
                    char ciphertext[1024];
                    char decryptedtext[1024];
                    char msg[1000];
                    int decryptedtext_len, ciphertext_len;

                    int size;
                    int strSize;
                    int o = recv(ii, &size, 4, 0);
                    printf("the cyphersize will be: %d\n", size);
                    bzero(ciphertext, 1024);
                    o = recv(ii, &strSize, 4, 0);
                    printf("the actual size will be: %d\n", strSize);

                    //recieving message
                    int n = recv(ii, ciphertext, size, 0);

                    printf("\nmessage recieved in decrypted form:\n");
                    BIO_dump_fp(stdout, (const char *)ciphertext, size);

                    if (strcmp(ciphertext, "") != 0)
                    {

                        printf("\nmessage recieved now decrypting. . .\n");

                        for (int f = 0; f < totalClients; f++)
                        {
                            if (ii == clients[f].socket)
                            {

                                printf("\n\n------------------------\n");
                                printf("\n\nkey:\n");
                                BIO_dump_fp(stdout, (const char *)clients[f].key, 32);
                                printf("\n\niv:\n");
                                BIO_dump_fp(stdout, (const char *)clients[f].iv, 16);
                                printf("\n\n------------------------\n");

                                decryptedtext_len = decrypt(ciphertext, size,
                                                            clients[f].key, clients[f].iv, decryptedtext);

                                memcpy(msg, decryptedtext, strSize);
                                msg[strSize] = '\0';
                                break;
                            }
                        }

                        printf("message recieved from client:\n%s\n", msg);
                        printf("finished decrypting\n");

                        //client is leaving
                        if (strstr(msg, "#quit") != 0)
                        {

                            for (int j = 0; j < totalClients; j++)
                            {

                                if (clients[j].socket == ii)
                                {
                                    printf("\n*** now leaving: %s\n", clients[j].username);
                                    strcpy(clients[j].username, "empty");
                                    FD_CLR(ii, &sockets);
                                    printf("user was removed from user list\n");
                                    break;
                                }
                            }
                        }

                        //user requested list of others
                        else if (strstr(msg, "#list") != 0)
                        {
                            printf("sending list\n");
                            char list[5000];
                            bzero(list, 5000);
                            printf("Starting List %s\n", list);
                            for (int k = 0; k < totalClients; k++)
                            {
                                if (strcmp(clients[k].username, "empty") != 0)
                                {
                                    printf("username: %s\n", clients[k].username);
                                    strcat(list, clients[k].username);
                                    printf("Starting List %s\n", list);
                                }
                            }
                            printf("list: %s", list);
                            send(ii, list, strlen(list) + 1, 0);
                        }

                        //client wants to become admin
                        else if (strstr(msg, "password:") != 0)
                        {
                            printf("user requested to become an admin. . .\n");
                            for (int j = 0; j < totalClients; j++)
                            {

                                if (clients[j].socket == ii)
                                {
                                    if (clients[j].admin == 0)
                                    {
                                        printf("user is now an admin\n");
                                        clients[j].admin = 1;
                                    }
                                    else
                                    {
                                        printf("user is already an admin\n");
                                    }
                                    break;
                                }
                            }
                        }

                        //client wants to change usernames
                        else if (strstr(msg, "username:") != 0)
                        {

                            printf("user requested to change usernames. . .\n");
                            char nothing[20];
                            char username[500];

                            strcpy(nothing, strtok(msg, ": "));
                            strcpy(username, strtok(NULL, ": "));
                            strcat(username, "\n");
                            printf("The new username is: %s\n", username);

                            for (int j = 0; j < totalClients; j++)
                            {

                                if (clients[j].socket == ii)
                                {
                                    strcpy(clients[j].username, username);
                                    printf("username was successfully changed\n");
                                    break;
                                }
                            }
                        }

                        else
                        {
                            char sendTo[20];
                            char text[500];

                            strcpy(sendTo, strtok(msg, ": "));
                            printf("message is getting sent to: %s\n", sendTo);
                            strcat(sendTo, "\n");

                            strcpy(text, strtok(NULL, ": "));
                            printf("The message is: %s\n", text);

                            //meant to be a broadcast message
                            if (strstr(sendTo, "broadcast\n") != 0)
                            { 
                                printf("this is a broadcast message\n");

                                for (int f = 0; f < totalClients; f++)
                                {
                                    printf("now sending message to %s", clients[f].username);
                                    send(clients[f].socket, text, strlen(text) + 1, 0);
                                }

                                printf("finished\n");
                            }

                            //send to client
                            else
                            {
                                printf("this message is getting forwarded. . .\n");

                                for (int f = 0; f < totalClients; f++)
                                {
                                    if (strcmp(clients[f].username, sendTo) == 0)
                                    {
                                        printf("%s was found, now sending message. . .\n", clients[f].username);
                                        send(clients[f].socket, text, strlen(text) + 1, 0);
                                        break;
                                    }
                                }

                                printf("finished\n");
                            }
                        }
                        //clear the receiving string
                        memset(line, 0, 5000);
                    }
                }
            }
        }
    }
}