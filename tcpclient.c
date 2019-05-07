#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <string.h>
#include <termios.h>
#include "cryptotest.h"

int main(int argc, char **argv)
{
  int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  fd_set sockets;
  FD_ZERO(&sockets);

  unsigned char *pubfilename = "RSApub.pem";
  unsigned char key[32];
  unsigned char iv[16];

  unsigned char ciphertext[1024];
  unsigned char decryptedtext[1024];
  int decryptedtext_len, ciphertext_len;
  OpenSSL_add_all_algorithms();
  RAND_bytes(key, 32);
  RAND_bytes(iv, 16);
  EVP_PKEY *pubkey, *privkey;

  FILE *pubf = fopen(pubfilename, "rb");
  pubkey = PEM_read_PUBKEY(pubf, NULL, NULL, NULL);
  unsigned char encrypted_key[256];

  if (sockfd < 0)
  {
    printf("There was an error creating the socket\n");
    return 1;
  }

  //asking user for port number
  printf("Enter a port number: \n");
  char input[5000];
  fgets(input, 5000, stdin);
  int port = atoi(input);

  //asking user an IP address
  printf("Enter an IP address: \n");
  char ip[5000];
  fgets(ip, 1000, stdin);

  struct sockaddr_in serveraddr, clientaddr;
  serveraddr.sin_family = AF_INET;
  serveraddr.sin_port = htons(port);
  serveraddr.sin_addr.s_addr = inet_addr(ip);

  int c = connect(sockfd, (struct sockaddr *)&serveraddr, sizeof(serveraddr));
  if (c < 0)
  {
    printf("There was an error connecting\n");
    return 1;
  }

  FD_SET(sockfd, &sockets);
  FD_SET(STDIN_FILENO, &sockets);

  //asking user for a username
  printf("what would you like your username to be?: \n");
  char username[5000];
  fgets(username, 5000, stdin);

  send(sockfd, username, strlen(username) + 1, 0);

  printf("symmetric key created: \n");
  BIO_dump_fp(stdout, (const char *)key, 32);

  //encryption for the establishing symmetric key pair
  int encryptedkey_len = rsa_encrypt(key, 32, pubkey, encrypted_key);
  
  printf("symmetric key encrypted: \n");
  BIO_dump_fp(stdout, (const char *)encrypted_key, encryptedkey_len);

  printf("initialization vector created: \n");
  BIO_dump_fp(stdout, (const char *)iv, 16);

  printf("sending symmetric key. . .\n");
  send(sockfd, encrypted_key, 256, 0);

  printf("sending initialization vector. . .\n");
  send(sockfd, iv, 16, 0);

  //printing menu for user
  printf("\n\n(~˘▾˘)~  Welcome to the tcp chat room  ~(˘▾˘~)\n");
  printf("To quit type '#quit' \n");
  printf("To request admin privledges type '#admin' \n");
  printf("To rename yourself type '#rename' \n");
  printf("To broadcast type 'broadcast: message' \n");
  printf("To send to a specific chatter type 'username: message' \n");
  printf("To request a list of chatters in the chatroom type '#list' \n");
  printf("-------------------------------------------------------------\n\n");

  while (1)
  {
    int len = sizeof(clientaddr);
    fd_set tmp_set = sockets;
    select(FD_SETSIZE, &tmp_set, NULL, NULL, NULL); // changes data in tmp_set, the sockets we can read from will be left in tmp_set
    int i;
    for (i = 0; i < FD_SETSIZE; i++)
    {
      if (FD_ISSET(i, &tmp_set))
      {
        if (i == sockfd)
        {
          char receiveStr[5000];
          recv(i,receiveStr,5000,0);
          printf("Recieved: \n%s",receiveStr);
        }
        else
        {
          char sendStr[5000];
          bzero(sendStr, 5000);
          fgets(sendStr,5000,stdin);
          bzero(ciphertext, 1024);

          int size = strlen(sendStr);

          //user wants to quit
          if (strstr(sendStr, "#quit") != 0)
          { 
            ciphertext_len = encrypt(sendStr, strlen(sendStr), key, iv, ciphertext);
            printf("Ciphertext is:\n");
            BIO_dump_fp(stdout, (const char *)ciphertext, ciphertext_len);

            //sending cyphertext size
            send(sockfd, &ciphertext_len,4,0);
            
            //sending string size
            send(sockfd, &size,4,0); 

            send(sockfd, ciphertext, ciphertext_len, 0);
            printf("Sutting down. . .\n");
            close(i);
            close(sockfd);
            FD_CLR(i, &sockets);
            exit(0);
          }
          
          //user wants list
          else if (strstr(sendStr, "#list") != 0)
          { 
            ciphertext_len = encrypt(sendStr, strlen(sendStr), key, iv, ciphertext);
            printf("Ciphertext is:\n");
            BIO_dump_fp(stdout, (const char *)ciphertext, ciphertext_len);

            //sending cyphertext size
            send(sockfd, &ciphertext_len,4,0);
            
            //sending string size
            send(sockfd, &size,4,0); 

            printf("sending cypher text. . .\n");
            send(sockfd, ciphertext, ciphertext_len, 0);
            printf("Sutting down. . .\n");
            printf("recieving list. . .\n");
          }
          
          //user wants to become admin
          else if (strstr(sendStr, "#admin") != 0)
          { 
            struct termios term, term_orig;
            tcgetattr(STDIN_FILENO, &term);
            term_orig = term;
            term.c_lflag &= ~ECHO;
            tcsetattr(STDIN_FILENO, TCSANOW, &term);
            char password[20];

            //asking for password
            bzero(sendStr, 5000);
            printf("enter password: ");
            fgets(sendStr,5000,stdin);

            strcpy(password, "password: ");
            strcat(password, sendStr);
            size = strlen(password);

            printf("string: %s", password);
            
            tcsetattr(STDIN_FILENO, TCSANOW, &term_orig);          
            
            ciphertext_len = encrypt(password, strlen(password), key, iv, ciphertext);
            printf("Ciphertext is:\n");
            BIO_dump_fp(stdout, (const char *)ciphertext, ciphertext_len);

            //sending cyphertext size
            send(sockfd, &ciphertext_len,4,0);
            
            //sending string size
            send(sockfd, &size,4,0); 
            printf("requesting access. . .\n");
            send(sockfd, ciphertext, ciphertext_len, 0);
          }

          //user wants to change usernames
          else if (strstr(sendStr, "#rename") != 0)
          { 
            char username[20];

            bzero(sendStr, 5000);
            printf("enter new username: ");
            fgets(sendStr,5000,stdin);

            strcpy(username, "username: ");
            strcat(username, sendStr);
            size = strlen(username);

            printf("string: %s", username);

            ciphertext_len = encrypt(username, strlen(username), key, iv, ciphertext);
            printf("Ciphertext is:\n");
            BIO_dump_fp(stdout, (const char *)ciphertext, ciphertext_len);

            //sending cyphertext size
            send(sockfd, &ciphertext_len,4,0);
            
            //sending string size
            send(sockfd, &size,4,0); 

            printf("requesting username change. . .\n");
            send(sockfd, ciphertext, ciphertext_len, 0);
          }


          //user is just sending a message
          else{
            ciphertext_len = encrypt(sendStr, strlen(sendStr), key, iv, ciphertext);
            printf("Ciphertext is:\n");
            BIO_dump_fp(stdout, (const char *)ciphertext, ciphertext_len);

            //sending cyphertext size
            send(sockfd, &ciphertext_len,4,0);
            
            //sending string size
            send(sockfd, &size,4,0); 

            printf("sending cypher text. . .\n");
            send(sockfd, ciphertext, ciphertext_len, 0);
          }
        }
      }
    }
  }
  close(sockfd);
  return 0;
}