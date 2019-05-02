// Command and Control Simple Mail Transport Protocol Server [CCSMTP]
// Kenneth Finnegan, GPLv2 - 2012
// Nicolas Mora - 2019
// kennethfinnegan.blogspot.com
//
// This is a VERY simple smtp daemon which implements the bare minimum
// required of it to receive email messages directed at it from other
// mail servers.
//
// It currently does no processing to the received email short of simply
// printing it to the terminal one line at a time.
// Attachments seem to blow its mind...
//
// WARNING: THIS IS NOTHING MORE THAN A TOY DAEMON!
//
// For sake of simplicity, many standard counter-measures were not 
// implemented to protect this server from a variety of attacks.
// This means that for an attacker to disable this server or your 
// entire computer is a trivial affair.
//
// If you're reading this looking for a useful SMTP server to deploy
// on your network, you are looking at the wrong thing! 
// You should probably be looking at Sendmail or Postfix.
//
// This code should be seen as nothing more than an educational toy.
// Implementing all of the required checks for a robust network service
// are left as an educational excersize for the reader. No attempt has
// been made to sandbox the server or prevent it from using excessive
// system resources in the name of responding to client requests.
//

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <pthread.h>
#include <orcania.h>
#include <yder.h>

// Port 25 redirected to 2525 through firewall
// or change this define to instead be "25"
#define PORT    "2525"
// Specify the domain being served by this server
// Ideally this is a config argument and not a const
#define DOMAIN    "glewlwyd.tld"

#define BACKLOG_MAX  (10)
#define BUF_SIZE  4096
#define STREQU(a,b)  (strcmp(a, b) == 0)
char * message_prefix;

// Linked list of ints container
struct int_ll {
  int d;
  struct int_ll *next;
};

// Overall server state
struct {
  struct int_ll *sockfds;
  int sockfd_max;
  char *domain;
  pthread_t thread; // Latest spawned thread
} state;

// Function prototypes
void init_socket(void);
void *handle_smtp (void *thread_arg);

// M     M     A     IIIIIII  N     N
// MM   MM    A A       I     NN    N
// M M M M   A   A      I     N N   N
// M  M  M  A     A     I     N N   N
// M     M  AAAAAAA     I     N  N  N
// M     M  A     A     I     N   N N
// M     M  A     A     I     N   N N
// M     M  A     A     I     N    NN
// M     M  A     A  IIIIIII  N     N
int main (int argc, char *argv[]) {
  int rc, i, j;
  char strbuf[INET6_ADDRSTRLEN];

  // This would be more useful as an argument
  state.domain = DOMAIN;

  // Open sockets to listen on for client connections
  init_socket();
  
  message_prefix = argv[1];

  // Loop forever listening for connections and spawning
  // threads to handle each exchange via handle_smtp()
  while (1) {
    fd_set sockets;
    FD_ZERO(&sockets);
    struct int_ll *p;

    for (p = state.sockfds; p != NULL; p = p->next) {
      FD_SET(p->d, &sockets);
    }

    // Wait forever for a connection on any of the bound sockets
    select (state.sockfd_max+1, &sockets, NULL, NULL, NULL);

    // Iterate through the sockets looking for one with a new connection
    for (p = state.sockfds; p != NULL; p = p->next) {
      if (FD_ISSET(p->d, &sockets)) {
        struct sockaddr_storage client_addr;
        socklen_t sin_size = sizeof(client_addr);
        int new_sock = accept (p->d, \
            (struct sockaddr*) &client_addr, &sin_size);
        if (new_sock == -1) {
          y_log_message(Y_LOG_LEVEL_ERROR, "Accepting client connection failed");
          continue;
        }

        // Pack the socket file descriptor into dynamic mem
        // to be passed to thread; it will free this when done.
        int * thread_arg = (int*) malloc(sizeof(int));
        *thread_arg = new_sock;

        // Spawn new thread to handle SMTP exchange
        pthread_create(&(state.thread), NULL, \
            handle_smtp, thread_arg);

      }
    }
  } // end forever loop

  return 0;
}



//   SSS      OOO      CCC    K    K   EEEEEEE  TTTTTTT
// SS   SS   O   O    CC CC   K   K    E           T   
// S        O     O  CC    C  K  K     E           T   
// SS       O     O  C        K K      E           T   
//   SSS    O     O  C        KK       EEEE        T   
//      SS  O     O  C        K K      E           T   
//       S  O     O  CC    C  K  K     E           T   
// SS   SS   O   O    CC CC   K   K    E           T   
//   SSS      OOO      CCC    K    K   EEEEEEE     T   
//
// Try to bind to as many local sockets as available.
// Typically this would just be one IPv4 and one IPv6 socket
void init_socket(void) {
  int rc, i, j, yes = 1;
  int sockfd;
  struct addrinfo hints, *hostinfo, *p;

  // Set up the hints indicating all of localhost's sockets
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;

  state.sockfds = NULL;
  state.sockfd_max = 0;

  rc = getaddrinfo(NULL, PORT, &hints, &hostinfo);
  if (rc != 0) {
    y_log_message(Y_LOG_LEVEL_ERROR, "Failed to get host addr info");
    exit(EXIT_FAILURE);
  }

  for (p=hostinfo; p != NULL; p = p->ai_next) {
    void *addr;
    char ipstr[INET6_ADDRSTRLEN];
    if (p->ai_family == AF_INET) {
      addr = &((struct sockaddr_in*)p->ai_addr)->sin_addr; 
    } else {
      addr = &((struct sockaddr_in6*)p->ai_addr)->sin6_addr; 
    }
    inet_ntop(p->ai_family, addr, ipstr, sizeof(ipstr));

    sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
    if (sockfd == -1) {
      y_log_message(Y_LOG_LEVEL_INFO, "Failed to create IPv%d socket", \
          (p->ai_family == AF_INET) ? 4 : 6 );
      continue;
    }

    setsockopt(sockfd, SOL_SOCKET, \
        SO_REUSEADDR, &yes, sizeof(int));

    rc = bind(sockfd, p->ai_addr, p->ai_addrlen);
    if (rc == -1) {
      close (sockfd);
      y_log_message(Y_LOG_LEVEL_INFO, "Failed to bind to IPv%d socket", \
          (p->ai_family == AF_INET) ? 4 : 6 );
      continue;
    }

    rc = listen(sockfd, BACKLOG_MAX);
    if (rc == -1) {
      y_log_message(Y_LOG_LEVEL_INFO, "Failed to listen to IPv%d socket", \
          (p->ai_family == AF_INET) ? 4 : 6 );
      exit(EXIT_FAILURE);
    }

    // Update highest fd value for select()
    (sockfd > state.sockfd_max) ? (state.sockfd_max = sockfd) : 1;

    // Add new socket to linked list of sockets to listen to
    struct int_ll *new_sockfd = malloc(sizeof(struct int_ll));
    new_sockfd->d = sockfd;
    new_sockfd->next = state.sockfds;
    state.sockfds = new_sockfd;
  }

  if (state.sockfds == NULL) {
    y_log_message(Y_LOG_LEVEL_ERROR, "Completely failed to bind to any sockets");
    exit(EXIT_FAILURE);
  }

  freeaddrinfo(hostinfo);

  return;
}

//   SSS    M     M  TTTTTTT  PPPP   
// SS   SS  MM   MM     T     P   PP 
// S        M M M M     T     P    PP
// SS       M  M  M     T     P   PP 
//   SSS    M     M     T     PPPP   
//      SS  M     M     T     P      
//       S  M     M     T     P      
// SS   SS  M     M     T     P      
//   SSS    M     M     T     P      
//
// This is typically spawned as a new thread for each exchange
// to handle the actual SMTP conversation with each client.
void *handle_smtp (void *thread_arg) {
  int rc, i, j;
  char buffer[BUF_SIZE], bufferout[BUF_SIZE];
  int buffer_offset = 0;
  buffer[BUF_SIZE-1] = '\0';

  // Unpack dynamic mem argument from main()
  int sockfd = *(int*)thread_arg;
  free(thread_arg);

  // Flag for being inside of DATA verb
  int inmessage = 0;

  sprintf(bufferout, "220 %s SMTP CCSMTP\r\n", state.domain);
  send(sockfd, bufferout, strlen(bufferout), 0);

  while (1) {
    fd_set sockset;
    struct timeval tv;

    FD_ZERO(&sockset);
    FD_SET(sockfd, &sockset);
    tv.tv_sec = 120; // Some SMTP servers pause for ~15s per message
    tv.tv_usec = 0;

    // Wait tv timeout for the server to send anything.
    select(sockfd+1, &sockset, NULL, NULL, &tv);

    if (!FD_ISSET(sockfd, &sockset)) {
      y_log_message(Y_LOG_LEVEL_DEBUG, "%d: Socket timed out", sockfd);
      break;
    }

    int buffer_left = BUF_SIZE - buffer_offset - 1;
    if (buffer_left == 0) {
      y_log_message(Y_LOG_LEVEL_DEBUG, "%d: Command line too long", sockfd);
      sprintf(bufferout, "500 Too long\r\n");
      send(sockfd, bufferout, strlen(bufferout), 0);
      buffer_offset = 0;
      continue;
    }

    rc = recv(sockfd, buffer + buffer_offset, buffer_left, 0);
    if (rc == 0) {
      y_log_message(Y_LOG_LEVEL_DEBUG, "%d: Remote host closed socket", sockfd);
      break;
    }
    if (rc == -1) {
      y_log_message(Y_LOG_LEVEL_DEBUG, "%d: Error on socket", sockfd);
      break;
    }

    buffer_offset += rc;

    char *eol;

    // Only process one line of the received buffer at a time
    // If multiple lines were received in a single recv(), goto
    // back to here for each line
    //
processline:
    eol = strstr(buffer, "\r\n");
    if (eol == NULL) {
      y_log_message(Y_LOG_LEVEL_DEBUG, "%d: Haven't found EOL yet", sockfd);
      continue;
    }

    // Null terminate each line to be processed individually
    eol[0] = '\0';

    if (!inmessage) { // Handle system verbs
      // Replace all lower case letters so verbs are all caps
      for (i=0; i<4; i++) {
        if (islower(buffer[i])) {
          buffer[i] += 'A' - 'a';
        }
      }
      // Null-terminate the verb for strcmp
      buffer[4] = '\0';

      // Respond to each verb accordingly.
      // You should replace these with more meaningful
      // actions than simply printing everything.
      //
      if (STREQU(buffer, "HELO")) { // Initial greeting
        sprintf(bufferout, "250 Ok\r\n");
        send(sockfd, bufferout, strlen(bufferout), 0);
      } else if (STREQU(buffer, "MAIL")) { // New mail from...
        sprintf(bufferout, "250 Ok\r\n");
        send(sockfd, bufferout, strlen(bufferout), 0);
      } else if (STREQU(buffer, "RCPT")) { // Mail addressed to...
        sprintf(bufferout, "250 Ok recipient\r\n");
        send(sockfd, bufferout, strlen(bufferout), 0);
      } else if (STREQU(buffer, "DATA")) { // Message contents...
        sprintf(bufferout, "354 Continue\r\n");
        send(sockfd, bufferout, strlen(bufferout), 0);
        inmessage = 1;
      } else if (STREQU(buffer, "RSET")) { // Reset the connection
        sprintf(bufferout, "250 Ok reset\r\n");
        send(sockfd, bufferout, strlen(bufferout), 0);
      } else if (STREQU(buffer, "NOOP")) { // Do nothing.
        sprintf(bufferout, "250 Ok noop\r\n");
        send(sockfd, bufferout, strlen(bufferout), 0);
      } else if (STREQU(buffer, "QUIT")) { // Close the connection
        sprintf(bufferout, "221 Ok\r\n");
        send(sockfd, bufferout, strlen(bufferout), 0);
        break;
      } else { // The verb used hasn't been implemented.
        sprintf(bufferout, "502 Command Not Implemented\r\n");
        send(sockfd, bufferout, strlen(bufferout), 0);
      }
    } else { // We are inside the message after a DATA verb.
      if (0 == o_strncmp(buffer, message_prefix, o_strlen(message_prefix))) {
        printf("%s\n", buffer + o_strlen(message_prefix));
      }

      if (STREQU(buffer, ".")) { // A single "." signifies the end
        sprintf(bufferout, "250 Ok\r\n");
        send(sockfd, bufferout, strlen(bufferout), 0);
        inmessage = 0;
      }
    }

    // Shift the rest of the buffer to the front
    memmove(buffer, eol+2, BUF_SIZE - (eol + 2 - buffer));
    buffer_offset -= (eol - buffer) + 2;

    // Do we already have additional lines to process? If so,
    // commit a horrid sin and goto the line processing section again.
    if (strstr(buffer, "\r\n")) 
      goto processline;
  }

  // All done. Clean up everything and exit.
  close(sockfd);
  pthread_exit(NULL);
}
