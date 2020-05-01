#include <nss.h>
#include <pwd.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#define SOCK_PATH "echo_socket"
#define BUFSIZE 1024
// ONEWORD_SIZE is the maximum size of one passwd entry. When creating a buffer
// to hold the entry prior to parsing into the user provided struct, we resize
// up to a maximum size, either the size of the user provided struct or
// ONEWORD_SIZE, whichever is smaller.
#define ONEWORD_SIZE 32768


// when do we malloc for the string to be parsed? it should be the one that
// grows as needed up to buflen.. so this is the highest level it could exist.
// but readaline currently doesn't do that resizing, either it needs to or i
// need to.
// all the nss functions are going to need to create resizeable buffers

struct Buffer {
  int socket; // the socket we read from
  char *buf;  // the 1-KB buffer we read into
  int rpos;   // our current byte position in the buffer
  ssize_t buflen; // how much data we read into the buffer
};

static enum nss_status
_nss_oslogin_getpwnam_r(const char *name, struct passwd *result, char *buffer,
                        size_t buflen, int *errnop) {
  // doesn't use the global resources, so doesn't need to use locks.
  // create a local struct
  // dial the socket
  // send the verb GETPWNAM with the argument <name>
  // read a line using the local struct
  // free and clear the local struct
  return NSS_STATUS_SUCCESS;
}

// "rewind" for getpwent calls, here by dialing again
// unit test would be to getpwent N times, setpwent, then getpwent and see if it
// gives the original first line
static enum nss_status _nss_oslogin_setpwent(int stayopen) {
  // get the lock
  // if the socket in the struct is not 0, close it.
  // dial the socket
  // release the lock
  return NSS_STATUS_SUCCESS;
}

// "cleanup", we aren't going to be calling anymore
static enum nss_status _nss_oslogin_endpwent(void) {
  // get the lock
  // if the socket in the struct is not 0, close it.
  // release the lock
  return NSS_STATUS_SUCCESS;
}

static enum nss_status
_nss_oslogin_getpwent_r(struct passwd *result, char *buffer, size_t buflen,
                        int *errnop) {
  // get the lock
  // call setpwent if the socket isn't created and connected yet
  // malloc for the recv buffer
  // send the verb GETPWENT
  // get a line using the *global* struct socket and buffer
  // parse it into result
  // release the lock
  return NSS_STATUS_SUCCESS;
}

int readaline(struct Buffer *buffer, char *oneword, int buflen) {
  int wpos = 0;
  int count = 0;
  while(1) {
    count++;
    for (; buffer->rpos < buffer->buflen; buffer->rpos++) {
      if (wpos >= buflen) {
        printf("wpos >= buflen\n");
        // ran out of room. set errno? return special val?
        // TODO: next call needs to still return THIS line
        return -1;
      }
      oneword[wpos++] = buffer->buf[buffer->rpos];
      if (buffer->buf[buffer->rpos] == '\n') {
        oneword[wpos++] = '\0';
        buffer->rpos++;
        return wpos;
      }
    }
    buffer->rpos = 0;
    if (buffer->buflen > 0 && buffer->buflen < BUFSIZE) {
      // this was the last bit of data in the recv queue, don't recv anymore.
      // Since we didn't return above, it must not have ended on a newline.
      //
      // TODO: what about when we have the last bit of data but buflen does
      // equal BUFSIZE ? Any chance of a hanging recv() ?
      printf("buffer->buflen < BUFSIZE\n");
      return -1;
    }
    if ((buffer->buflen = recv(buffer->socket, buffer->buf, BUFSIZE, 0)) < 0) {
      perror("recv");
      return -1;
    }
  }
}

int main(void)
{
    int len;
    struct sockaddr_un remote;
    char *str = "GETPWENT\n";

    struct Buffer *buffer;
    buffer = malloc(sizeof(struct Buffer));
    buffer->buf = malloc(BUFSIZE);

    if ((buffer->socket = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        perror("socket");
        exit(1);
    }

    printf("Trying to connect...\n");

    remote.sun_family = AF_UNIX;
    strcpy(remote.sun_path, SOCK_PATH);
    len = strlen(remote.sun_path) + sizeof(remote.sun_family);
    if (connect(buffer->socket, (struct sockaddr *)&remote, len) == -1) {
        perror("connect");
        exit(1);
    }

    printf("Connected.\n");

    if (send(buffer->socket, str, strlen(str), 0) == -1) {
        perror("send");
        exit(1);
    }

    char *oneword;
    oneword = malloc(ONEWORD_SIZE);
    while ((readaline(buffer, oneword, ONEWORD_SIZE)) > 0) {
      if (oneword[0] == '\n') {
        printf("done!\n");
        break;
      }
      printf("got a line: \"%s\"\n", oneword);
    }
    close(buffer->socket);
    return 0;
}

