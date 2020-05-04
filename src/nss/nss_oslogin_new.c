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
#include <pthread.h>


#define SOCK_PATH "/usr/local/google/home/liamh/echo_socket"
#define BUFSIZE 1024
// ONEWORD_SIZE is the maximum size of one passwd entry. When creating a buffer
// to hold the entry prior to parsing into the user provided struct, we resize
// up to a maximum size, either the size of the user provided struct or
// ONEWORD_SIZE, whichever is smaller.
#define ONEWORD_SIZE 32768

// Locking implementation: use pthreads.
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
#define NSS_OSLOGIN_LOCK() \
  do {                           \
    pthread_mutex_lock(&mutex);  \
  } while (0)
#define NSS_OSLOGIN_UNLOCK() \
  do {                             \
    pthread_mutex_unlock(&mutex);  \
  } while (0)


// TODO: switch from \n to \0
// TODO: readline must do dynamic buffer (re-)allocation up to max as above
// TODO: change all perror()s to debug()s
// TODO: macro and function out the parsing routines

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

int dial(struct Buffer *buf) {
    if ((buf->socket = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
      perror("failed to create socket");
      return -1;
    }

    int len;
    struct sockaddr_un remote;
    remote.sun_family = AF_UNIX;
    strcpy(remote.sun_path, SOCK_PATH);
    len = strlen(remote.sun_path) + sizeof(remote.sun_family);
    if (connect(buf->socket, (struct sockaddr *)&remote, len) == -1) {
        perror("failed to connect");
        return -1;
    }

    return 0;
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

int parsepwent(char *str, struct passwd *result, char *buffer, size_t buflen) {
  // a passwd entry is e.g. USER:x:UID:GID:GECOS:HOMEDIR:SHELL
  // all string values need to go in the user-provided buffer, up to buflen
  //
  // so. count bytes til we get to a ':'
  // do we have that many bytes left in buflen?
  // ok then strncpy() it in to ->pw_name. don't forget about \0s!
  //
  // start over from where we are.
  // this should be one-byte 'x', verify that?
  //
  // start over from where we are.
  // count bytes til we get to a ':'
  // convert this to a number using atoi()
  // assign to ->pw_uid
  //
  // start over from where we are.
  // count bytes til we get to a ':'
  // convert this to a number using atoi()
  // assign to ->pw_gid
  //
  // start over from where we are.
  // count bytes til we get to a ':'
  // do we have that many bytes left in buflen?
  // ok then strncpy() it in to ->pw_gecos. don't forget about \0s!
  //
  // start over from where we are.
  // count bytes til we get to a ':'
  // do we have that many bytes left in buflen?
  // ok then strncpy() it in to ->pw_dir. don't forget about \0s!
  //
  // start over from where we are.
  // count bytes til we get to a ':'
  // do we have that many bytes left in buflen?
  // ok then strncpy() it in to ->pw_shell. don't forget about \0s!
  //
  // TODO: macro the read-and-count bit
  // we can use up the buffer proactively, that's fine
  char *ptr = str;
  int count = 0;
  for(; *ptr != ':'; ptr++)
    count++;
  if (count >= buflen) // no room left in buffer
    return -1;
  result->pw_name = strncpy(buffer, str, count);
  buflen -= (count + 1);
  buffer += (count + 1);
  *buffer = '\0';
  buffer++;
  str = ptr;

  count=0;
  for(; *ptr != ':'; ptr++)
    count++;
  str = ptr;

  count=0;
  for(; *ptr != ':'; ptr++)
    count++;
  char conv[100];
  strncpy(conv, str, count);
  conv[count+1] = '\0';
  result->pw_uid = atoi(conv);
  str = ptr;

  count=0;
  for(; *ptr != ':'; ptr++)
    count++;
  strncpy(conv, str, count);
  conv[count+1] = '\0';
  result->pw_gid = atoi(conv);
  str = ptr;

  return 0;
}

static enum nss_status
_nss_oslogin_getpwnam_r(const char *name, struct passwd *result, char *buffer,
                        size_t buflen, int *errnop) {
  // create a local manager struct
  struct Buffer mgr;
  mgr.buf = malloc(BUFSIZE);

  // dial the socket
  if (!(dial(&mgr))) {
    return NSS_STATUS_NOTFOUND;
  }

  // send the verb GETPWNAM with the argument <name>
  // TODO: validate incoming length of 'name' fits in 100 char
  char str[100];
  sprintf(str, "GETPWNAM %s\n", name);
  if (send(mgr.socket, str, strlen(str), 0) == -1) {
      perror("send");
      return NSS_STATUS_NOTFOUND;
  }

  // read a line using the local struct
  // TODO: stop using 'str' here
  if ((readaline(&mgr, str, 100)) < 0) {
    perror("failed to read result");
    return NSS_STATUS_NOTFOUND;
  }

  if (str[0] == '\n') {
    perror("no results for name");
    return NSS_STATUS_NOTFOUND;
  }

  // parse into struct passwd result

  // free and clear the local struct
  free(mgr.buf);
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
  // if needed (the socket in the struct is not NULL), close it.
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


int main(void)
{
    int len;
    struct sockaddr_un remote;
    //char *str = "GETPWENT\n";
    char *str = "GETPWNAM liamr\n";

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
    printf("Sending %s.\n", str);

    if (send(buffer->socket, str, strlen(str), 0) == -1) {
        perror("send");
        exit(1);
    }

    char *oneword;
    oneword = malloc(ONEWORD_SIZE);
    if ((readaline(buffer, oneword, ONEWORD_SIZE)) > 0) {
      if (oneword[0] == '\n') {
        printf("no results\n");
      } else {
        printf("got a line: \"%s\"\n", oneword);
      }
    }
    /*
    while ((readaline(buffer, oneword, ONEWORD_SIZE)) > 0) {
      if (oneword[0] == '\n') {
        printf("done!\n");
        break;
      }
      printf("got a line: \"%s\"\n", oneword);
    }
    */
    close(buffer->socket);
    return 0;
}

