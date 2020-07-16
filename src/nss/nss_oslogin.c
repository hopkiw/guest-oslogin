#include <nss.h>
#include <pwd.h>
#include <grp.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <pthread.h>


// ONEWORD_SIZE is the maximum size of one passwd entry. When creating a buffer
// to hold the entry prior to parsing into the user provided struct, we resize
// up to a maximum size, either the size of the user provided struct or
// ONEWORD_SIZE, whichever is smaller.
#define ONEWORD_SIZE 32768
#define SOCK_PATH "/usr/local/google/home/liamh/echo_socket"
#define BUFSIZE 1024

#define MAX_GR_MEM 100

#define PW_NAME 0
#define PW_PASSWD 1
#define PW_UID 2
#define PW_GID 3
#define PW_GECOS 4
#define PW_DIR 5
#define PW_SHELL 6
#define PW_END 7

#define GR_NAME 0
#define GR_PASSWD 1
#define GR_GID 2
#define GR_MEM 3
#define GR_END 4

#define LEN(index) ((fields[index+1] - fields[index]) - 1)

#define COPYINT(index, result) \
    do { \
      memset(buffer,0,buflen); \
      memcpy(buffer,&str[fields[index]],LEN(index)); \
      buffer[LEN(index)+1] = '\0'; \
      result = atoi(buffer); \
    } while(0)

#define COPYSTR(index, result) \
    do { \
      result = buffer; \
      memcpy(buffer, &str[fields[index]], LEN(index)); \
      buffer[LEN(index)+1] = '\0'; \
      buffer += LEN(index)+1; \
    } while(0)

#define DEBUGF(...) \
    do { \
      fprintf (stderr, __VA_ARGS__); \
    } while(0)

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


// TODO: strip \n from end of strings, don't create member names with \n in them
// TODO: switch from \n to \0
// TODO: readline must do dynamic buffer (re-)allocation up to max as above
// DONE: macro and function out the parsing routines

// when do we malloc for the string to be parsed? it should be the one that
// grows as needed up to buflen.. so this is the highest level it could exist.
// but readaline currently doesn't do that resizing, either it needs to or i
// need to.
// all the nss functions are going to need to create resizeable buffers

void getpwnam_r_locked() {
  NSS_OSLOGIN_LOCK();
  DEBUGF("would now call getpwnam\n");
  NSS_OSLOGIN_UNLOCK();
}

int parsepasswd(char *str, struct passwd *result, char *buffer, size_t buflen) {
  int fields[PW_END+1] = {0};

  fields[PW_END] = strlen(str)+1;
  if (fields[PW_END] > (int)buflen) {
    return ERANGE;
  }

  int i, field;
  for(field = 1, i = 0; i < fields[PW_END]; i++) {
    if (str[i] == ':') {
      fields[field++] = i+1;
    }
  }

  if (field != PW_END) {
    return ENOENT;
  }

  COPYINT(PW_UID, result->pw_uid);
  COPYINT(PW_GID, result->pw_gid);

  memset(buffer, 0, fields[PW_END]);
  COPYSTR(PW_NAME, result->pw_name);
  COPYSTR(PW_PASSWD, result->pw_passwd);
  COPYSTR(PW_GECOS, result->pw_gecos);
  COPYSTR(PW_DIR, result->pw_dir);
  COPYSTR(PW_SHELL, result->pw_shell);

  return 0;
}

int parsegroup(char *str, struct group *result, char *buffer, size_t buflen) {
  int fields[GR_END+1] = {0};
  int members[MAX_GR_MEM] = {0};
  int i, field, len;
  char **bufp;

  // Check whether buffer can fit the string.
  fields[GR_END] = strlen(str)+1;
  if (fields[GR_END] > (int)buflen) {
    return ERANGE;
  }

  // Record field indexes.
  for(field = 1, i = 0; i < fields[GR_END]; i++) {
    if (str[i] == ':') {
      fields[field++] = i+1;
    }
  }

  // Wrong number of fields in record.
  if (field != GR_END) {
    return ENOENT;
  }

  // Record member indexes.
  members[0] = fields[GR_MEM];
  for(field = 1, i = fields[GR_MEM]; i < fields[GR_END]; i++) {
    if (str[i] == ',') {
      members[field++] = i+1;
    }
  }
  members[field] = fields[GR_END];

  // Check whether the buffer can fit the char* array.
  if ((fields[GR_END] + ((field+1) * sizeof(char *))) > buflen) {
    return ERANGE;
  }

  COPYINT(GR_GID, result->gr_gid);

  memset(buffer, 0, fields[GR_END]);
  COPYSTR(GR_NAME, result->gr_name);
  COPYSTR(GR_PASSWD, result->gr_passwd);

  result->gr_mem = bufp = (char **)buffer;
  buffer += (sizeof(char *) * (field + 1));

  for(i = 0; i < field; i++) {
    len = ((members[i+1] - members[i]) - 1);
    memcpy(buffer, &str[members[i]], len);
    buffer[len+1] = '\0';

    *(bufp++) = buffer;
    buffer += len+1;
  }
  *bufp = NULL;

  return 0;
}

struct Buffer {
  int socket; // the socket we read from
  char *buf;  // the 1-KB buffer we read into
  int rpos;   // our current byte position in the buffer
  ssize_t buflen; // how much data we read into the buffer
};

int dial(struct Buffer *buf) {
    if ((buf->socket = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
      DEBUGF("failed to create socket");
      return -1;
    }

    int len;
    struct sockaddr_un remote;
    remote.sun_family = AF_UNIX;
    strcpy(remote.sun_path, SOCK_PATH);
    len = strlen(remote.sun_path) + sizeof(remote.sun_family);
    if (connect(buf->socket, (struct sockaddr *)&remote, len) == -1) {
        DEBUGF("failed to connect");
        return -1;
    }

    return 0;
}

int readaline(struct Buffer *buffer, char *oneword, int buflen) {
  int wpos = 0;
  while(1) {
    for (; buffer->rpos < buffer->buflen; buffer->rpos++) {
      if (wpos >= buflen) {
        DEBUGF("wpos >= buflen\n");
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
      DEBUGF("buffer->buflen < BUFSIZE\n");
      return -1;
    }
    if ((buffer->buflen = recv(buffer->socket, buffer->buf, BUFSIZE, 0)) < 0) {
      DEBUGF("recv");
      return -1;
    }
  }
}

static enum nss_status
_nss_oslogin_getpwnam_r(const char *name, struct passwd *result, char *buffer,
                        size_t buflen, int *errnop) {
  // create a local manager struct
  struct Buffer mgr;
  mgr.buf = (char *)malloc(BUFSIZE);

  // dial the socket
  if (!(dial(&mgr))) {
    return NSS_STATUS_NOTFOUND;
  }

  // send the verb GETPWNAM with the argument <name>
  // TODO: validate incoming length of 'name' fits in 100 char
  char str[100];
  sprintf(str, "GETPWNAM %s\n", name);
  if (send(mgr.socket, str, strlen(str), 0) == -1) {
      DEBUGF("send");
      return NSS_STATUS_NOTFOUND;
  }

  // read a line using the local struct
  // TODO: stop using 'str' here
  if ((readaline(&mgr, str, 100)) < 0) {
    DEBUGF("failed to read result");
    return NSS_STATUS_NOTFOUND;
  }

  if (str[0] == '\n') {
    DEBUGF("no results for name");
    return NSS_STATUS_NOTFOUND;
  }

  // parse into struct passwd result
  parsepasswd(str,result,buffer,buflen);

  // free and clear the local struct
  free(mgr.buf);
  return NSS_STATUS_SUCCESS;
}

static enum nss_status
_nss_oslogin_getpwuid_r(uid_t uid, struct passwd *result, char *buffer,
                        size_t buflen, int *errnop) {
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
  DEBUGF("stayopen %d\n", stayopen);
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
  DEBUGF("result %p buffer %p buflen %zd errnop %p\n", result, buffer,
         buflen, errnop);
  return NSS_STATUS_SUCCESS;
}

static enum nss_status
_nss_oslogin_getgrnam_r(const char *name, struct group *result, char *buffer,
                        size_t buflen, int *errnop) {
  return NSS_STATUS_SUCCESS;
}

static enum nss_status
_nss_oslogin_getgrgid_r(gid_t gid, struct group *result, char *buffer,
                        size_t buflen, int *errnop) {
  return NSS_STATUS_SUCCESS;
}

static enum nss_status _nss_oslogin_setgrent(int stayopen) {
  DEBUGF("stayopen %d\n", stayopen);
  return NSS_STATUS_SUCCESS;
}

static enum nss_status _nss_oslogin_endgrent(void) {
  return NSS_STATUS_SUCCESS;
}

static enum nss_status
_nss_oslogin_getgrent_r(struct group *result, char *buffer, size_t buflen,
                        int *errnop) {
  DEBUGF("result %p buffer %p buflen %zd errnop %p\n", result, buffer,
         buflen, errnop);
  return NSS_STATUS_SUCCESS;
}
