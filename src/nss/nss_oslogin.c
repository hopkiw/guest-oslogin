// Copyright 2020 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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


#define ONEWORD_SIZE 4096
#define MAX_ONEWORD_SIZE 1048576
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

#define new_DEBUGF(...) \
    do { } while(0)

#define MIN(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a < _b ? _a : _b; })

// Locking implementation: use pthreads.
static pthread_mutex_t pwmutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t grmutex = PTHREAD_MUTEX_INITIALIZER;
#define NSS_OSLOGIN_PWLOCK() \
  do {                           \
    pthread_mutex_lock(&pwmutex);  \
  } while (0)
#define NSS_OSLOGIN_PWUNLOCK() \
  do {                             \
    pthread_mutex_unlock(&pwmutex);  \
  } while (0)
#define NSS_OSLOGIN_GRLOCK() \
  do {                           \
    pthread_mutex_lock(&grmutex);  \
  } while (0)
#define NSS_OSLOGIN_GRUNLOCK() \
  do {                             \
    pthread_mutex_unlock(&grmutex);  \
  } while (0)


// TODO: strip \n from end of strings, don't create member names with \n in them
// TODO: switch from \n to \0
// TODO: recvline must do dynamic buffer (re-)allocation up to max as above
// TODO: should return NSS_STATUS_UNAVAIL if we fail to dial

int parsepasswd(char *str, struct passwd *result, char *buffer, size_t buflen) {
  DEBUGF("parsepasswd(%s)\n", str);
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
    DEBUGF("field is %d PW_END %d\n", field, PW_END);
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
  DEBUGF("parsegroup(%s)\n", str);
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
    DEBUGF("number of fields found: %d should be: %d, returning %d\n", field, GR_END, ENOENT);
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
  ssize_t buflen; // how much data we read into the buffer
  ssize_t bufsize; // allocated space for buffer
  char *buf;  // the buffer we copy results into
  int socket;
};

struct Buffer pwbuf;
struct Buffer grbuf;

int dial(struct Buffer *buf) {
  DEBUGF("entered dial\n");
  if (buf->socket != 0) {
    return 0;
  }
  if ((buf->socket = socket(AF_UNIX, SOCK_STREAM|SOCK_NONBLOCK, 0)) == -1) {
    DEBUGF("failed to create socket");
    return -1;
  }

  int len;
  struct sockaddr_un remote;
  remote.sun_family = AF_UNIX;
  strcpy(remote.sun_path, SOCK_PATH);
  len = strlen(remote.sun_path) + sizeof(remote.sun_family);
  if (connect(buf->socket, (struct sockaddr *)&remote, len) == -1) {
      DEBUGF("failed to connect\n");
      return -1;
  }

  return 0;
}

int recvline(struct Buffer *buffer) {
  int res = 0;
  ssize_t recvlen, new_size = 0;
  fd_set fds;
  struct timeval tmout = {2,0};


  // TODO: catch malloc errors
  char *recvbuf = (char *)malloc(BUFSIZE);

  while(1) {
    FD_ZERO(&fds);
    FD_SET(buffer->socket, &fds);
    res = select(buffer->socket+1, &fds, NULL, NULL, &tmout);
    if (res <= 0 || !(FD_ISSET(buffer->socket, &fds))) {
      DEBUGF("select\n");
      return -1;
    }
    DEBUGF("going to recv..\n");
    if ((recvlen = recv(buffer->socket, recvbuf, BUFSIZE, 0)) <= 0) {
      DEBUGF("error during recv, got %ld\n", recvlen);
      return -1;
    }

    // Determine if buffer needs resizing.
    if ((buffer->buflen + recvlen) > buffer->bufsize) {
      new_size = MIN((buffer->bufsize * 2), MAX_ONEWORD_SIZE);
      if (new_size == buffer->bufsize) {
        // We were already at limit!
        DEBUGF("we were already at limit! current bufsize is %ld and proposed was %ld\n", buffer->bufsize, new_size);
        return -1;
      }
      if (realloc(buffer->buf, new_size) == NULL) {
        DEBUGF("realloc failed!\n");
        return -1;
      }
      buffer->bufsize = new_size;
    }

    memcpy(&(buffer->buf[buffer->buflen]), recvbuf, recvlen);
    buffer->buflen += recvlen;

    if (recvbuf[recvlen - 1] == '\n') {
      return buffer->buflen;
    }
  }
}

static enum nss_status
_nss_oslogin_getpwnam_r(const char *name, struct passwd *result, char *buffer,
                        size_t buflen, int *errnop) {
  DEBUGF("entered getpwnam_r\n");
  // create a local manager struct
  // TODO: memset 0 this, or initialize fields
  int res;
  struct Buffer mgr;
  memset(&mgr, 0, sizeof(struct Buffer));

  *errnop = 0;
  mgr.bufsize = BUFSIZE;
  mgr.buf = (char *)malloc(BUFSIZE);


  // dial the socket
  if (dial(&mgr) != 0) {
    DEBUGF("failed to dial\n");
    return NSS_STATUS_NOTFOUND;
  }

  // send the verb GETPWNAM with the argument <name>
  // TODO: validate incoming length of 'name' fits in 100 char
  char str[1000];
  sprintf(str, "GETPWNAM %s\n", name);
  if ((res = send(mgr.socket, str, strlen(str), 0)) == -1) {
    perror("send failed");
    return NSS_STATUS_NOTFOUND;
  }

  // read a line using the local struct
  // TODO: stop using 'str' here
  if ((recvline(&mgr)) < 0) {
    DEBUGF("failed to read result\n");
    free(mgr.buf);
    return NSS_STATUS_NOTFOUND;
  }

  if (mgr.buf[0] == '\n') {
    DEBUGF("no results for name\n");
    return NSS_STATUS_NOTFOUND;
  }

  // parse into struct passwd result
  res = parsepasswd(mgr.buf,result,buffer,buflen);
  if (res == 0) {
    return NSS_STATUS_SUCCESS;
  }
  *errnop = res;
  if (res == ERANGE) {
    return NSS_STATUS_TRYAGAIN;
  }
  return NSS_STATUS_NOTFOUND;
}

static enum nss_status
_nss_oslogin_getpwuid_r(uid_t uid, struct passwd *result, char *buffer,
                        size_t buflen, int *errnop) {
  DEBUGF("entered getpwuid_r\n");
  // create a local manager struct
  // TODO: memset 0 this, or initialize fields
  int res;
  struct Buffer mgr;
  memset(&mgr, 0, sizeof(struct Buffer));

  *errnop = 0;
  mgr.bufsize = BUFSIZE;
  mgr.buf = (char *)malloc(BUFSIZE);

  // dial the socket
  if (dial(&mgr) != 0) {
    return NSS_STATUS_NOTFOUND;
  }

  // send the verb GETPWUID with the argument <uid>
  // TODO: validate incoming length of 'uid' fits in 100 char
  char str[100];
  sprintf(str, "GETPWUID %d\n", uid);
  if (send(mgr.socket, str, strlen(str), 0) == -1) {
      perror("send failed:");
      return NSS_STATUS_NOTFOUND;
  }


  // read a line using the local struct
  // TODO: stop using 'str' here
  if ((recvline(&mgr)) < 0) {
    DEBUGF("failed to read result\n");
    free(mgr.buf);
    return NSS_STATUS_NOTFOUND;
  }

  if (mgr.buf[0] == '\n') {
    DEBUGF("no results for uid\n");
    return NSS_STATUS_NOTFOUND;
  }

  // parse into struct passwd result
  res = parsepasswd(mgr.buf,result,buffer,buflen);
  if (res == 0) {
    return NSS_STATUS_SUCCESS;
  }
  *errnop = res;
  if (res == ERANGE) {
    return NSS_STATUS_TRYAGAIN;
  }
  return NSS_STATUS_NOTFOUND;
}

static enum nss_status _nss_oslogin_endpwent_locked(void) {
  DEBUGF("entered endpwent_locked\n");
  pwbuf.bufsize = 0;
  pwbuf.buflen = 0;

  // if needed (the socket in the struct is not 0), close it.
  if (pwbuf.socket != 0) {
    close(pwbuf.socket);
    pwbuf.socket = 0;
  }

  // if needed (the buffer in the struct is not NULL), free it.
  if (pwbuf.buf != NULL) {
    free(pwbuf.buf);
    pwbuf.buf = NULL;
  }

  return NSS_STATUS_SUCCESS;
}

static enum nss_status _nss_oslogin_endpwent(void) {
  enum nss_status ret;
  NSS_OSLOGIN_PWLOCK();
  ret = _nss_oslogin_endpwent_locked();
  NSS_OSLOGIN_PWUNLOCK();
  return ret;
}

// "rewind" for getpwent calls, here by dialing again
// unit test would be to getpwent N times, setpwent, then getpwent and see if it
// gives the original first line
static enum nss_status _nss_oslogin_setpwent_locked() {
  DEBUGF("entered setpwent_locked\n");
  // if the socket in the struct is not 0, close it.
  if (pwbuf.socket != 0) {
    _nss_oslogin_endpwent_locked();
  }
  // dial the socket
  if (dial(&pwbuf) != 0) {
    return NSS_STATUS_UNAVAIL;
  }

  return NSS_STATUS_SUCCESS;
}

static enum nss_status _nss_oslogin_setpwent(int __attribute__((__unused__)) stayopen) {
  enum nss_status ret;
  NSS_OSLOGIN_PWLOCK();
  ret = _nss_oslogin_setpwent_locked();
  NSS_OSLOGIN_PWUNLOCK();
  return ret;
}

static enum nss_status
_nss_oslogin_getpwent_r_locked(struct passwd *result, char *buffer, size_t buflen,
                        int *errnop) {
  DEBUGF("entered getpwent_r_locked\n");
  int res;
  *errnop = 0;

  // dial the socket
  if (pwbuf.buf == NULL) {
    pwbuf.buf = (char *)malloc(BUFSIZE);
    if (pwbuf.buf == NULL || dial(&pwbuf) != 0) {
      return NSS_STATUS_NOTFOUND;
    }
    pwbuf.bufsize = BUFSIZE;
  }

  if (pwbuf.buflen == 0) {
    // send the verb GETPWENT with no argument
    char str[] = "GETPWENT\n";
    if (send(pwbuf.socket, str, strlen(str), 0) == -1) {
        DEBUGF("send\n");
        return NSS_STATUS_NOTFOUND;
    }

    // read a line using the global struct
    if ((recvline(&pwbuf)) < 0) {
      DEBUGF("failed to read result\n");
      return NSS_STATUS_NOTFOUND;
    }

    if (pwbuf.buf[0] == '\n') {
      DEBUGF("no results for name\n");
      return NSS_STATUS_NOTFOUND;
    }
  }

  // parse into struct passwd result
  res = parsepasswd(pwbuf.buf,result,buffer,buflen);
  if (res == 0) {
    //memset(pwbuf.buf, 0, pwbuf.bufsize);
    pwbuf.buflen = 0;
    return NSS_STATUS_SUCCESS;
  }
  *errnop = res;
  if (res == ERANGE) {
    DEBUGF("returning ERANGE\n");
    return NSS_STATUS_TRYAGAIN;
  }
  _nss_oslogin_endpwent();
  DEBUGF("returning error, res was %d\n", res);
  return NSS_STATUS_NOTFOUND;
}

static enum nss_status
_nss_oslogin_getpwent_r(struct passwd *result, char *buffer, size_t buflen,
                        int *errnop) {
  enum nss_status ret;
  NSS_OSLOGIN_PWLOCK();
  ret = _nss_oslogin_getpwent_r_locked(result, buffer, buflen, errnop);
  NSS_OSLOGIN_PWUNLOCK();

  return ret;
}

static enum nss_status
_nss_oslogin_getgrnam_r(const char *name, struct group *result, char *buffer,
                        size_t buflen, int *errnop) {
  DEBUGF("entered getgrnam_r\n");
  // create a local manager struct
  // TODO: memset 0 this, or initialize fields
  int res;
  struct Buffer mgr;
  memset(&mgr, 0, sizeof(struct Buffer));

  *errnop = 0;
  mgr.bufsize = BUFSIZE;
  mgr.buf = (char *)malloc(BUFSIZE);

  // dial the socket
  if (dial(&mgr) != 0) {
    return NSS_STATUS_NOTFOUND;
  }

  // send the verb GETPWNAM with the argument <name>
  // TODO: validate incoming length of 'name' fits in 100 char
  char str[1000];
  sprintf(str, "GETGRNAM %s\n", name);
  if (send(mgr.socket, str, strlen(str), 0) == -1) {
      DEBUGF("send\n");
      return NSS_STATUS_NOTFOUND;
  }

  // read a line using the local struct
  // TODO: stop using 'str' here
  if ((recvline(&mgr)) < 0) {
    DEBUGF("failed to read result\n");
    free(mgr.buf);
    return NSS_STATUS_NOTFOUND;
  }

  if (mgr.buf[0] == '\n') {
    DEBUGF("no results for name\n");
    return NSS_STATUS_NOTFOUND;
  }

  // parse into struct passwd result
  res = parsegroup(mgr.buf,result,buffer,buflen);
  if (res == 0) {
    return NSS_STATUS_SUCCESS;
  }
  *errnop = res;
  if (res == ERANGE) {
    return NSS_STATUS_TRYAGAIN;
  }
  return NSS_STATUS_NOTFOUND;
}

static enum nss_status
_nss_oslogin_getgrgid_r(gid_t gid, struct group *result, char *buffer,
                        size_t buflen, int *errnop) {
  DEBUGF("entered getgrgid_r\n");
  // create a local manager struct
  // TODO: memset 0 this, or initialize fields
  int res;
  struct Buffer mgr;
  memset(&mgr, 0, sizeof(struct Buffer));

  *errnop = 0;
  mgr.bufsize = BUFSIZE;
  mgr.buf = (char *)malloc(BUFSIZE);

  // dial the socket
  if (dial(&mgr) != 0) {
    return NSS_STATUS_NOTFOUND;
  }

  // send the verb GETGRGID with the argument <gid>
  // TODO: validate incoming length of 'name' fits in 100 char
  char str[1000];
  sprintf(str, "GETGRGID %d\n", gid);
  if (send(mgr.socket, str, strlen(str), 0) == -1) {
      DEBUGF("send\n");
      return NSS_STATUS_NOTFOUND;
  }

  // read a line using the local struct
  // TODO: stop using 'str' here
  if ((recvline(&mgr)) < 0) {
    DEBUGF("failed to read result\n");
    free(mgr.buf);
    return NSS_STATUS_NOTFOUND;
  }

  if (mgr.buf[0] == '\n') {
    DEBUGF("no results for name\n");
    return NSS_STATUS_NOTFOUND;
  }

  // parse into struct passwd result
  res = parsegroup(mgr.buf,result,buffer,buflen);
  if (res == 0) {
    return NSS_STATUS_SUCCESS;
  }
  *errnop = res;
  if (res == ERANGE) {
    return NSS_STATUS_TRYAGAIN;
  }
  return NSS_STATUS_NOTFOUND;
}



static enum nss_status _nss_oslogin_endgrent_locked(void) {
  grbuf.bufsize = 0;
  grbuf.buflen = 0;

  // if needed (the socket in the struct is not NULL), close it.
  if (grbuf.socket != 0) {
    close(grbuf.socket);
    grbuf.socket = 0;
  }

  // if needed (the buffer in the struct is not NULL), free it.
  if (grbuf.buf != NULL) {
    free(grbuf.buf);
    grbuf.buf = NULL;
  }

  return NSS_STATUS_SUCCESS;
}

static enum nss_status _nss_oslogin_endgrent(void) {
  enum nss_status ret;
  NSS_OSLOGIN_GRLOCK();
  ret = _nss_oslogin_endgrent_locked();
  NSS_OSLOGIN_GRUNLOCK();
  return ret;
}

static enum nss_status _nss_oslogin_setgrent_locked() {
  // if the socket in the struct is not 0, close it.
  if (grbuf.socket != 0) {
    _nss_oslogin_endgrent_locked();
  }
  // dial the socket
  if (!dial(&grbuf)) {
    return NSS_STATUS_UNAVAIL;
  }

  return NSS_STATUS_SUCCESS;
}

static enum nss_status _nss_oslogin_setgrent(int __attribute__((__unused__)) stayopen) {
  enum nss_status ret;
  NSS_OSLOGIN_GRLOCK();
  ret = _nss_oslogin_setgrent_locked();
  NSS_OSLOGIN_GRUNLOCK();
  return ret;
}

static enum nss_status
_nss_oslogin_getgrent_r_locked(struct group *result, char *buffer, size_t
                               buflen, int *errnop) {
  DEBUGF("entered getgrent_r_locked\n");
  int res;
  *errnop = 0;

  // dial the socket
  if (grbuf.buf == NULL) {
    grbuf.buf = (char *)malloc(BUFSIZE);
    if (grbuf.buf == NULL || dial(&grbuf) != 0) {
      return NSS_STATUS_NOTFOUND;
    }
    grbuf.bufsize = BUFSIZE;
  }

  if (grbuf.buflen == 0) {
    // send the verb GETGRENT with no argument
    char str[] = "GETGRENT\n";
    if (send(grbuf.socket, str, strlen(str), 0) == -1) {
        DEBUGF("send\n");
        return NSS_STATUS_NOTFOUND;
    }

    // read a line using the global struct
    if ((recvline(&grbuf)) < 0) {
      DEBUGF("failed to read result\n");
      return NSS_STATUS_NOTFOUND;
    }

    if (grbuf.buf[0] == '\n') {
      DEBUGF("no results for name\n");
      return NSS_STATUS_NOTFOUND;
    }
  }

  // parse into struct passwd result
  res = parsegroup(grbuf.buf,result,buffer,buflen);
  if (res == 0) {
    //memset(grbuf.buf, 0, grbuf.bufsize);
    grbuf.buflen = 0;
    return NSS_STATUS_SUCCESS;
  }
  *errnop = res;
  if (res == ERANGE) {
    DEBUGF("returning ERANGE\n");
    return NSS_STATUS_TRYAGAIN;
  }
  _nss_oslogin_endgrent();
  DEBUGF("returning error, res was %d\n", res);
  return NSS_STATUS_NOTFOUND;
}

static enum nss_status
_nss_oslogin_getgrent_r(struct group *result, char *buffer, size_t buflen,
                        int *errnop) {
  enum nss_status ret;
  NSS_OSLOGIN_PWLOCK();
  ret = _nss_oslogin_getgrent_r_locked(result, buffer, buflen, errnop);
  NSS_OSLOGIN_PWUNLOCK();

  return ret;
}

NSS_METHOD_PROTOTYPE(__nss_compat_getpwnam_r);
NSS_METHOD_PROTOTYPE(__nss_compat_getpwuid_r);
NSS_METHOD_PROTOTYPE(__nss_compat_getpwent_r);
NSS_METHOD_PROTOTYPE(__nss_compat_setpwent);
NSS_METHOD_PROTOTYPE(__nss_compat_endpwent);

NSS_METHOD_PROTOTYPE(__nss_compat_getgrnam_r);
NSS_METHOD_PROTOTYPE(__nss_compat_getgrgid_r);
NSS_METHOD_PROTOTYPE(__nss_compat_getgrent_r);
NSS_METHOD_PROTOTYPE(__nss_compat_setgrent);
NSS_METHOD_PROTOTYPE(__nss_compat_endgrent);

DECLARE_NSS_METHOD_TABLE(methods,
                         {NSDB_PASSWD, "getpwnam_r", __nss_compat_getpwnam_r,
                          (void *)_nss_oslogin_getpwnam_r},
                         {NSDB_PASSWD, "getpwuid_r", __nss_compat_getpwuid_r,
                          (void *)_nss_oslogin_getpwuid_r},
                         {NSDB_PASSWD, "getpwent_r", __nss_compat_getpwent_r,
                          (void *)_nss_oslogin_getpwent_r},
                         {NSDB_PASSWD, "endpwent", __nss_compat_endpwent,
                          (void *)_nss_oslogin_endpwent},
                         {NSDB_PASSWD, "setpwent", __nss_compat_setpwent,
                          (void *)_nss_oslogin_setpwent},
                         {NSDB_GROUP, "getgrnam_r", __nss_compat_getgrnam_r,
                          (void *)_nss_oslogin_getgrnam_r},
                         {NSDB_GROUP, "getgrgid_r", __nss_compat_getgrgid_r,
                          (void *)_nss_oslogin_getgrgid_r},
                         {NSDB_GROUP, "getgrent_r", __nss_compat_getgrent_r,
                          (void *)_nss_oslogin_getgrent_r},
                         {NSDB_GROUP, "endgrent", __nss_compat_endgrent,
                          (void *)_nss_oslogin_endgrent},
                         {NSDB_GROUP, "setgrent", __nss_compat_setgrent,
                          (void *)_nss_oslogin_setgrent}, )

NSS_REGISTER_METHODS(methods)
