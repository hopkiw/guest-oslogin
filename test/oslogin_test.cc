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

// Requires libgtest-dev and gtest compiled and installed.
#include <errno.h>
#include <gtest/gtest.h>
// yes, the c file.
#include "../src/nss/nss_oslogin.c"
#include <stdio.h>
#include <stdlib.h>

using std::string;
using std::vector;

// functions to test:
//
//int parsepasswd(char *str, struct passwd *result, char *buffer, size_t buflen)
//int parsegroup(char *str, struct group *result, char *buffer, size_t buflen)
//int dial(struct Buffer *buf)
//int readaline(struct Buffer *buffer, char *oneword, int buflen)
//nss_status _nss_oslogin_getpwnam_r(const char *name, struct passwd *result, char *buffer, size_t buflen, int *errnop)
//nss_status _nss_oslogin_setpwent(int stayopen)
//nss_status _nss_oslogin_getpwent_r(struct passwd *result, char *buffer, size_t buflen, int *errnop)
//
//we need a test that shows that if i get erange during getpwent, resize my
//buffer, i'll get the same entry again. might need to be an integration test.

TEST(ParserTest, TestParsepasswd) {
  int res;
  ssize_t buflen;
  struct passwd result;
  char *buf;

  buflen = 32768;
  buf = (char *)malloc(buflen);

  res = parsepasswd((char *)"liamh:x:601004:89939:Liam Hopkins:/home/liamh:/bin/bash",
                   &result, buf, buflen);

  ASSERT_EQ(res, 0);
  ASSERT_EQ(result.pw_uid, 601004);
  ASSERT_EQ(result.pw_gid, 89939);
  ASSERT_STREQ(result.pw_name, "liamh");
  ASSERT_STREQ(result.pw_passwd, "x");
  ASSERT_STREQ(result.pw_gecos , "Liam Hopkins");
  ASSERT_STREQ(result.pw_dir, "/home/liamh");
  ASSERT_STREQ(result.pw_shell, "/bin/bash");
}

TEST(ParserTest, TestParsepasswdErange) {
  int res;
  ssize_t buflen;
  struct passwd result;
  char *buf;

  buflen = 32;
  buf = (char *)malloc(buflen);

  res = parsepasswd((char *)"liamh:x:601004:89939:Liam Hopkins:/home/liamh:/bin/bash",
                   &result, buf, buflen);

  ASSERT_EQ(res, ERANGE);
}

TEST(ParserTest, TestParsepasswdEnoent) {
  int res;
  ssize_t buflen;
  struct passwd result;
  char *buf;

  buflen = 32768;
  buf = (char *)malloc(buflen);

  res = parsepasswd((char *)"liamh:x:601004:89939:Liam Hopkins:/home/liamh",
                   &result, buf, buflen);

  ASSERT_EQ(res, ENOENT);
}

TEST(ParserTest, TestParsegroup) {
  int res;
  ssize_t buflen;
  struct group result;
  char *buf;

  buflen = 32768;
  buf = (char *)malloc(buflen);

  res = parsegroup((char *)"loas-corp-daemons:x:1000:x20,srcfs,objfs,binfs-fuse-client-role",
                   &result, buf, buflen);

  ASSERT_EQ(res, 0);
  ASSERT_EQ(result.gr_gid, 1000);
  ASSERT_STREQ(result.gr_name, "loas-corp-daemons");
  ASSERT_STREQ(result.gr_passwd, "x");
  ASSERT_STREQ(result.gr_mem[0], "x20");
  ASSERT_STREQ(result.gr_mem[1], "srcfs");
  ASSERT_STREQ(result.gr_mem[2], "objfs");
  ASSERT_STREQ(result.gr_mem[3], "binfs-fuse-client-role");
}

TEST(ParserTest, TestParsegroupErange) {
  int res;
  ssize_t buflen;
  struct group result;
  char *buf;

  buflen = 32;
  buf = (char *)malloc(buflen);

  res = parsegroup((char *)"loas-corp-daemons:x:1000:x20,srcfs,objfs,binfs-fuse-client-role",
                   &result, buf, buflen);

  ASSERT_EQ(res, ERANGE);
}

TEST(ParserTest, TestParsegroupEnoent) {
  int res;
  ssize_t buflen;
  struct group result;
  char *buf;

  buflen = 32768;
  buf = (char *)malloc(buflen);

  res = parsegroup((char *)"loas-corp-daemons:x", &result, buf, buflen);

  ASSERT_EQ(res, ENOENT);
}

TEST(IntegTest, TestGetpwnam) {
  int res;
  ssize_t buflen;
  struct passwd result;
  char *buf;

  buflen = 32;
  buf = (char *)malloc(buflen);

  res = _nss_oslogin_getpwent_r(&result, buf, buflen, &errno);
  ASSERT_EQ(res, ERANGE);

  buflen = 32768;
  buf = (char *)realloc(buf, buflen);

  res = _nss_oslogin_getpwent_r(&result, buf, buflen, &errno);
  ASSERT_EQ(res, 0);
}

TEST(IntegTest, TestGetpwuid) {
  int res;
  ssize_t buflen;
  struct passwd result;
  char *buf;

  buflen = 32;
  buf = (char *)malloc(buflen);

  res = _nss_oslogin_getpwent_r(&result, buf, buflen, &errno);
  ASSERT_EQ(res, ERANGE);

  buflen = 32768;
  buf = (char *)realloc(buf, buflen);

  res = _nss_oslogin_getpwent_r(&result, buf, buflen, &errno);
  ASSERT_EQ(res, 0);
}

TEST(IntegTest, TestGetgrnam) {
  int res;
  ssize_t buflen;
  struct passwd result;
  char *buf;

  buflen = 32;
  buf = (char *)malloc(buflen);

  res = _nss_oslogin_getpwent_r(&result, buf, buflen, &errno);
  ASSERT_EQ(res, ERANGE);

  buflen = 32768;
  buf = (char *)realloc(buf, buflen);

  res = _nss_oslogin_getpwent_r(&result, buf, buflen, &errno);
  ASSERT_EQ(res, 0);
}

TEST(IntegTest, TestGetgrgid) {
  nss_status res;
  int errnop;
  ssize_t buflen;
  struct group result;
  char *buf;

  buflen = 32768;
  buf = (char *)malloc(buflen);

  res = _nss_oslogin_getgrgid_r(123, &result, buf, buflen, &errnop);
  ASSERT_EQ(res, ERANGE);
}

TEST(IntegTest, TestGetpwentErange) {
  int res;
  ssize_t buflen;
  struct passwd result;
  char *buf;

  buflen = 32;
  buf = (char *)malloc(buflen);

  res = _nss_oslogin_getpwent_r(&result, buf, buflen, &errno);
  ASSERT_EQ(res, ERANGE);

  buflen = 32768;
  buf = (char *)realloc(buf, buflen);

  res = _nss_oslogin_getpwent_r(&result, buf, buflen, &errno);
  ASSERT_EQ(res, 0);
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
