#define _CRT_SECURE_NO_WARNINGS
#include <stdint.h>
#include <string.h>
#include <iostream>
#include "openssl/sha.h"

namespace FLAG{
  constexpr int32_t SHA_256 = 1;
  constexpr int32_t SHA_384 = 2;
  constexpr int32_t SHA_512 = 3;
}

int main(int argc, char** argv) {
  //参数判断
  if (2 != argc) {
    printf("the parameter is invalid...\n");
    return 1;
  }
  int retval = -1;
  uint32_t length = strlen(argv[1]);
  unsigned char buf[1024] = "";

  //选择加密方式
  int32_t flag = -1;
  printf("[1]-->SHA256\n[2]-->SHA384\n[3]-->SHA512\n");
  printf("Enter the one of SHA2:");
  scanf("%d", &flag);

  switch (flag) {
  case FLAG::SHA_256:
    SHA256_CTX sha256;
    //初始化
    retval = SHA256_Init(&sha256);
    if (1 != retval) {
      printf("SHA256_Init failed...\n");
      return 4;
    }

    //添加数据
    retval = SHA256_Update(&sha256, argv[1], length);
    if (1 != retval) {
      printf("SHA256_Update failed...\n");
      return 5;
    }

    //得到结果
    retval = SHA256_Final(buf, &sha256);
    if (1 != retval) {
      printf("SHA256_Final failed...\n");
      return 6;
    }

    for (int32_t i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
      printf("%x", buf[i]);
    }

    break;

  case FLAG::SHA_384:
    SHA512_CTX sha384;
    //初始化
    retval = SHA384_Init(&sha384);
    if (1 != retval) {
      printf("SHA384_Init failed...\n");
      return 8;
    }

    //添加数据
    retval = SHA384_Update(&sha384, argv[1], length);
    if (1 != retval) {
      printf("SHA384_Update failed...\n");
      return 9;
    }

    //得到结果
    retval = SHA384_Final(buf, &sha384);
    if (1 != retval) {
      printf("SHA384_Final failed...\n");
      return 10;
    }

    for (int32_t i = 0; i < SHA384_DIGEST_LENGTH; ++i) {
      printf("%x", buf[i]);
    }
    break;

  case FLAG::SHA_512:
    SHA512_CTX sha512;
    //初始化
    retval = SHA512_Init(&sha512);
    if (1 != retval) {
      printf("SHA512_Init failed...\n");
      return 11;
    }

    //添加数据
    retval = SHA512_Update(&sha512, argv[1], length);
    if (1 != retval) {
      printf("SHA512_Update failed...\n");
      return 12;
    }

    //得到结果
    retval = SHA512_Final(buf, &sha512);
    if (1 != retval) {
      printf("SHA512_Final failed...\n");
      return 13;
    }

    for (int32_t i = 0; i < SHA512_DIGEST_LENGTH; ++i) {
      printf("%x", buf[i]);
    }
    break;

  default:
    printf("error flag\n");
    return 2;
    break;
  }

  return 0;
}

