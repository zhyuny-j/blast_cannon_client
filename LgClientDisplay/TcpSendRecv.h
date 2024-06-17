#pragma once
#include <winsock2.h>
#include <ws2tcpip.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

int ReadDataTcp(SOCKET socket, unsigned char* data, int length);
int ReadDataTcpNoBlock(SSL* ssl, unsigned char* data, int length);
int WriteDataTcp(SSL* ssl, unsigned char* data, int length);
//-----------------------------------------------------------------
// END of File
//-----------------------------------------------------------------