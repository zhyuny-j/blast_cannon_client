#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <atlstr.h>
#include <cstdlib >
#include <opencv2\highgui\highgui.hpp>
#include <opencv2\opencv.hpp>
#include "Message.h"
#include "Client.h"
#include "LgClientDisplay.h"
#include "TcpSendRecv.h"
#include "DisplayImage.h"

#include <wincrypt.h>
#include <wincred.h>
#include <iostream>

#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")
#pragma comment(lib, "advapi32.lib")

#define CA_CERT_FILE "ca.crt.pem"
#define CLIENT_CERT_FILE "client.crt.pem"
#define CLIENT_KEY_FILE "client.key.pem"

enum InputMode { MsgHeader, Msg };
static  std::vector<uchar> sendbuff;//buffer for coding
static HANDLE hClientEvent = INVALID_HANDLE_VALUE;
static HANDLE hEndClientEvent = INVALID_HANDLE_VALUE;
static SOCKET Client = INVALID_SOCKET;
static cv::Mat ImageIn;
static DWORD ThreadClientID;
static HANDLE hThreadClient = INVALID_HANDLE_VALUE;

static DWORD WINAPI ThreadClient(LPVOID ivalue);
static void ClientSetExitEvent(void);
static void ClientCleanup(void);

SSL* ssl;

char* reveivedHmac;
char* token;

SSL_CTX* InitCTX() {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == nullptr) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    // Set TLS Version to TLSv1.2
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);
    return ctx;
}


static void ClientSetExitEvent(void)
{
    if (hEndClientEvent != INVALID_HANDLE_VALUE)
        SetEvent(hEndClientEvent);
}
static void ClientCleanup(void)
{
    std::cout << "ClientCleanup" << std::endl;

    if (hClientEvent != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hClientEvent);
        hClientEvent = INVALID_HANDLE_VALUE;
    }
    if (hEndClientEvent != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hEndClientEvent);
        hEndClientEvent = INVALID_HANDLE_VALUE;
    }
    if (Client != INVALID_SOCKET)
    {
        closesocket(Client);
        Client = INVALID_SOCKET;
    }
}
bool SendCodeToSever(unsigned char Code)
{
    if (IsClientConnected())
    {
        TMesssageCommands MsgCmd;
        int msglen = sizeof(TMesssageHeader) + sizeof(unsigned char);
        //printf("Message len %d\n", msglen);
        MsgCmd.Hdr.Len = htonl(sizeof(unsigned char));
        MsgCmd.Hdr.Type = htonl(MT_COMMANDS);
        MsgCmd.Commands = Code;
        if (WriteDataTcp(ssl, (unsigned char *)&MsgCmd, msglen)== msglen)
        {
            return true;
        }

    }
    return false;
}

bool SendCalibToSever(unsigned char Code)
{
    if (IsClientConnected())
    {
        TMesssageCalibCommands MsgCmd;
        int msglen = sizeof(TMesssageHeader) + sizeof(unsigned char);
        //printf("Message len %d\n", msglen);
        MsgCmd.Hdr.Len = htonl(sizeof(unsigned char));
        MsgCmd.Hdr.Type = htonl(MT_CALIB_COMMANDS);
        MsgCmd.Commands = Code;
        if (WriteDataTcp(ssl, (unsigned char*)&MsgCmd, msglen) == msglen)
        {
            return true;
        }

    }
    return false;
}

bool SendTargetOrderToSever(char* TargetOrder)
{
    if (IsClientConnected())
    {
        TMesssageTargetOrder MsgTargetOrder;
        int msglen = sizeof(TMesssageHeader) + (int)strlen((const char*)TargetOrder)+1;
        MsgTargetOrder.Hdr.Len = htonl((int)strlen((const char*)TargetOrder)+1);
        MsgTargetOrder.Hdr.Type = htonl(MT_TARGET_SEQUENCE);
        strcpy_s((char*)MsgTargetOrder.FiringOrder,sizeof(MsgTargetOrder.FiringOrder),TargetOrder);
        if (WriteDataTcp(ssl, (unsigned char*)&MsgTargetOrder, msglen) == msglen)
        {
            return true;
        }

    }
    return false;
}

bool SendPreArmCodeToSever(char* Code)
{
    if (IsClientConnected())
    {
        TMesssagePreArm MsgPreArm;
        int msglen = sizeof(TMesssageHeader) + (int)strlen(Code) + 1;
        MsgPreArm.Hdr.Len = htonl((int)strlen(Code) + 1);
        MsgPreArm.Hdr.Type = htonl(MT_PREARM);
        strcpy_s((char*)MsgPreArm.Code, sizeof(MsgPreArm.Code), Code);
        if (WriteDataTcp(ssl, (unsigned char*)&MsgPreArm, msglen) == msglen)
        {
            return true;
        }

    }
    return false;
}

bool SendStateChangeRequestToSever(SystemState_t State)
{
    if (IsClientConnected())
    {
        TMesssageChangeStateRequest MsgChangeStateRequest;
        int msglen = sizeof(TMesssageChangeStateRequest);
        MsgChangeStateRequest.Hdr.Len = htonl(sizeof(MsgChangeStateRequest.State));
        MsgChangeStateRequest.Hdr.Type = htonl(MT_STATE_CHANGE_REQ);
        MsgChangeStateRequest.State = (SystemState_t)htonl(State);
        if (WriteDataTcp(ssl, (unsigned char*)&MsgChangeStateRequest, msglen) == msglen)
        {
            return true;
        }

    }
    return false;
}

/*
bool SendLoginToSever(unsigned int idLength, unsigned int pwLength, char* idAndPwd)
{
    if (IsClientConnected())
    {
        std::cout << "SendLoginToServer" << std::endl;

        TMesssageLogin MsgLogin;
        int msglen = sizeof(TMesssageHeader) + (int)strlen(idAndPwd) + 4 + 4 + 1;
        //printf("Message len %d\n", msglen);
        MsgLogin.Hdr.Len = htonl((int)strlen(idAndPwd) + 1 + 1 + 1);
        MsgLogin.Hdr.Type = htonl(MT_LOGIN);
        MsgLogin.LengthOfId = htonl(idLength);
        MsgLogin.LengthOfPw = htonl(pwLength);

        std::cout << sizeof(MsgLogin.IdAndPw) << std::endl;

        strcpy_s((char*)MsgLogin.IdAndPw, sizeof(MsgLogin.IdAndPw), idAndPwd);
        std::cout << MsgLogin.IdAndPw << std::endl;

        if (WriteDataTcp(ssl, (unsigned char*)&MsgLogin, msglen) == msglen)
        {
            return true;
        }

    }
    return false;
}
*/

bool SendLoginEnrollToSever(char* userId, char* userPw)
{
    if (IsClientConnected())
    {
        std::cout << "SendLoginEnrollToSever" << std::endl;

        TMesssageLoginEnrollRequest MsgLoginEnroll;
        int msglen = sizeof(TMesssageHeader) + (int)strlen(userId) + (int)strlen(userPw) + 1;

        MsgLoginEnroll.Hdr.Len = htonl((int)strlen(userId) + (int)strlen(userPw) + 1);
        MsgLoginEnroll.Hdr.Type = htonl(MT_LOGIN_ENROLL_REQ);
        strcpy_s(MsgLoginEnroll.Hdr.HMAC, sizeof(MsgLoginEnroll.Hdr.HMAC), reveivedHmac);

        strcpy_s(MsgLoginEnroll.Name, sizeof(MsgLoginEnroll.Name), userId);
        strcpy_s(MsgLoginEnroll.Password, sizeof(MsgLoginEnroll.Password), userPw);


        if (WriteDataTcp(ssl, (unsigned char*)&MsgLoginEnroll, msglen) == msglen)
        {
            return true;
        }

    }
    return false;
}

bool SendLoginVerifyToSever(char *userId, char *userPw)
{
    if (IsClientConnected())
    {
        std::cout << "SendLoginVerifyToSever" << std::endl;

        TMesssageLoginVerifyRequest MsgLoginVerify;
        int msglen = sizeof(TMesssageHeader) + (int)strlen(userId) + (int)strlen(userPw) + 1;

        MsgLoginVerify.Hdr.Len = htonl((int)strlen(userId) + (int)strlen(userPw) + 1);
        MsgLoginVerify.Hdr.Type = htonl(MT_LOGIN_VERITY_REQ);
        strcpy_s(MsgLoginVerify.Hdr.HMAC, sizeof(MsgLoginVerify.Hdr.HMAC), reveivedHmac);

        strcpy_s(MsgLoginVerify.Name, sizeof(MsgLoginVerify.Name), userId);
        strcpy_s(MsgLoginVerify.Password, sizeof(MsgLoginVerify.Password), userPw);
 

        if (WriteDataTcp(ssl, (unsigned char*)&MsgLoginVerify, msglen) == msglen)
        {
            return true;
        }

    }
    return false;
}

bool SendLoginChangePwToSever(char* userId, char* userPw)
{
    if (IsClientConnected())
    {
        std::cout << "SendLoginChangePwToSever" << std::endl;

        TMesssageLoginChangePwRequest MsgLoginChangePw;
        int msglen = sizeof(TMesssageHeader) + (int)strlen(userId) + (int)strlen(userPw) + (int)strlen(token) + 1;

        MsgLoginChangePw.Hdr.Len = htonl((int)strlen(userId) + (int)strlen(userPw) + (int)strlen(token) + 1);
        MsgLoginChangePw.Hdr.Type = htonl(MT_LOGIN_CHANGEPW_REQ);
        strcpy_s(MsgLoginChangePw.Hdr.HMAC, sizeof(MsgLoginChangePw.Hdr.HMAC), reveivedHmac);

        strcpy_s(MsgLoginChangePw.Name, sizeof(MsgLoginChangePw.Name), userId);
        strcpy_s(MsgLoginChangePw.Password, sizeof(MsgLoginChangePw.Password), userPw);
        strcpy_s(MsgLoginChangePw.Token, sizeof(MsgLoginChangePw.Token), token);


        if (WriteDataTcp(ssl, (unsigned char*)&MsgLoginChangePw, msglen) == msglen)
        {
            return true;
        }

    }
    return false;
}


bool ConnectToSever(const char* remotehostname, unsigned short remoteport)
{
    int iResult;
    struct addrinfo   hints;
    struct addrinfo* result = NULL;
    char remoteportno[128];
	SSL_CTX* ctx = InitCTX();
    
    //TODO: delete this code
    remoteport = 12345;

    //TODO: delete this code if cannot get password from certification manager
    /*
    std::wstring targetName = L"ClientKeyCredential";
    std::wstring username, password;

    if (GetStoredCredential(targetName.c_str(), username, password))
    {
        std::wcout << "Username: " << username << std::endl;
        std::wcout << "Password: " << password << std::endl;
        // 여기에서 password를 사용하여 필요한 작업을 수행합니다.
    }
    else
    {
        std::cerr << "Failed to retrieve credential." << std::endl;
    }
    */
    

    
    // Load server key and CRT
    if (SSL_CTX_load_verify_locations(ctx, CA_CERT_FILE, nullptr) <= 0) {
        std::cerr << "Error setting CA certificate" << std::endl;
        return false;
    }

    if (SSL_CTX_use_certificate_file(ctx, CLIENT_CERT_FILE, SSL_FILETYPE_PEM) <= 0) {
        std::cerr << "Error loading server certificate." << std::endl;
        return false;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, CLIENT_KEY_FILE, SSL_FILETYPE_PEM) <= 0) {
        std::cerr << "Error loading server private key." << std::endl;
        return false;
    }

    sprintf_s(remoteportno,sizeof(remoteportno), "%d", remoteport);

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    iResult = getaddrinfo(remotehostname, remoteportno, &hints, &result);
    if (iResult != 0)
    {
        std::cout << "getaddrinfo: Failed" << std::endl;
        return false;
    }
    if (result == NULL)
    {
        std::cout << "getaddrinfo: Failed" << std::endl;
        return false;
    }

    if ((Client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET)

    {
        freeaddrinfo(result);
        std::cout << "video client socket() failed with error "<< WSAGetLastError() << std::endl;
        return false;
    }

    //----------------------
    // Connect to server.
    iResult = connect(Client, result->ai_addr, (int)result->ai_addrlen);
    freeaddrinfo(result);
    if (iResult == SOCKET_ERROR) {
        std::cout << "connect function failed with error : "<< WSAGetLastError() << std::endl;
        iResult = closesocket(Client);
        Client = INVALID_SOCKET;
        if (iResult == SOCKET_ERROR)
            std::cout << "closesocket function failed with error :"<< WSAGetLastError() << std::endl;
        return false;
    }
    int yes = 1;
    iResult = setsockopt(Client,
        IPPROTO_TCP,
        TCP_NODELAY,
        (char*)&yes,
        sizeof(int));    // 1 - on, 0 - off
    if (iResult < 0)
    {
        printf("TCP NODELAY Failed\n");
    }
    else  printf("TCP NODELAY SET\n");
    
    // SSL socket create
    ssl = SSL_new(ctx);
    if (ssl == NULL) {
        std::cerr << "Error creating SSL structure." << std::endl;
        closesocket(Client);
        return false;
    }
    SSL_set_fd(ssl, Client);

    // SSL Handshake
    if (SSL_connect(ssl) != 1) {
        std::cerr << "Error establishing SSL connection." << std::endl;
        SSL_free(ssl);
        closesocket(Client);
        return false;
    }

    return true;

}

bool StartClient(void)
{
 hThreadClient = CreateThread(NULL, 0, ThreadClient, NULL, 0, &ThreadClientID);
 return true;
}

bool StopClient(void)
{
    ClientSetExitEvent();
    if (hThreadClient != INVALID_HANDLE_VALUE)
    {
        WaitForSingleObject(hThreadClient, INFINITE);
        CloseHandle(hThreadClient);
        hThreadClient = INVALID_HANDLE_VALUE;
    }
;
    return true;
}
bool IsClientConnected(void)
{
    if (hThreadClient == INVALID_HANDLE_VALUE)
    {
        return false;
    }
    else return true;
}
void ProcessMessage(char* MsgBuffer)
{
    TMesssageHeader *MsgHdr;
    MsgHdr = (TMesssageHeader*)MsgBuffer;
    MsgHdr->Len = ntohl(MsgHdr->Len);
    MsgHdr->Type = ntohl(MsgHdr->Type);

    switch (MsgHdr->Type)
    {
    case MT_IMAGE:
      {
        cv::imdecode(cv::Mat(MsgHdr->Len, 1, CV_8UC1, MsgBuffer + sizeof(TMesssageHeader)), cv::IMREAD_COLOR, &ImageIn);
        ProcessImage(ImageIn);
      }
    break;
    case MT_TEXT:
    {
        CStringW cstring(MsgBuffer + sizeof(TMesssageHeader));
        PRINT(_T("%s\r\n"), cstring);
    }
    break;
    case MT_STATE:
    {
        TMesssageSystemState* MsgState;
        MsgState = (TMesssageSystemState*)MsgBuffer;
        MsgState->State = (SystemState_t)ntohl(MsgState->State);
        PostMessage(hWndMain, WM_SYSTEM_STATE, MsgState->State, 0);

    }
    break;
    case MT_LOGIN_ENROLL_RES:
    {
        TMesssageLoginEnrollResponse* MsgLoginEnrolRes;
        MsgLoginEnrolRes = (TMesssageLoginEnrollResponse*)MsgBuffer;
        MsgLoginEnrolRes->LoginState = (LoginState_t)ntohl(MsgLoginEnrolRes->LoginState);
        PostMessage(hWndMain, WM_LOGIN_STATE, MsgLoginEnrolRes->LoginState, 0);

    }
    break;
    case MT_LOGIN_VERITY_RES:
    {
        TMesssageLoginVerifyResponse* MsgLoginVerifyRes;
        MsgLoginVerifyRes = (TMesssageLoginVerifyResponse*)MsgBuffer;
        MsgLoginVerifyRes->LoginState = (LoginState_t)ntohl(MsgLoginVerifyRes->LoginState);
        PostMessage(hWndMain, WM_LOGIN_STATE, MsgLoginVerifyRes->LoginState, 0);
        if (LoginState_t::SUCCESS != MsgLoginVerifyRes->LoginState) {
            PostMessage(hWndMain, WM_LOGIN_FAIL_COUNT, MsgLoginVerifyRes->FailCount, 0);
        }
        else {
            PostMessage(hWndMain, WM_LOGIN_PRIVILEGE, MsgLoginVerifyRes->Privilige, 0);
        }
    }
    break;
    case MT_LOGIN_CHANGEPW_RES:
    {
        TMesssageLoginChangePwResponse* MsgLoginChangePwRes;
        MsgLoginChangePwRes = (TMesssageLoginChangePwResponse*)MsgBuffer;
        MsgLoginChangePwRes->LoginState = (LoginState_t)ntohl(MsgLoginChangePwRes->LoginState);
        PostMessage(hWndMain, WM_LOGIN_STATE, MsgLoginChangePwRes->LoginState, 0);

    }
    break;
    default:
    {
        printf("unknown message\n");
    }
    break;
    }
}

bool GetStoredCredential(const wchar_t* targetName, std::wstring& username, std::wstring& password)
{
    PCREDENTIAL cred;
    if (!CredReadW(targetName, CRED_TYPE_GENERIC, 0, &cred))
    {
        std::cerr << "CredRead failed: " << GetLastError() << std::endl;
        return false;
    }

    if (cred->Type == CRED_TYPE_GENERIC)
    {
        username = std::wstring(cred->UserName);
        DATA_BLOB dataIn;
        DATA_BLOB dataOut;
        dataIn.cbData = cred->CredentialBlobSize;
        dataIn.pbData = cred->CredentialBlob;

        /*
        // 암호는 CredentialBlob에 저장되어 있으며, CredentialBlobSize에 크기가 저장되어 있음
        if (cred->CredentialBlobSize > 0) {
            std::vector<char> password(cred->CredentialBlob, cred->CredentialBlob + cred->CredentialBlobSize);
            password.push_back('\0'); // null-terminator 추가

            std::wcout << L"Credential Password: " << (char*)password.data() << std::endl;
        }
        */

        if (CryptUnprotectData(&dataIn, nullptr, nullptr, nullptr, nullptr, 0, &dataOut))
        {
            password = std::wstring(reinterpret_cast<wchar_t*>(dataOut.pbData), dataOut.cbData / sizeof(wchar_t));
            LocalFree(dataOut.pbData);
            CredFree(cred);
            return true;
        }
        else
        {
            std::cerr << "CryptUnprotectData failed: " << GetLastError() << std::endl;
        }
    }

    CredFree(cred);
    return false;
}


static DWORD WINAPI ThreadClient(LPVOID ivalue)
{    
    HANDLE ghEvents[2];
    int NumEvents;
    int iResult;
    DWORD dwEvent;
    InputMode Mode = MsgHeader;
    unsigned int InputBytesNeeded=sizeof(TMesssageHeader);
    TMesssageHeader MsgHdr;
    char* InputBuffer = NULL;
    char* InputBufferWithOffset = NULL;
    unsigned int CurrentInputBufferSize = 1024 * 10;
  
    InputBuffer = (char*)std::realloc(InputBuffer, CurrentInputBufferSize);
    InputBufferWithOffset = InputBuffer;

    if (InputBuffer == NULL)
    {
      std::cout << "InputBuffer Realloc failed" << std::endl;
      ExitProcess(0);
      return 1;
    }
 
    hClientEvent = WSACreateEvent();
    hEndClientEvent = CreateEvent(NULL, FALSE, FALSE, NULL);

    if (WSAEventSelect(Client, hClientEvent, FD_READ | FD_CLOSE) == SOCKET_ERROR)

    {
        std::cout << "WSAEventSelect() failed with error "<< WSAGetLastError() << std::endl;
        iResult = closesocket(Client);
        Client = INVALID_SOCKET;
        if (iResult == SOCKET_ERROR)
            std::cout << "closesocket function failed with error : " << WSAGetLastError() << std::endl;
        return 4;
    }
    ghEvents[0] = hEndClientEvent;
    ghEvents[1] = hClientEvent;
    NumEvents = 2;

    while (1) {
     dwEvent = WaitForMultipleObjects(
         NumEvents,        // number of objects in array
         ghEvents,       // array of objects
         FALSE,           // wait for any object
         INFINITE);  // INFINITE) wait

     if (dwEvent == WAIT_OBJECT_0) break;
     else if (dwEvent == WAIT_OBJECT_0 + 1)
     {
         WSANETWORKEVENTS NetworkEvents;
         if (SOCKET_ERROR == WSAEnumNetworkEvents(Client, hClientEvent, &NetworkEvents))
         {
             std::cout << "WSAEnumNetworkEvent: "<< WSAGetLastError() << "dwEvent "<< dwEvent << " lNetworkEvent "<<std::hex<< NetworkEvents.lNetworkEvents<< std::endl;
             NetworkEvents.lNetworkEvents = 0;
         }
         else
         {
             if (NetworkEvents.lNetworkEvents & FD_READ)
             {
                 if (NetworkEvents.iErrorCode[FD_READ_BIT] != 0)
                 {
                     std::cout << "FD_READ failed with error " << NetworkEvents.iErrorCode[FD_READ_BIT]<< std::endl;
                 }
                 else
                 {
                   int iResult;
                   iResult = ReadDataTcpNoBlock(ssl, (unsigned char*)InputBufferWithOffset, InputBytesNeeded);
                   if (iResult != SOCKET_ERROR)
                   {
                       if (iResult == 0)
                       {
                           Mode = MsgHeader;
                           InputBytesNeeded = sizeof(TMesssageHeader);
                           InputBufferWithOffset = InputBuffer;
                           PostMessage(hWndMain, WM_CLIENT_LOST, 0, 0);
                           std::cout << "Connection closed on Recv" << std::endl;
                           break;
                       }
                       else
                       {
                           //TODO: delete this code
                           /*
                           int i = 0;
                           std::cout << "RECV: ";
                           for (i = 0; i < 8; i++) {
                               fprintf(stdout, "%02X", InputBufferWithOffset[i]);
                           }
                           std::cout << std::endl;
                           */

                           InputBytesNeeded -= iResult;
                           InputBufferWithOffset += iResult;
                           if (InputBytesNeeded == 0)
                           {
                               if (Mode == MsgHeader)
                               {
                                  
                                   InputBufferWithOffset = InputBuffer+sizeof(TMesssageHeader);
                                   memcpy(&MsgHdr, InputBuffer, sizeof(TMesssageHeader));
                                   MsgHdr.Len = ntohl(MsgHdr.Len);
                                   MsgHdr.Type = ntohl(MsgHdr.Type);
                                   InputBytesNeeded = MsgHdr.Len;
                                   Mode = Msg;
                                   if ((InputBytesNeeded+sizeof(TMesssageHeader)) > CurrentInputBufferSize)
                                   {   
                                       CurrentInputBufferSize = InputBytesNeeded+sizeof(TMesssageHeader) + (10 * 1024);
                                       InputBuffer = (char*)std::realloc(InputBuffer, CurrentInputBufferSize);
                                       if (InputBuffer == NULL)
                                       {
                                           std::cout << "std::realloc failed " << std::endl;
                                           ExitProcess(0);
                                       }
                                       InputBufferWithOffset = InputBuffer + sizeof(TMesssageHeader);
                                   }
                                   
                               }
                               else if (Mode == Msg)
                               {
                                   ProcessMessage(InputBuffer);
                                   // Setup for next message
                                   Mode = MsgHeader;
                                   InputBytesNeeded = sizeof(TMesssageHeader);
                                   InputBufferWithOffset = InputBuffer;
                               }
                           }

                       }
                   }
                  else std::cout << "ReadDataTcpNoBlock buff failed " << WSAGetLastError() << std::endl;

                 }

             }
             if (NetworkEvents.lNetworkEvents & FD_WRITE)
             {
                 if (NetworkEvents.iErrorCode[FD_WRITE_BIT] != 0)
                 {
                     std::cout << "FD_WRITE failed with error "<< NetworkEvents.iErrorCode[FD_WRITE_BIT] << std::endl;
                 }
                 else
                 {
                     std::cout << "FD_WRITE" << std::endl;
                 }
             }
         
             if (NetworkEvents.lNetworkEvents & FD_CLOSE)
             {
                 if (NetworkEvents.iErrorCode[FD_CLOSE_BIT] != 0)

                 {
                     std::cout << "FD_CLOSE failed with error "<< NetworkEvents.iErrorCode[FD_CLOSE_BIT] << std::endl;
                 }
                 else
                 {
                     std::cout << "FD_CLOSE" << std::endl;
                     PostMessage(hWndMain, WM_CLIENT_LOST, 0, 0);
                     break;
                  }

             }
          }

       }
     }
    if (InputBuffer)
    {
        std::free(InputBuffer);
        InputBuffer = nullptr;
    }
    ClientCleanup();
    std::cout << "Client Exiting" << std::endl;
    return 0;
}
//-----------------------------------------------------------------
// END of File
//-----------------------------------------------------------------