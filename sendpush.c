
//#define SERVER  "gateway.sandbox.push.apple.com"
#define SERVER  "gateway.push.apple.com"
#define PORT 2195


#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

// Establish a regular tcp connection
int tcpConnect(){
  struct hostent *host = gethostbyname(SERVER);
  int handle = socket(AF_INET, SOCK_STREAM, 0);
  if(handle == -1){
      perror("Socket");
      handle = 0;
  } else {
      struct sockaddr_in server;
      server.sin_family = AF_INET;
      server.sin_port = htons(PORT);
      server.sin_addr = *((struct in_addr *) host->h_addr);
      bzero(&(server.sin_zero), 8);

      int error = connect(handle, (struct sockaddr *) &server, sizeof(struct sockaddr));
      if(error == -1) {
          perror("Connect");
          handle = 0;
      }
  }
  return handle;
}


// Establish a connection using an SSL layer
int sslSend(unsigned char* packet, int len){

    int socket = tcpConnect();
    if(socket<=0){
        perror("Connect failed");
        return -1;
    }

    // Register the error strings for libcrypto & libssl
    SSL_load_error_strings();
    // Register the available ciphers and digests
    SSL_library_init();

    // New context saying we are a client, and using SSL 2 or 3
    SSL_CTX* sslContext = SSL_CTX_new(SSLv23_client_method());
    if(!sslContext){
        ERR_print_errors_fp(stderr);
        return -1;
    }

    if(!SSL_CTX_use_PrivateKey_file(sslContext, "/etc/xapsd/key.pem", SSL_FILETYPE_PEM) ||
        !SSL_CTX_use_certificate_file(sslContext, "/etc/xapsd/cert.pem", SSL_FILETYPE_PEM) ){
        fprintf(stderr, "SSL_CTX_use_certificate_file ERROR\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    // Create an SSL struct for the connection
    SSL* sslHandle = SSL_new(sslContext);
    if(!sslHandle){
        ERR_print_errors_fp(stderr);
        return -1;
    }

    // Connect the SSL struct to our connection
    if(!SSL_set_fd(sslHandle, socket)) ERR_print_errors_fp(stderr);

    // Initiate SSL handshake
    if(SSL_connect(sslHandle)!=1) ERR_print_errors_fp(stderr);

    // Send the payload!
    SSL_write(sslHandle, packet, len);

    // Disconnect & free connection struct
    SSL_shutdown(sslHandle);
    SSL_free(sslHandle);
    SSL_CTX_free(sslContext);
    close(socket);
    return 0;
}



// Construct and send apple push trigger packet from account id/token:
int sendpush(char* aps_account_id,char* aps_device_token){
    unsigned char token[32];
    char json[1000];
    sprintf(json,"{\"aps\":{\"account-id\":\"%s\"}}",aps_account_id);

//    printf("parsing token! %s\n",aps_device_token);
    int i;
    for(i=0;i<64;i++){
       int c=aps_device_token[i];
       if(c>'9') c=10+(c-'A'); else c-='0';
       c&=15;
//	printf("%2d: %c = %d\n",i,aps_device_token[i],c);
       if(i&1) token[i>>1]|=c; else token[i>>1]=c<<4;
    }

int jlen=strlen(json);
unsigned char packet[1000];
unsigned char* p=packet;
// hdr (1+4 byte)
//      hdr   item1  item2    item3 item4 item5
int len=1+4 + 3+32 + 3+jlen + 3+4 + 3+4 + 3+1;
*(p++)=2;*(p++)=0;*(p++)=0;*(p++)=(len-5)>>8;*(p++)=(len-5)&255;
// item 1: token (32 byte)
*(p++)=1;*(p++)=0;*(p++)=32;
memcpy(p,token,32); p+=32;
// item 2: json (ascii, jlen bytes)
*(p++)=2;*(p++)=jlen>>8;*(p++)=jlen&255;
memcpy(p,json,jlen); p+=jlen;
// item 3: id (4 byte)
*(p++)=3;*(p++)=0;*(p++)=4;
unsigned id=time(NULL);
*(p++)=id>>24;*(p++)=(id>>16)&255;*(p++)=(id>>8)&255;*(p++)=id&255;
// item 4: time (4 byte)
*(p++)=4;*(p++)=0;*(p++)=4;
id=time(NULL)+60*30; // now+30 minute
*(p++)=id>>24;*(p++)=(id>>16)&255;*(p++)=(id>>8)&255;*(p++)=id&255;
// item 5: priority (1 byte)
*(p++)=5;*(p++)=0;*(p++)=1;
*(p++)=10;

  sslSend(packet, len);

  return 0;
}



#define DB_MAX 1024
static char* db[DB_MAX];

// read unique lines from text file at 'path' to db[], optional filtering by ^username:
int load_db(const char* path,const char* username){
    int unlen=username ? strlen(username) : 0;
    int n=0;
    int fd=open(path,O_RDONLY);
    if(fd<0) return 0;
    off_t fsize=lseek(fd,0,SEEK_END);
//    printf("fsize=%d\n",(int)fsize);
    char* raw=malloc(fsize+1);
    lseek(fd,0,SEEK_SET);
    fsize=read(fd,raw,fsize);
//    printf("fsize=%d\n",(int)fsize);
    close(fd);
    if(fsize<=0) return 0;
    int i;
    for(char* q=raw;q<raw+fsize;){
        char* p=q; while(q<raw+fsize && *q!=10) q++; *q++=0;
        if(!username || (!memcmp(p,username,unlen) && p[unlen]==':')){
            for(i=0;i<n && strcmp(db[i],p);i++);
            if(i>=n && n<DB_MAX) db[n++]=strdup(p);
    }   }
    free(raw);
    return n;
}


int main(int argc,char* argv[]){
    int n=load_db("/var/lib/xapsd/register.log",argc>1?argv[1]:NULL);
    for(int i=0;i<n;i++){
//        printf("%d: %s\n",i,db[i]);
        char* p=strchr(db[i],':')+1;
        char* q=strchr(p,':'); *q++=0;
        char* r=strchr(q,':'); *r=0;
//        printf("p1='%s' p2='%s'\n",p,q);
        if(argc>1) sendpush(p,q);
    }
}

