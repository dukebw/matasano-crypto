#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "crypt_helper.h"

#define VERSION 23
#define BUFSIZE 8096
#define ERROR      42
#define LOG        44
#define FORBIDDEN 403
#define NOTFOUND  404

struct {
	char *ext;
	char *filetype;
} extensions [] = {
	{"gif", "image/gif" },  
	{"jpg", "image/jpg" }, 
	{"jpeg","image/jpeg"},
	{"png", "image/png" },  
	{"ico", "image/ico" },  
	{"zip", "image/zip" },  
	{"gz",  "image/gz"  },  
	{"tar", "image/tar" },  
	{"htm", "text/html" },  
	{"html","text/html" },  
	{0,0} };

void logger(int type, char *s1, char *s2, int socket_fd)
{
	int fd ;
	char logbuffer[BUFSIZE*2];

	switch (type) {
	case ERROR: (void)sprintf(logbuffer,"ERROR: %s:%s Errno=%d exiting pid=%d",s1, s2, errno,getpid()); 
		break;
	case FORBIDDEN: 
		(void)write(socket_fd, "HTTP/1.1 403 Forbidden\nContent-Length: 185\nConnection: close\nContent-Type: text/html\n\n<html><head>\n<title>403 Forbidden</title>\n</head><body>\n<h1>Forbidden</h1>\nThe requested URL, file type or operation is not allowed on this simple static file webserver.\n</body></html>\n",271);
		(void)sprintf(logbuffer,"FORBIDDEN: %s:%s",s1, s2); 
		break;
	case NOTFOUND: 
		(void)write(socket_fd, "HTTP/1.1 404 Not Found\nContent-Length: 136\nConnection: close\nContent-Type: text/html\n\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\nThe requested URL was not found on this server.\n</body></html>\n",224);
		(void)sprintf(logbuffer,"NOT FOUND: %s:%s",s1, s2); 
		break;
	case LOG: (void)sprintf(logbuffer," INFO: %s:%s:%d",s1, s2,socket_fd); break;
	}	
	/* No checks here, nothing can be done with a failure anyway */
	if((fd = open("nweb.log", O_CREAT| O_WRONLY | O_APPEND,0644)) >= 0) {
		(void)write(fd,logbuffer,strlen(logbuffer)); 
		(void)write(fd,"\n",1);      
		(void)close(fd);
	}
	if(type == ERROR || type == NOTFOUND || type == FORBIDDEN) exit(3);
}

const u8 TEST_HMAC_KEY[] =
{
	0x82, 0xF3, 0xB6, 0x9A, 0x1B, 0xFF, 0x4D, 0xE1, 0x5C, 0x33, 
	0x82, 0xF3, 0xB6, 0x9A, 0x1B, 0xFF, 0x4D, 0xE1, 0x5C, 0x33, 
};

const u8 TEST_FILE_HMAC_HEX[] = "254b6040afd5a30d669c06c8a7e4e3e2e771fa51";
#define HMAC_TEST_KEY_HEX_DIGIT_COUNT (2*sizeof(TEST_HMAC_KEY))

/* this is a child web server process, so we can exit on errors */
void web(int fd, int hit)
{
	int j, file_fd, buflen;
	long i, ret, len;
	char * fstr;
	static char buffer[BUFSIZE+1]; /* static so zero filled */

	ret =read(fd,buffer,BUFSIZE); 	/* read Web request in one go */
	if(ret == 0 || ret == -1) {	/* read failure stop now */
		logger(FORBIDDEN,"failed to read browser request","",fd);
	}
	if(ret > 0 && ret < BUFSIZE)	/* return code is valid chars */
		buffer[ret]=0;		/* terminate the buffer */
	else buffer[0]=0;
	for(i=0;i<ret;i++)	/* remove CF and LF characters */
		if(buffer[i] == '\r' || buffer[i] == '\n')
			buffer[i]='*';
	logger(LOG,"request",buffer,hit);

	if( (strncmp(buffer,"GET ",4) == 0) || (strncmp(buffer,"get ",4) == 0))
	{
		for(i=4;i<BUFSIZE;i++) { /* null terminate after the second space to ignore extra stuff */
			if(buffer[i] == ' ') { /* string is "GET URL " +lots of other stuff */
				buffer[i] = 0;
				break;
			}
		}
		for(j=0;j<i-1;j++) 	/* check for illegal parent directory use .. */
			if(buffer[j] == '.' && buffer[j+1] == '.') {
				logger(FORBIDDEN,"Parent directory (..) path names not supported",buffer,fd);
			}
		if( !strncmp(&buffer[0],"GET /\0",6) || !strncmp(&buffer[0],"get /\0",6) ) /* convert no filename to index file */
			(void)strcpy(buffer,"GET /index.html");

		/* work out the file type and check we support it */
		buflen=strlen(buffer);
		fstr = (char *)0;
		for(i=0;extensions[i].ext != 0;i++) {
			len = strlen(extensions[i].ext);
			if( !strncmp(&buffer[buflen-len], extensions[i].ext, len)) {
				fstr =extensions[i].filetype;
				break;
			}
		}
		if(fstr == 0) logger(FORBIDDEN,"file extension type not supported",buffer,fd);

		if(( file_fd = open(&buffer[5],O_RDONLY)) == -1) {  /* open the file for reading */
			logger(NOTFOUND, "failed to open file",&buffer[5],fd);
		}
		logger(LOG,"SEND",&buffer[5],hit);
		len = (long)lseek(file_fd, (off_t)0, SEEK_END); /* lseek to the file end to find the length */
		(void)lseek(file_fd, (off_t)0, SEEK_SET); /* lseek back to the file start ready for reading */
		(void)sprintf(buffer,"HTTP/1.1 200 OK\nServer: nweb/%d.0\nContent-Length: %ld\nConnection: close\nContent-Type: %s\n\n", VERSION, len, fstr); /* Header + a blank line */
		logger(LOG,"Header",buffer,hit);
		(void)write(fd,buffer,strlen(buffer));

		/* send file in 8KB block - last block may be smaller */
		while (	(ret = read(file_fd, buffer, BUFSIZE)) > 0 ) {
			(void)write(fd,buffer,ret);
		}
	}
	else if (strncmp(buffer, TEST_HMAC_PREFIX, STR_LEN(TEST_HMAC_PREFIX)) == 0)
	{
		if (strncmp(buffer + STR_LEN(TEST_HMAC_PREFIX), FILE_PREFIX, STR_LEN(FILE_PREFIX)))
		{
			logger(ERROR, "No valid file= in request string", buffer, fd);
		}

		u32 PrefixToFilename = (STR_LEN(TEST_HMAC_PREFIX) + STR_LEN(FILE_PREFIX));
		u32 RemainingReceivedLength = (ret - PrefixToFilename);
		u32 FilenameLength;
		for (FilenameLength = 0;
			 (FilenameLength < RemainingReceivedLength) &&
			 buffer[PrefixToFilename + FilenameLength] != '&';
			 ++FilenameLength)
		{
		}

		if ((RemainingReceivedLength - FilenameLength - 1 - STR_LEN(SIG_PREFIX)) < 2*sizeof(TEST_HMAC_KEY))
		{
			logger(ERROR, "No signature of correct length in request string", buffer, fd);
		}

		buffer[PrefixToFilename + FilenameLength] = 0;

		char DebugBuffer[256];
		sprintf(DebugBuffer, "%d", FilenameLength);
		logger(LOG, "Length of filename received", DebugBuffer, fd);

#if 1
		file_fd = open(buffer + PrefixToFilename, O_RDONLY);
		if (file_fd == -1)
		{
			memcpy(DebugBuffer, buffer + PrefixToFilename, FilenameLength);
			DebugBuffer[FilenameLength] = 0;
			logger(NOTFOUND, "failed to open file", DebugBuffer, fd);
		}

		u8 FileBuffer[8196];
		u32 FileSize = read(file_fd, FileBuffer, sizeof(FileBuffer));
		if (FileSize == sizeof(FileBuffer))
		{
			sprintf(DebugBuffer, "%d", FileSize);
			logger(ERROR, "File size too large to HMAC", DebugBuffer, fd);
		}

		sprintf(DebugBuffer, "%s == %d", buffer + PrefixToFilename, FileSize);
		logger(LOG, "Length of file", DebugBuffer, fd);

		u8 FileHmac[SHA_1_HASH_LENGTH_BYTES];
		HmacSha1(FileHmac, FileBuffer, FileSize, (u8 *)TEST_HMAC_KEY, sizeof(TEST_HMAC_KEY));

        u8 FileHmacHex[2*sizeof(TEST_HMAC_KEY) + 1];
		StringToHex((u8 *)FileHmacHex, FileHmac, sizeof(TEST_HMAC_KEY));
		FileHmacHex[HMAC_TEST_KEY_HEX_DIGIT_COUNT] = 0;
		logger(LOG, "FileHmac", (char *)FileHmacHex, fd);
#endif

		char *ReceivedSignaturePrefix = buffer + PrefixToFilename + FilenameLength + 1;
		if (strncmp(ReceivedSignaturePrefix, SIG_PREFIX, STR_LEN(SIG_PREFIX)))
		{
			logger(ERROR, "No valid signature= in request string", buffer, fd);
		}


		timespec Request;
		Request.tv_sec = 0;
		Request.tv_nsec = 2*ONE_MILLION;

		u32 ReceivedSigHexIndex;
		for (ReceivedSigHexIndex = 0;
			 ReceivedSigHexIndex < HMAC_TEST_KEY_HEX_DIGIT_COUNT;
			 ++ReceivedSigHexIndex)
		{
#if 1
			timespec Remaining;
			nanosleep(&Request, &Remaining);
#else
			timespec StartArtificialDelay;
			clock_gettime(CLOCK_MONOTONIC, &StartArtificialDelay);

			timespec EndArtificialDelay;
			i64 ElapsedTime;
			do
			{
				clock_gettime(CLOCK_MONOTONIC, &EndArtificialDelay);

				ElapsedTime = (ONE_BILLION*(EndArtificialDelay.tv_sec - StartArtificialDelay.tv_sec) +
							   (EndArtificialDelay.tv_nsec - StartArtificialDelay.tv_nsec));
			} while (ElapsedTime < Request.tv_nsec);
#endif

#if 1
			if (ReceivedSignaturePrefix[ReceivedSigHexIndex + STR_LEN(SIG_PREFIX)] !=
                FileHmacHex[ReceivedSigHexIndex])
#else
			if (ReceivedSignaturePrefix[ReceivedSigHexIndex + STR_LEN(SIG_PREFIX)] !=
                TEST_FILE_HMAC_HEX[ReceivedSigHexIndex])
#endif
			{
				break;
			}
		}
		
		if (ReceivedSigHexIndex == HMAC_TEST_KEY_HEX_DIGIT_COUNT)
		{
			sprintf(DebugBuffer, "%d", HMAC_RET_CODE_VALID);
		}
		else
		{
			sprintf(DebugBuffer, "%d", HMAC_RET_CODE_INVALID);
		}

		write(fd, DebugBuffer, HMAC_RET_CODE_LENGTH_BYTES);
	}
	else if (strncmp(buffer, TEST_SRP_PREFIX, STR_LEN(TEST_SRP_PREFIX)) == 0)
    {
        if ((strncmp(buffer + STR_LEN(TEST_SRP_PREFIX), USER_PREFIX, STR_LEN(USER_PREFIX)) == 0) &&
            (strncmp(buffer + STR_LEN(TEST_SRP_PREFIX) + STR_LEN(USER_PREFIX),
                     SRP_TEST_VEC_EMAIL,
                     STR_LEN(USER_PREFIX)) == 0))
        {
            u8 ServerSendRcvBuffer[4*sizeof(bignum)];

            BigNumCopyUnchecked((bignum *)ServerSendRcvBuffer, (bignum *)&RFC_5054_NIST_PRIME_1024);
            BigNumCopyUnchecked((bignum *)ServerSendRcvBuffer + 1, (bignum *)&NIST_RFC_5054_GEN_BIGNUM);
            BigNumCopyUnchecked((bignum *)ServerSendRcvBuffer + 2, (bignum *)&RFC_5054_TEST_SALT);
            BigNumCopyUnchecked((bignum *)ServerSendRcvBuffer + 3, (bignum *)&RFC_5054_TEST_BIG_B);

            write(fd, ServerSendRcvBuffer, sizeof(ServerSendRcvBuffer));

            u32 ReadBytes = read(fd, ServerSendRcvBuffer, sizeof(ServerSendRcvBuffer));
            if (ReadBytes == sizeof(ServerSendRcvBuffer))
            {
                logger(ERROR, "Received message _BigA_ too long in nweb server!", buffer, fd);
            }

            bignum BigA;
            BigNumCopyUnchecked(&BigA, (bignum *)ServerSendRcvBuffer);

            bignum PremasterSecret;
            ServerGetPremasterSecret(&PremasterSecret,
                                     (bignum *)&RFC_5054_TEST_V,
                                     (bignum *)&RFC_5054_TEST_LITTLE_B,
                                     &BigA);

            u8 ServerHashScratch[SHA_1_HASH_LENGTH_BYTES];
            u32 ServerSecretSizeBytes = BigNumSizeBytesUnchecked(&PremasterSecret);
            Sha1(ServerHashScratch, (u8 *)PremasterSecret.Num, ServerSecretSizeBytes);

            // Send HMAC(K, salt)
            HmacSha1(ServerHashScratch,
                     (u8 *)PremasterSecret.Num,
                     ServerSecretSizeBytes,
                     (u8 *)RFC_5054_TEST_SALT.Num,
                     BigNumSizeBytesUnchecked((bignum *)&RFC_5054_TEST_SALT));

            ReadBytes = read(fd, ServerSendRcvBuffer, sizeof(ServerSendRcvBuffer));
            if (ReadBytes == sizeof(ServerSendRcvBuffer))
            {
                logger(ERROR, "Received message _HMAC_ too long in nweb server!", buffer, fd);
            }

            if (memcmp(ServerSendRcvBuffer, ServerHashScratch, sizeof(ServerHashScratch)) == 0)
            {
                write(fd, HMAC_VALID_STRING, STR_LEN(HMAC_VALID_STRING));
            }
            else
            {
                write(fd, HMAC_INVALID_STRING, STR_LEN(HMAC_INVALID_STRING));
            }
        }
        else
        {
            logger(ERROR, "Unsupported second argument in SRP command!", buffer, fd);
        }
    }
	else
	{
		logger(FORBIDDEN,"Only simple GET operation, test HMAC verification, and test SRP supported",buffer,fd);
	}
	sleep(1);	/* allow socket to drain before signalling the socket is closed */
	close(fd);
	exit(1);
}

int main(int argc, char **argv)
{
	int i, port, pid, listenfd, socketfd, hit;
	socklen_t length;
	static struct sockaddr_in cli_addr; /* static = initialised to zeros */
	static struct sockaddr_in serv_addr; /* static = initialised to zeros */

	if( argc < 3  || argc > 3 || !strcmp(argv[1], "-?") ) {
		(void)printf("hint: nweb Port-Number Top-Directory\t\tversion %d\n\n"
	"\tnweb is a small and very safe mini web server\n"
	"\tnweb only servers out file/web pages with extensions named below\n"
	"\t and only from the named directory or its sub-directories.\n"
	"\tThere is no fancy features = safe and secure.\n\n"
	"\tExample: nweb 8181 /home/nwebdir &\n\n"
	"\tOnly Supports:", VERSION);
		for(i=0;extensions[i].ext != 0;i++)
			(void)printf(" %s",extensions[i].ext);

		(void)printf("\n\tNot Supported: URLs including \"..\", Java, Javascript, CGI\n"
	"\tNot Supported: directories / /etc /bin /lib /tmp /usr /dev /sbin \n"
	"\tNo warranty given or implied\n\tNigel Griffiths nag@uk.ibm.com\n"  );
		exit(0);
	}
	if( !strncmp(argv[2],"/"   ,2 ) || !strncmp(argv[2],"/etc", 5 ) ||
	    !strncmp(argv[2],"/bin",5 ) || !strncmp(argv[2],"/lib", 5 ) ||
	    !strncmp(argv[2],"/tmp",5 ) || !strncmp(argv[2],"/usr", 5 ) ||
	    !strncmp(argv[2],"/dev",5 ) || !strncmp(argv[2],"/sbin",6) ){
		(void)printf("ERROR: Bad top directory %s, see nweb -?\n",argv[2]);
		exit(3);
	}
	if(chdir(argv[2]) == -1){ 
		(void)printf("ERROR: Can't Change to directory %s\n",argv[2]);
		exit(4);
	}
	/* Become deamon + unstopable and no zombies children (= no wait()) */
	if(fork() != 0)
		return 0; /* parent returns OK to shell */
	(void)signal(SIGCLD, SIG_IGN); /* ignore child death */
	(void)signal(SIGHUP, SIG_IGN); /* ignore terminal hangups */
	for(i=0;i<32;i++)
		(void)close(i);		/* close open files */
	(void)setpgrp();		/* break away from process group */
	logger(LOG,"nweb starting",argv[1],getpid());
	/* setup the network socket */
	if((listenfd = socket(AF_INET, SOCK_STREAM,0)) <0)
		logger(ERROR, "system call","socket",0);
	port = atoi(argv[1]);
	if(port < 0 || port >60000)
		logger(ERROR,"Invalid port number (try 1->60000)",argv[1],0);
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	serv_addr.sin_port = htons(port);
	if(bind(listenfd, (struct sockaddr *)&serv_addr,sizeof(serv_addr)) <0)
		logger(ERROR,"system call","bind",0);
	if( listen(listenfd,64) <0)
		logger(ERROR,"system call","listen",0);
	for(hit=1; ;hit++) {
		length = sizeof(cli_addr);
		if((socketfd = accept(listenfd, (struct sockaddr *)&cli_addr, &length)) < 0)
			logger(ERROR,"system call","accept",0);
		if((pid = fork()) < 0) {
			logger(ERROR,"system call","fork",0);
		}
		else {
			if(pid == 0) { 	/* child */
				(void)close(listenfd);
				web(socketfd,hit); /* never returns */
			} else { 	/* parent */
				(void)close(socketfd);
			}
		}
	}
}
