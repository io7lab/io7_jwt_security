#include <unistd.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <regex.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

#define BUFFER_SIZE 1024

struct jwt_conn_info {
	char host[50];
	char address[20];
	uint16_t port;
} conn_info;

regex_t ipV4regex;
regex_t httpRegex;

int split(char *buffer, char* delim, char* list[], int list_size) {
    // buffer : string buffer to split
    // delim : delimiter to split the string
    // list : array of char pointers to store the tokens
    // list_size : size of the list
    //
    // To use this, you need to pass a buffer that is modifiable, a delimiter, and an array of char pointers
    // number of tokens should be less than list_size at least by 1 since the last element NULL needs counted
    //
    // It returns the number of tokens stored in the list or -1 if the number of tokens exceeds the list size
    //
    int count = 0;
    char* p;

    p = strtok(buffer, delim);
    while (p != NULL && count < list_size) {
        list[count++] = p;
        p = strtok(NULL, delim);
    }
    list[count] = p;

    if (count < list_size) {
        return count;
    } else {
        return -1;
    }
}

int jwt_conn_info_init(struct jwt_conn_info *conn_info, char* host, uint16_t port) {
	// this sets the address, port, and token to conn_info glabal variable
	// and it compiles the regex for ipV4 and HTTP to global variables
	//
	struct hostent *hp;
	conn_info->port = port;
	strcpy(conn_info->host, host);

	int rc = regexec(&ipV4regex, host, 0, NULL, 0);
	if (rc == REG_NOMATCH) {
		if((hp = gethostbyname(host)) == NULL){
			mosquitto_log_printf(MOSQ_LOG_ERR, "Could not gethostbyname\n");
			return 1;
		}
		strcpy(conn_info->address, inet_ntoa(*(struct in_addr *)hp->h_addr));
	} else {
		strcpy(conn_info->address, host);
	}

	return 0;
}

//int socket_connect(char *add, in_port_t port){
int socket_connect(struct jwt_conn_info conn_info){
	struct sockaddr_in addr;
	int on = 1, sock;     

	inet_aton(conn_info.address, &addr.sin_addr);
	addr.sin_port = htons(conn_info.port);
	addr.sin_family = AF_INET;
	sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (const char *)&on, sizeof(int));

	if(sock == -1){
		mosquitto_log_printf(MOSQ_LOG_ERR, "JWT : setsockopt error");
	} else if(connect(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) == -1){
			mosquitto_log_printf(MOSQ_LOG_ERR, "JWT : connect error");
		sock = -1;
	}

	return sock;
}

int regex_init() {
	// on success it returns 0
	int rc = regcomp(&ipV4regex, 
			"^([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))."
            "([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))."
            "([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))."
            "([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))$", REG_EXTENDED);
	if (rc) {
		mosquitto_log_printf(MOSQ_LOG_ERR, "Could not compile regex\n");
	} else {
		rc = regcomp(&httpRegex, "HTTP/", REG_EXTENDED);
		if (rc) {
			mosquitto_log_printf(MOSQ_LOG_ERR, "Could not compile regex\n");
		}
	}
	return rc;
}

int doGET(int fd, char* token, char* buffer) {
	// this function sends a GET request to the server with the token
	// and reads the response into the buffer
	// it returns 0 on success
	char request[200];
	sprintf(request, "GET /users/validate_token HTTP/1.1\r\n");
    char header1[100];
	sprintf(header1, "Host: %s:%d", conn_info.host, conn_info.port);
    char header2[] = "Accept: application/json";
	char header3[300];
	sprintf(header3, "Authorization: Bearer %s", token);

    write(fd, request, strlen(request));
    write(fd, header1, strlen(header1));
    write(fd, "\r\n", strlen("\r\n"));
    write(fd, header2, strlen(header2));
    write(fd, "\r\n", strlen("\r\n"));
    write(fd, header3, strlen(header3));
    write(fd, "\r\n", strlen("\r\n"));
    write(fd, "\r\n", strlen("\r\n"));

    ssize_t bytes_received = recv(fd, buffer, BUFFER_SIZE, 0);
    if (bytes_received < 0) {
		mosquitto_log_printf(MOSQ_LOG_ERR, "Error receiving response");
        return 1;
    }
    buffer[bytes_received] = '\0';

	// the last line of the response is the payload
	// if the payload is empty, there may be some data pending so re-read the response
	char *payload = strrchr(buffer, '\n') + 1; 	// +1 to skip the newline character
	if (strlen(payload) == 0) {					
		mosquitto_log_printf(MOSQ_LOG_INFO, "Re-reading for the payload jwt authentication\n");
		ssize_t bytes_received2 = recv(fd, buffer + bytes_received, BUFFER_SIZE - (long unsigned int)bytes_received, 0);
		if (bytes_received2 < 0) {
			mosquitto_log_printf(MOSQ_LOG_ERR, "Error receiving payload");
			return 1;
		}
		buffer[bytes_received + bytes_received2] = '\0';
	}

	return 0;
}

int validateToken(char* token) {
	int isTokenValid = 0;
	char buffer[BUFFER_SIZE];

	int fd = socket_connect(conn_info);
	doGET(fd, token, (char*)&buffer);

	char* list[200];
    int count = split(buffer, "\n", list, 100);
	for (int i = 0; i < count; i++) {
		int rc = regexec(&httpRegex, list[i], 0, NULL, 0);
		if (rc != REG_NOMATCH) {
			char* result[10];
			int num = split(list[i], " ", result, 10);
			if (num == -1) {
				mosquitto_log_printf(MOSQ_LOG_ERR, "Too many tokens\n");
				isTokenValid = 0;
			} else {
				isTokenValid = atoi(result[1]) == 200 ? 1 : 0;
			}
		}
	}

	shutdown(fd, SHUT_RDWR); 
	close(fd); 

	int validPayload = strstr(list[count - 1], "{\"detail\"") ? 1 : 0;

	if (isTokenValid == 1 && validPayload) {
		mosquitto_log_printf(MOSQ_LOG_INFO, "JWT Authorized");
	} else {
		mosquitto_log_printf(MOSQ_LOG_INFO, "JWT Not Authorized");
	}
	return isTokenValid && validPayload;
}