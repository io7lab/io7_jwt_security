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
#include <cjson/cJSON.h>

#define JWT_AUTH_PORT 2009
#define JWT_AUTH_SERVER "io7api"

#define BUFFER_SIZE 1024

struct jwt_conn_info {
	char url[300];
	char protocol[10];
	char host[100];
	uint16_t port;
	char path[500];
	char user[100];
	char password[100];
	char address[20];
} conn_info;

regex_t ipV4regex;
regex_t httpRegex;

void parseURL(char *url, struct jwt_conn_info *conn_info) {
	char buffer[500];
	char buffer2[500];
	int port = 80;

	bzero(conn_info->protocol, sizeof(conn_info->protocol));
	bzero(conn_info->host, sizeof(conn_info->host));
	bzero(conn_info->user, sizeof(conn_info->user));
	bzero(conn_info->password, sizeof(conn_info->password));
	bzero(conn_info->path, sizeof(conn_info->path));
	bzero(conn_info->address, sizeof(conn_info->address));
	strcpy(conn_info->url, url);

	int rc = sscanf(url, "%99[^:]://%99[^\n]", conn_info->protocol, buffer);
	rc = sscanf(buffer, "%99[^@]@%99[^\n]", buffer2, buffer);
	if (rc == 2) {
		rc = sscanf(buffer2, "%99[^:]:%99[^\n]", conn_info->user, conn_info->password);
	}
	rc = sscanf(buffer, "%99[^/]/%99[^\n]", buffer2, conn_info->path);
	rc = sscanf(buffer2, "%99[^:]:%99d[^\n]", conn_info->host, &port);
	conn_info->port = (uint16_t)port;

}

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

void regex_free() {
	regfree(&ipV4regex);
	regfree(&httpRegex);
}

int load_conn_info(struct jwt_conn_info *conn_info, char *config_file) { 
	FILE *fp;
	char buffer[500];
	bzero(buffer, sizeof(buffer));
	cJSON *tree;

	fp = fopen(config_file, "r");
	if (NULL == fp) {
		mosquitto_log_printf(MOSQ_LOG_ERR, "Error: JWT security plugin config file can't be opened.");
	} else {
		fread(buffer, 1, sizeof(buffer), fp);
		fclose(fp);

		tree = cJSON_Parse(buffer);
		if (tree == NULL) {
			mosquitto_log_printf(MOSQ_LOG_ERR, "Error: JSON parsing failed for %s.", config_file);
			return MOSQ_ERR_INVAL;
		}

		cJSON *url = cJSON_GetObjectItem(tree, "url");
		parseURL(url->valuestring, conn_info);
	}

	return 0;
}

int jwt_conn_config_init(struct jwt_conn_info *conn_info, char *config_file) {
	// this sets the host, port, and token to conn_info glabal variable
	// and it resolves and set the ip address with the regex for ipV4
	//
	struct hostent *hp;

	if (config_file == NULL) {
		conn_info->port = JWT_AUTH_PORT;			// default port
		strcpy(conn_info->host, JWT_AUTH_SERVER);	// default host
	} else {
		load_conn_info(conn_info, config_file);
	}

	regex_init();

	char *host = conn_info->host;
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

int doGET(int fd, char* token, char* buffer) {
	// this function sends a GET request to the server with the token
	// and reads the response into the buffer
	// it returns 0 on success
	char request[200];
	sprintf(request, "GET /users/validate_token HTTP/1.1\r\n");
    char header1[200];
	sprintf(header1, "Host: %s:%d", conn_info.host, (int)conn_info.port);
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
	int resp200 = 0;
	char buffer[BUFFER_SIZE];

	int fd = socket_connect(conn_info);
	doGET(fd, token, (char*)&buffer);

	char* list[200];
    int count = split(buffer, "\n", list, 100);
	for (int i = 0; i < count; i++) {
		int rc = regexec(&httpRegex, list[i], 0, NULL, 0);
		if (rc != REG_NOMATCH) {							// if matches "HTTP/"
			char* result[10];
			int num = split(list[i], " ", result, 10);
			if (num == -1) {
				mosquitto_log_printf(MOSQ_LOG_ERR, "Too many tokens\n");
				resp200 = 0;
			} else {
				resp200 = atoi(result[1]) == 200 ? 1 : 0;
			}
		}
	}

	shutdown(fd, SHUT_RDWR); 
	close(fd); 

	int authorized = 0;
	cJSON *auth = cJSON_Parse(list[count - 1]);				// list[count - 1] is the payload
	if (auth == NULL) {
		mosquitto_log_printf(MOSQ_LOG_ERR, "JWT Authorization Response JSON Parse Error\n");
	} else {
		cJSON *detail = cJSON_GetObjectItem(auth, "detail");
		authorized = strstr(detail->valuestring, "Authorized") ? 1 : 0;
	}

	if (resp200 == 1 && authorized) {
		mosquitto_log_printf(MOSQ_LOG_INFO, "JWT Authorized");
	} else {
		mosquitto_log_printf(MOSQ_LOG_INFO, "JWT Not Authorized");
	}
	return resp200 && authorized;
}