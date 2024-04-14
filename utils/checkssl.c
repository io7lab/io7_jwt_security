#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <netdb.h>
#include <openssl/err.h>
#include <regex.h>

// compile with: gcc -o checkssl checkssl.c -lssl -lcrypto

int isSSLConnection(char *address, char *port) {
    int sock;
    struct sockaddr_in server;
    char server_reply[2000];

    // Create socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        return 1;
    }


    inet_aton(address, &server.sin_addr);
    server.sin_family = AF_INET;
    server.sin_port = htons(atoi(port));

    // Connect to remote server
    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
        return 2;
    }

    // Initialize SSL
    SSL_library_init();
    SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!ssl_ctx) {
        return 3;
    }
    SSL *ssl = SSL_new(ssl_ctx);
    SSL_set_fd(ssl, sock);

    // Perform SSL handshake
    if (SSL_connect(ssl) != 1) {
        return 4;
    }
    
    // Clean up
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ssl_ctx);
    close(sock);

    return 0;
}

int main(int argc, char* argv[]) {
    regex_t ipV4regex;
    char address[20];
    struct hostent *hp;

    if (argc < 3) {
        printf("\nUsage: %s <hostname> <port>\n\n", argv[0]);
        return 1;
    }

    regcomp(&ipV4regex, 
			"^([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))."
            "([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))."
            "([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))."
            "([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))$", REG_EXTENDED);

    
	int rc = regexec(&ipV4regex, argv[1], 0, NULL, 0);
	if (rc == REG_NOMATCH) {
		if((hp = gethostbyname(argv[1])) == NULL){
			printf("Could not gethostbyname\n");
			return 1;
		}
		strcpy(address, inet_ntoa(*(struct in_addr *)hp->h_addr));
	} else {
		strcpy(address, argv[1]);
	}

    int result = isSSLConnection(address, argv[2]);
    if (result == 0) {
        // Check if SSL handshake was successful
        printf("SSL handshake successful. Server is using TLS.\n");
    } else if (result == 1) {
        perror("Could not create socket");
    } else if (result == 2) {
        perror("Connect failed");
    } else if (result == 3) {
        perror("SSL_CTX_new failed");
    } else if (result == 4) {
        perror("SSL handshake failed");
    }

    return 0;
}