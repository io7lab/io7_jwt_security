#include <stdio.h>
#include <string.h>

struct urlParts {
	char protocol[10];
	char host[100];
	char user[100];
	char pass[100];
	int  port;
	char path[500];
};

void parseURL(char *url, struct urlParts *parsedURL) {
	char buffer[500];
	char buffer2[500];

	bzero(parsedURL->protocol, sizeof(parsedURL->protocol));
	bzero(parsedURL->host, sizeof(parsedURL->host));
	parsedURL->port = 80;
	bzero(parsedURL->user, sizeof(parsedURL->user));
	bzero(parsedURL->pass, sizeof(parsedURL->pass));
	bzero(parsedURL->path, sizeof(parsedURL->path));

	int rc = sscanf(url, "%99[^:]://%99[^\n]", parsedURL->protocol, buffer);
	rc = sscanf(buffer, "%99[^@]@%99[^\n]", buffer2, buffer);
	if (rc == 2) {
		rc = sscanf(buffer2, "%99[^:]:%99[^\n]", parsedURL->user, parsedURL->pass);
	}
	rc = sscanf(buffer, "%99[^/]/%99[^\n]", buffer2, parsedURL->path);
	rc = sscanf(buffer2, "%99[^:]:%99d[^\n]", parsedURL->host, &parsedURL->port);
}


int main(int argc, char *argv[])
{
	char buffer[500];
	struct urlParts parsedURL;
	strcpy(buffer, argv[1]);
	parseURL(buffer, &parsedURL);

    printf("\tParsed URL\n");
    printf("protocol: %s\n", parsedURL.protocol);
    printf("host\t: %s\n", parsedURL.host);
    printf("port\t: %d\n", parsedURL.port);
    printf("path\t: %s\n", parsedURL.path);
    printf("user\t: %s\n", parsedURL.user);
    printf("pass\t: %s\n", parsedURL.pass);

    return 0;
}
