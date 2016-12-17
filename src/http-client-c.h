/*
	http-client-c
	Copyright (C) 2012-2013  Swen Kooij

	This file is part of http-client-c.

    http-client-c is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    http-client-c is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with http-client-c. If not, see <http://www.gnu.org/licenses/>.

	Warning:
	This library does not tend to work that stable nor does it fully implent the
	standards described by IETF. For more information on the precise implentation of the
	Hyper Text Transfer Protocol:

	http://www.ietf.org/rfc/rfc2616.txt
*/

#pragma GCC diagnostic ignored "-Wwrite-strings"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#ifdef _WIN32
	#include <winsock2.h>
	#include <ws2tcpip.h>
	#include <stdio.h>
	#pragma comment(lib, "Ws2_32.lib")
#else
	#include <sys/socket.h>
	#include <netinet/in.h>
	#include <netdb.h>
	#include <arpa/inet.h>
#endif

#include <unistd.h>
#include <errno.h>
#include "stringx.h"
#include "urlparser.h"

#define HTTP_BUFFER_SIZE 2048

/*
	Prototype functions
*/
struct http_response* http_req(char *http_headers, struct parsed_url *purl, struct parsed_url *proxy_url);
struct http_response* http_get(const char *url, const char *custom_headers, const char *proxy);
struct http_response* http_head(const char *url, const char *custom_headers, const char *proxy);
struct http_response* http_post(const char *url, const char *custom_headers, const char *post_data, const char *proxy);
struct http_response* http_options(const char *url, const char *proxy);
void http_response_free(struct http_response *hresp);


/*
	Represents an HTTP html response
*/
struct http_response
{
	struct parsed_url *request_uri;
	struct parsed_url *proxy_uri;
	char *body;
	char *status_code;
	int status_code_int;
	char *status_text;
	char *request_headers;
	char *response_headers;
};

/*
	Handles redirect if needed for get requests
*/
struct http_response *handle_redirect_get(struct http_response* hresp, const char* custom_headers, const char *proxy)
{
	if(hresp != NULL && hresp->status_code_int > 300 && hresp->status_code_int < 399)
	{
		char *token = strtok(hresp->response_headers, "\r\n");
		while(token != NULL)
		{
			if(str_contains(token, "Location:"))
			{
				/* Extract url */
				char *location = str_replace_x("Location: ", "", token);
				struct http_response *res = http_get(location, custom_headers, proxy);
				free(location);
				http_response_free(hresp);
				return res;
			}
			token = strtok(NULL, "\r\n");
		}
		return hresp;
	}
	else
	{
		/* We're not dealing with a redirect, just return the same structure */
		return hresp;
	}
}

/*
	Handles redirect if needed for head requests
*/
struct http_response* handle_redirect_head(struct http_response* hresp, const char* custom_headers, const char *proxy)
{
	if(hresp != NULL && hresp->status_code_int > 300 && hresp->status_code_int < 399)
	{
		char *token = strtok(hresp->response_headers, "\r\n");
		while(token != NULL)
		{
			if(str_contains(token, "Location:"))
			{
				/* Extract url */
				char *location = str_replace_x("Location: ", "", token);
				struct http_response *res = http_head(location, custom_headers, proxy);
				free(location);
				http_response_free(hresp);
				return res;
			}
			token = strtok(NULL, "\r\n");
		}
		return hresp;
	}
	else
	{
		/* We're not dealing with a redirect, just return the same structure */
		return hresp;
	}
}

/*
	Handles redirect if needed for post requests
*/
struct http_response* handle_redirect_post(struct http_response* hresp, const char* custom_headers, const char *post_data, const char *proxy)
{
	if(hresp != NULL && hresp->status_code_int > 300 && hresp->status_code_int < 399)
	{
		char *token = strtok(hresp->response_headers, "\r\n");
		while(token != NULL)
		{
			if(str_contains(token, "Location:"))
			{
				/* Extract url */
				char *location = str_replace_x("Location: ", "", token);
				struct http_response *res = http_post(location, custom_headers, post_data, proxy);
				free(location);
				http_response_free(hresp);
				return res;
			}
			token = strtok(NULL, "\r\n");
		}
		return hresp;
	}
	else
	{
		/* We're not dealing with a redirect, just return the same structure */
		return hresp;
	}
}

/*
	Makes a HTTP request and returns the response
*/
struct http_response* http_req(char *http_headers, struct parsed_url *purl, struct parsed_url *proxy_url)
{
	/* Parse url */
	if(purl == NULL)
	{
		printf("Unable to parse url");
		return NULL;
	}

	/* Declare variable */
	int sock;
	int tmpres;
	struct sockaddr_in *remote;

	/* Allocate memeory for htmlcontent */
	struct http_response *hresp = (struct http_response*)malloc(sizeof(struct http_response));
	if(hresp == NULL)
	{
		printf("Unable to allocate memory for htmlcontent.");
		return NULL;
	}
	hresp->body = NULL;
	hresp->request_headers = NULL;
	hresp->response_headers = NULL;
	hresp->status_code = NULL;
	hresp->status_text = NULL;

	/* Create TCP socket */
	if((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
	{
	    printf("Can't create TCP socket");
		free(hresp);
		return NULL;
	}

	/* Set remote->sin_addr.s_addr */
	remote = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in *));
	remote->sin_family = AF_INET;
	tmpres = inet_pton(AF_INET, proxy_url==NULL?purl->ip:proxy_url->ip, (void *)(&(remote->sin_addr.s_addr)));
  	if( tmpres < 0)
  	{
    	printf("Can't set remote->sin_addr.s_addr");
		free(remote);
		free(hresp);
    	return NULL;
  	}
	else if(tmpres == 0)
  	{
		printf("Not a valid IP");
		free(remote);
		free(hresp);
    	return NULL;
  	}
	remote->sin_port = htons(atoi(proxy_url==NULL?purl->port:proxy_url->port));

	/* Connect */
	if(connect(sock, (struct sockaddr *)remote, sizeof(struct sockaddr)) < 0)
	{
	    printf("Could not connect");
		free(remote);
		free(hresp);
		return NULL;
	}

	/* Send headers to server */
	size_t sent = 0;
	while(sent < strlen(http_headers))
	{
	    tmpres = send(sock, http_headers+sent, strlen(http_headers)-sent, 0);
		if(tmpres == -1)
		{
			printf("Can't send headers");
			free(remote);
			free(hresp);
			return NULL;
		}
		sent += tmpres;
	 }

	/* Recieve into response*/
	char *response = (char *)malloc(BUFSIZ);
	response[0] = '\0';
	char buf[BUFSIZ];
	ssize_t received_len = 0;
	while((received_len = recv(sock, buf, BUFSIZ-1, 0)) > 0)
	{
        buf[received_len] = '\0';
		response = (char*)realloc(response, strlen(response) + strlen(buf) + 1);
		strcat(response, buf);
	}
	if (received_len < 0)
    {
		free(http_headers);
		#ifdef _WIN32
			closesocket(sock);
		#else
			close(sock);
		#endif
        printf("Unabel to recieve");
		free(remote);
		free(hresp);
		free(response);
		return NULL;
    }

	free(remote);

	/* Close socket */
	#ifdef _WIN32
		closesocket(sock);
	#else
		close(sock);
	#endif

	/* Parse status code and text */
	char *p = NULL;

	p = str_get_until_x(response, "\r\n");
	char *status_line = str_replace_x("HTTP/1.1 ", "", p);
	free(p);

	p = str_ndup_x(status_line, 4);
	char *status_code = str_replace_x(" ", "", p);
	free(p);

	p= str_replace_x(status_code, "", status_line);
	char *status_text = str_replace_x(" ", "", p);
	free(p);

	hresp->status_code = status_code;
	hresp->status_code_int = atoi(status_code);
	hresp->status_text = status_text;

	free(status_line);

	/* Parse response headers */
	char *headers = str_get_until_x(response, "\r\n\r\n");
	hresp->response_headers = headers;

	/* Assign request headers */
	hresp->request_headers = http_headers;

	/* Assign request url */
	hresp->request_uri = purl;

	/* Assign proxy url */
	hresp->proxy_uri = proxy_url;

	/* Parse body */
	p = strstr(response, "\r\n\r\n");
	char *body = str_replace_x("\r\n\r\n", "", p);
	hresp->body = body;

	free(response);

	/* Return response */
	return hresp;
}

/*
	Makes a HTTP GET request to the given url
*/
struct http_response* http_get(const char *url, const char *custom_headers, const char *proxy)
{
	/* Parse url */
	struct parsed_url *purl = parse_url(url);
	if(purl == NULL)
	{
		printf("Unable to parse url");
		return NULL;
	}

	struct parsed_url *proxy_url = NULL;
	if (proxy)
	{
		proxy_url = parse_url(proxy);
		if(proxy_url == NULL)
		{
			printf("Unable to parse proxy");
			return NULL;
		}
	}

	/* Declare variable */
	char *http_headers = (char*)malloc(HTTP_BUFFER_SIZE);

	/* Build query/headers */
	if(purl->path != NULL)
	{
		if(purl->query != NULL)
		{
			if (proxy_url == NULL)
			{
				sprintf(http_headers, "GET /%s?%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n", purl->path, purl->query, purl->host);
			}
			else
			{
				sprintf(http_headers, "GET %s://%s/%s?%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n", purl->scheme, purl->host, purl->path, purl->query, purl->host);
			}
		}
		else
		{
			if (proxy_url == NULL)
			{
				sprintf(http_headers, "GET /%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n", purl->path, purl->host);
			}
			else
			{
				sprintf(http_headers, "GET %s://%s/%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n", purl->scheme, purl->host, purl->path, purl->host);
			}
		}
	}
	else
	{
		if(purl->query != NULL)
		{
			if (proxy_url == NULL)
			{
				sprintf(http_headers, "GET /?%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n", purl->query, purl->host);
			}
			else
			{
				sprintf(http_headers, "GET %s://%s/?%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n", purl->scheme, purl->host, purl->query, purl->host);
			}
		}
		else
		{
			if (proxy_url == NULL)
			{
				sprintf(http_headers, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n", purl->host);
			}
			else
			{
				sprintf(http_headers, "GET %s://%s/ HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n", purl->scheme, purl->host, purl->host);
			}
		}
	}

	/* Handle authorisation if needed */
	if(purl->username != NULL)
	{
		/* Format username:password pair */
		char *upwd = (char*)malloc(HTTP_BUFFER_SIZE);
		sprintf(upwd, "%s:%s", purl->username, purl->password);
		upwd = (char*)realloc(upwd, strlen(upwd) + 1);

		/* Base64 encode */
		char *base64 = http_base64_encode(upwd);

		/* Form header */
		char *auth_header = (char*)malloc(HTTP_BUFFER_SIZE);
		sprintf(auth_header, "Authorization: Basic %s\r\n", base64);
		auth_header = (char*)realloc(auth_header, strlen(auth_header) + 1);

		/* Add to header */
		http_headers = (char*)realloc(http_headers, strlen(http_headers) + strlen(auth_header) + 2);
		strcat(http_headers, auth_header);

		free(upwd);
		free(base64);
		free(auth_header);
	}

	/* Add custom headers, and close */
	if(custom_headers != NULL)
	{
		http_headers = (char*)realloc(http_headers, strlen(http_headers) + strlen(custom_headers) + 3);
		strcat(http_headers, custom_headers);
	}
	strcat(http_headers, "\r\n");

	/* Make request and return response */
	struct http_response *hresp = http_req(http_headers, purl, proxy_url);

	/* Handle redirect */
	return handle_redirect_get(hresp, custom_headers, proxy);
}

/*
	Makes a HTTP POST request to the given url
*/
struct http_response* http_post(const char *url, const char *custom_headers, const char *post_data, const char *proxy)
{
	/* Parse url */
	struct parsed_url *purl = parse_url(url);
	if(purl == NULL)
	{
		printf("Unable to parse url");
		return NULL;
	}

	struct parsed_url *proxy_url = NULL;
	if (proxy)
	{
		proxy_url = parse_url(proxy);
		if(proxy_url == NULL)
		{
			printf("Unable to parse proxy");
			return NULL;
		}
	}

	if (post_data == NULL)
	{
		post_data = "";
	}

	/* Declare variable */
	char *http_headers = (char*)malloc(HTTP_BUFFER_SIZE);

	/* Build query/headers */
	if(purl->path != NULL)
	{
		if(purl->query != NULL)
		{
			if (proxy_url == NULL)
			{
				sprintf(http_headers, "POST /%s?%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nContent-Length: %zu\r\nContent-Type: application/x-www-form-urlencoded\r\n", purl->path, purl->query, purl->host, strlen(post_data));
			}
			else
			{
				sprintf(http_headers, "POST %s://%s/%s?%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nContent-Length: %zu\r\nContent-Type: application/x-www-form-urlencoded\r\n", purl->scheme, purl->host, purl->path, purl->query, purl->host, strlen(post_data));
			}
		}
		else
		{
			if (proxy_url == NULL)
			{
				sprintf(http_headers, "POST /%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nContent-Length: %zu\r\nContent-Type: application/x-www-form-urlencoded\r\n", purl->path, purl->host, strlen(post_data));
			}
			else
			{
				sprintf(http_headers, "POST %s://%s/%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nContent-Length: %zu\r\nContent-Type: application/x-www-form-urlencoded\r\n", purl->scheme, purl->host, purl->path, purl->host, strlen(post_data));
			}
		}
	}
	else
	{
		if(purl->query != NULL)
		{
			if (proxy_url == NULL)
			{
				sprintf(http_headers, "POST /?%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nContent-Length: %zu\r\nContent-Type: application/x-www-form-urlencoded\r\n", purl->query, purl->host, strlen(post_data));
			}
			else
			{
				sprintf(http_headers, "POST %s://%s/?%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nContent-Length: %zu\r\nContent-Type: application/x-www-form-urlencoded\r\n", purl->scheme, purl->host, purl->query, purl->host, strlen(post_data));
			}
		}
		else
		{
			if (proxy_url == NULL)
			{
				sprintf(http_headers, "POST / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nContent-Length: %zu\r\nContent-Type: application/x-www-form-urlencoded\r\n", purl->host, strlen(post_data));
			}
			else
			{
				sprintf(http_headers, "POST %s://%s/ HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nContent-Length: %zu\r\nContent-Type: application/x-www-form-urlencoded\r\n", purl->scheme, purl->host, purl->host, strlen(post_data));
			}
		}
	}

	/* Handle authorisation if needed */
	if(purl->username != NULL)
	{
		/* Format username:password pair */
		char *upwd = (char*)malloc(HTTP_BUFFER_SIZE);
		sprintf(upwd, "%s:%s", purl->username, purl->password);
		upwd = (char*)realloc(upwd, strlen(upwd) + 1);

		/* Base64 encode */
		char *base64 = http_base64_encode(upwd);

		/* Form header */
		char *auth_header = (char*)malloc(HTTP_BUFFER_SIZE);
		sprintf(auth_header, "Authorization: Basic %s\r\n", base64);
		auth_header = (char*)realloc(auth_header, strlen(auth_header) + 1);

		/* Add to header */
		http_headers = (char*)realloc(http_headers, strlen(http_headers) + strlen(auth_header) + 2);
		strcat(http_headers, auth_header);

		free(upwd);
		free(base64);
		free(auth_header);
	}

	size_t header_len = strlen(http_headers) + strlen(post_data) + 3;
	if(custom_headers != NULL)
	{
		http_headers = (char*)realloc(http_headers, header_len + strlen(custom_headers));
		strcat(http_headers, custom_headers);
	}
	else
	{
		http_headers = (char*)realloc(http_headers, header_len);
	}
	strcat(http_headers, "\r\n");
	strcat(http_headers, post_data);

	/* Make request and return response */
	struct http_response *hresp = http_req(http_headers, purl, proxy_url);

	/* Handle redirect */
	return handle_redirect_post(hresp, custom_headers, post_data, proxy);
}

/*
	Makes a HTTP HEAD request to the given url
*/
struct http_response* http_head(const char *url, const char *custom_headers, const char *proxy)
{
	/* Parse url */
	struct parsed_url *purl = parse_url(url);
	if(purl == NULL)
	{
		printf("Unable to parse url");
		return NULL;
	}

	struct parsed_url *proxy_url = NULL;
	if (proxy)
	{
		proxy_url = parse_url(proxy);
		if(proxy_url == NULL)
		{
			printf("Unable to parse proxy");
			return NULL;
		}
	}

	/* Declare variable */
	char *http_headers = (char*)malloc(HTTP_BUFFER_SIZE);

	/* Build query/headers */
	if(purl->path != NULL)
	{
		if(purl->query != NULL)
		{
			if (proxy_url == NULL)
			{
				sprintf(http_headers, "HEAD /%s?%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n", purl->path, purl->query, purl->host);
			}
			else
			{
				sprintf(http_headers, "HEAD %s://%s/%s?%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n", purl->scheme, purl->host, purl->path, purl->query, purl->host);
			}
		}
		else
		{
			if (proxy_url == NULL)
			{
				sprintf(http_headers, "HEAD /%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n", purl->path, purl->host);
			}
			else
			{
				sprintf(http_headers, "HEAD %s://%s/%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n", purl->scheme, purl->host, purl->path, purl->host);
			}
		}
	}
	else
	{
		if(purl->query != NULL)
		{
			if (proxy_url == NULL)
			{
				sprintf(http_headers, "HEAD /?%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n", purl->query, purl->host);
			}
			else
			{
				sprintf(http_headers, "HEAD %s://%s/?%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n", purl->scheme, purl->host, purl->query, purl->host);
			}
		}
		else
		{
			if (proxy_url == NULL)
			{
				sprintf(http_headers, "HEAD / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n", purl->host);
			}
			else
			{
				sprintf(http_headers, "HEAD %s://%s/ HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n", purl->scheme, purl->host, purl->host);
			}
		}
	}

	/* Handle authorisation if needed */
	if(purl->username != NULL)
	{
		/* Format username:password pair */
		char *upwd = (char*)malloc(HTTP_BUFFER_SIZE);
		sprintf(upwd, "%s:%s", purl->username, purl->password);
		upwd = (char*)realloc(upwd, strlen(upwd) + 1);

		/* Base64 encode */
		char *base64 = http_base64_encode(upwd);

		/* Form header */
		char *auth_header = (char*)malloc(HTTP_BUFFER_SIZE);
		sprintf(auth_header, "Authorization: Basic %s\r\n", base64);
		auth_header = (char*)realloc(auth_header, strlen(auth_header) + 1);

		/* Add to header */
		http_headers = (char*)realloc(http_headers, strlen(http_headers) + strlen(auth_header) + 2);
		strcat(http_headers, auth_header);

		free(upwd);
		free(base64);
		free(auth_header);
	}

	/* Add custom headers, and close */
	if(custom_headers != NULL)
	{
		http_headers = (char*)realloc(http_headers, strlen(http_headers) + strlen(custom_headers) + 2);
		strcat(http_headers, custom_headers);
	}
	strcat(http_headers, "\r\n");

	/* Make request and return response */
	struct http_response *hresp = http_req(http_headers, purl, proxy_url);

	/* Handle redirect */
	return handle_redirect_head(hresp, custom_headers, proxy);
}

/*
	Do HTTP OPTIONs requests
*/
struct http_response* http_options(const char *url, const char *proxy)
{
	/* Parse url */
	struct parsed_url *purl = parse_url(url);
	if(purl == NULL)
	{
		printf("Unable to parse url");
		return NULL;
	}

	struct parsed_url *proxy_url = NULL;
	if (proxy)
	{
		proxy_url = parse_url(proxy);
		if(proxy_url == NULL)
		{
			printf("Unable to parse proxy");
			return NULL;
		}
	}

	/* Declare variable */
	char *http_headers = (char*)malloc(HTTP_BUFFER_SIZE);

	/* Build query/headers */
	if(purl->path != NULL)
	{
		if(purl->query != NULL)
		{
			if (proxy_url == NULL)
			{
				sprintf(http_headers, "OPTIONS /%s?%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n", purl->path, purl->query, purl->host);
			}
			else
			{
				sprintf(http_headers, "OPTIONS %s://%s/%s?%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n", purl->scheme, purl->host, purl->path, purl->query, purl->host);
			}
		}
		else
		{
			if (proxy_url == NULL)
			{
				sprintf(http_headers, "OPTIONS /%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n", purl->path, purl->host);
			}
			else
			{
				sprintf(http_headers, "OPTIONS %s://%s/%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n", purl->scheme, purl->host, purl->path, purl->host);
			}
		}
	}
	else
	{
		if(purl->query != NULL)
		{
			if (proxy_url == NULL)
			{
				sprintf(http_headers, "OPTIONS /?%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n", purl->query, purl->host);
			}
			else
			{
				sprintf(http_headers, "OPTIONS %s://%s/?%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n", purl->scheme, purl->host, purl->query, purl->host);
			}
		}
		else
		{
			if (proxy_url == NULL)
			{
				sprintf(http_headers, "OPTIONS / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n", purl->host);
			}
			else
			{
				sprintf(http_headers, "OPTIONS %s://%s/ HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n", purl->scheme, purl->host, purl->host);
			}
		}
	}

	/* Handle authorisation if needed */
	if(purl->username != NULL)
	{
		/* Format username:password pair */
		char *upwd = (char*)malloc(HTTP_BUFFER_SIZE);
		sprintf(upwd, "%s:%s", purl->username, purl->password);
		upwd = (char*)realloc(upwd, strlen(upwd) + 1);

		/* Base64 encode */
		char *base64 = http_base64_encode(upwd);

		/* Form header */
		char *auth_header = (char*)malloc(HTTP_BUFFER_SIZE);
		sprintf(auth_header, "Authorization: Basic %s\r\n", base64);
		auth_header = (char*)realloc(auth_header, strlen(auth_header) + 1);

		/* Add to header */
		http_headers = (char*)realloc(http_headers, strlen(http_headers) + strlen(auth_header) + 2);
		strcat(http_headers, auth_header);

		free(upwd);
		free(base64);
		free(auth_header);
	}

	/* Build headers */
	strcat(http_headers, "\r\n");

	/* Make request and return response */
	struct http_response *hresp = http_req(http_headers, purl, proxy_url);

	/* Handle redirect */
	return hresp;
}

/*
	Free memory of http_response
*/
void http_response_free(struct http_response *hresp)
{
	if(hresp != NULL)
	{
		if(hresp->request_uri != NULL) parsed_url_free(hresp->request_uri);
		if(hresp->proxy_uri != NULL) parsed_url_free(hresp->proxy_uri);
		if(hresp->body != NULL) free(hresp->body);
		if(hresp->status_code != NULL) free(hresp->status_code);
		if(hresp->status_text != NULL) free(hresp->status_text);
		if(hresp->request_headers != NULL) free(hresp->request_headers);
		if(hresp->response_headers != NULL) free(hresp->response_headers);
		free(hresp);
	}
}
