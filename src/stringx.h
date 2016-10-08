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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifdef __cplusplus
	#include <locale>
#endif

/*
	Gets the offset of one string in another string
*/
ssize_t str_index_of(const char *haystack, char *needle)
{
	char *offset = strstr(haystack, needle);
	return offset == NULL ? -1 : offset - haystack;
}

/*
	Checks if one string contains another string
*/
int str_contains(const char *haystack, const char *needle)
{
	return strstr(haystack, needle) == NULL ? 0 : 1;
}

/*
	Removes last character from string
*/
char *str_trim_end(char *s, char to_trim)
{
	size_t len = strlen(s);
	if (len > 0 && s[len - 1] == to_trim)
	{
		s[len - 1] = 0;
	}
	return s;
}

/*
	Concecates two strings, a wrapper for strcat from string.h, handles the resizing and copying
*/
char *str_cat_x(char *s1, char *s2)
{
	char *ret = (char*)malloc(strlen(s1) + strlen(s2) + 1);
	if (ret)
	{
		strcat(strcpy(ret, s1), s2);
	}
	return ret;
}

/*
	Converts an integer value to its hex character
*/
static inline char to_hex(char code)
{
	static const char hex[] = "0123456789abcdef";
	return hex[code & 15];
}

/*
	URL encodes a string
*/
char *url_encode_x(const char *url)
{
	const char *pstr = url;
	char *res = (char *)malloc(strlen(url) * 3 + 1);
	char *pbuf = res;
	if (pbuf)
	{
		while (*pstr)
		{
			if (isalnum(*pstr) || *pstr == '-' || *pstr == '_' || *pstr == '.' || *pstr == '~')
				*pbuf++ = *pstr;
			else if (*pstr == ' ')
				*pbuf++ = '+';
			else
				*pbuf++ = '%', *pbuf++ = to_hex(*pstr >> 4), *pbuf++ = to_hex(*pstr & 15);
			pstr++;
		}
		*pbuf = '\0';
	}
	return res;
}

/*
	Replacement for the string.h strndup
*/
char *str_ndup_x(const char *s, size_t n)
{
    size_t len = strnlen(s, n);
    char *res = (char*)malloc(len + 1);
    if (res)
    {
        memcpy(res, s, len);
        res[len] = '\0';
    }
    return res;
}

/*
	Replacement for the string.h strdup
*/
char *str_dup_x(const char *src)
{
	return str_ndup_x(src, strlen(src));
}

/*
 	Search and replace a string with another string , in a string
*/
char *str_replace_x(char *search , char *replace , char *subject)
{
	size_t matches = 0;
	size_t search_size = strlen(search);
	char *p = NULL;
	for (p = strstr(subject, search); p != NULL ; p = strstr(p + search_size, search))
	{
		matches++;
	}
	ssize_t result_size = (strlen(replace) - search_size) * matches + strlen(subject);

	char *new_subject = (char*)malloc(result_size + 1);
	new_subject[0] = '\0';
	char *old_subject = subject;

	for(p = strstr(subject, search) ; p != NULL ; p = strstr(p + search_size , search))
	{
		size_t new_subject_len = strlen(new_subject);
		size_t copy_len = p - old_subject;
		memcpy(new_subject + new_subject_len, old_subject , copy_len);
		new_subject[new_subject_len + copy_len] = '\0';
		strcat(new_subject, replace);
		old_subject = p + search_size;
	}
	strcat(new_subject, old_subject);

	return new_subject;
}

/*
	Get's all characters until '*until' has been found
*/
char *str_get_until_x(char *haystack, char *until)
{
	ssize_t offset = str_index_of(haystack, until);
	if (offset < 0)
	{
		return NULL;
	}
	else
	{
		return str_ndup_x(haystack, offset);
	}
}


/* decodeblock - decode 4 '6-bit' characters into 3 8-bit binary bytes */
void decodeblock(unsigned char in[], char *clrstr)
{
  	unsigned char out[4];
	out[0] = in[0] << 2 | in[1] >> 4;
	out[1] = in[1] << 4 | in[2] >> 2;
	out[2] = in[2] << 6 | in[3] >> 0;
	out[3] = '\0';
	strncat((char *)clrstr, (char *)out, sizeof(char *));
}

/*
	Decodes a Base64 string
*/
char* base64_decode(char *b64src)
{
	char *clrdst = (char*)malloc( ((strlen(b64src) - 1) / 3 ) * 4 + 4 + 50);
	char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	int c, phase, i;
	unsigned char in[4];
	char *p;
	clrdst[0] = '\0';
	phase = 0; i=0;
	while(b64src[i])
	{
		c = (int) b64src[i];
		if(c == '=')
		{
			decodeblock(in, clrdst);
			break;
		}
		p = strchr(b64, c);
		if(p)
		{
			in[phase] = p - b64;
			phase = (phase + 1) % 4;
			if(phase == 0)
			{
				decodeblock(in, clrdst);
				in[0]=in[1]=in[2]=in[3]=0;
			}
		}
		i++;
	}
	clrdst = (char*)realloc(clrdst, strlen(clrdst) + 1);
	return clrdst;
}

/* encodeblock - encode 3 8-bit binary bytes as 4 '6-bit' characters */
void encodeblock( unsigned char in[], char b64str[], int len )
{
	char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    unsigned char out[5];
    out[0] = b64[ in[0] >> 2 ];
    out[1] = b64[ ((in[0] & 0x03) << 4) | ((in[1] & 0xf0) >> 4) ];
    out[2] = (unsigned char) (len > 1 ? b64[ ((in[1] & 0x0f) << 2) |
             ((in[2] & 0xc0) >> 6) ] : '=');
    out[3] = (unsigned char) (len > 2 ? b64[ in[2] & 0x3f ] : '=');
    out[4] = '\0';
    strncat((char *)b64str, (char *)out, sizeof(char *));
}

/*
	Encodes a string with Base64
*/
char* base64_encode(char *clrstr)
{
	size_t encoded_length = strlen(clrstr) / 3 * 4 + 10;
	char *b64dst = (char*)malloc(encoded_length);
	unsigned char in[3];
	int i, len = 0;
	int j = 0;

	b64dst[0] = '\0';
	while(clrstr[j])
	{
		len = 0;
		for(i=0; i<3; i++)
		{
			in[i] = (unsigned char) clrstr[j];
			if(clrstr[j])
			{
				len++; j++;
			}
			else in[i] = 0;
		}
		if( len )
		{
			encodeblock( in, b64dst, len );
		}
	}
	b64dst = (char*)realloc(b64dst, strlen(b64dst) + 1);
	return b64dst;
}
