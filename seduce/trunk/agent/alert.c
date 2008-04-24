#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/uio.h>

#include "server_contact.h"
#include "detect_engine.h"

static int tcp_connect(const ServerSession *s)
{
	int sock;
	socklen_t addrlen = sizeof(struct sockaddr);

	sock = socket(PF_INET, SOCK_STREAM, 0);
	if(sock == -1) {
		perror("socket");
		return 0;
	}

	if(connect(sock, (struct sockaddr *)&s->addr, addrlen) == -1) {
		perror("connect");
		return 0;
	}

	return sock;
}

static ssize_t do_read(int sock, char *ptr)
{
	static int read_cnt = 0;
	static char *read_ptr;
	static char read_buf[256];

	if(read_cnt <= 0) {
again:
		if( (read_cnt = read(sock, read_buf, 256)) < 0) {
			if(errno == EINTR)
				goto again;
			return -1;
		} else if(read_cnt == 0)
			return 0;
		read_ptr = read_buf;
	}
	read_cnt--;
	*ptr = *read_ptr++;
	return 1;
}

ssize_t readline(int sock, char *vptr, size_t maxlen)
{
	ssize_t n, rc;
	char c, *p;

	p = vptr;
	for(n = 1; n < maxlen; n++) {
again:
		if((rc = do_read(sock, &c)) == 1) {
			*p++ = c;
			if(c == '\n')
				break;
		} else if(rc == 0) {
			if(n == 1)
				return 0;
			else
				break;
		} else {
			if(errno == EINTR)
				goto again;
			return -1;
		}
	}

	*p = '\0';
	return n;
}

static char *uint_to_str(char *str, unsigned int num)
{
	sprintf(str, "%u", num);
	return str;
}

static char *addr_to_str(char *str, unsigned int addr, unsigned short port)
{
	struct in_addr addr_struct;
	char *tmp;
	size_t  i;

	addr_struct.s_addr = addr;

	tmp = inet_ntoa(addr_struct);
	
	strcpy(str, tmp);

	i = strlen(tmp);

	str[i] = ':';

	uint_to_str(str + i + 1, port);

	return str;
}

static char *proper_msg(char *msg)
{
	size_t len;
	char *tmp;

	len = strlen(msg);
	tmp = malloc(len + 3);
	if(tmp == NULL) {
		perror("malloc");
		return NULL;
	}

	memcpy(tmp+1, msg, len);
	tmp[0] = tmp[len + 1] = '"';
	tmp[len + 2] = '\0';

	return tmp;
}

static int check_reply(int sock)
{
	char buf[128];
	int longline = 0;
	ssize_t numbytes;

again:
	numbytes = readline(sock, buf, 127);
	if(numbytes <= 0) {
		fprintf(stderr, "Error while reading...\n");
		return -1;
	}

	if(buf[numbytes - 1]  != '\n') {
		longline = 1;
		goto again;
	}

	if(longline) {
		return -2;
	}

	/* remove the new line */
	buf[numbytes - 1] = '\0';

	return (strcmp(buf, "OK")) ? 0 : 1;
}

static int send_command(int sock, const char *com, const char *arg)
{
	size_t com_size, arg_size;
	int iovcnt;
	struct iovec iov[4];
	int have_arg;
	int numbytes;

	have_arg = (arg != NULL);
	com_size = com ? strlen(com) : 0;
	arg_size = have_arg ? strlen(arg) : 0;

	if((com_size == 0) ||(have_arg && (arg_size == 0)))
		return -2; /*wrong input*/

	/* 
	 * the iov_base fields should be const, but I guess because the struct
	 * is used by readev too, they are left char *. I'll try to suppress
	 * the warning by casting.
	 */
	iov[0].iov_base = (char *) com;
	iov[0].iov_len = com_size;	/* without the '\0' */
	if(have_arg) {
		iov[1].iov_base = " ";
		iov[1].iov_len = 1;
		iov[2].iov_base = (char *) arg;
		iov[2].iov_len = arg_size;
		iovcnt = 4;
	} else
		iovcnt = 2;

	iov[iovcnt - 1].iov_base = "\n";
	iov[iovcnt - 1].iov_len = 1;

	numbytes = writev(sock, iov, iovcnt);
	if(numbytes <= 0) {
		if(numbytes == -1)
			perror("writev");

		return -1;
	}

	return 1;
}

int do_request_response(int sock, const char *com, const char *arg)
{
	int ret;

	ret = send_command(sock, com, arg);
	if(ret < 0) {
		fprintf(stderr,"Unable to send command %s\n", com);
		return 0;
	}

	ret = check_reply(sock);
	if(ret < 0) {
		fprintf(stderr, "Error when waiting servers reply");
		return 0;
	} else if(ret == 0) {
		fprintf(stderr, "Server denied to fulfill the command %s\n", 
				com);
		return 0;
	}

	return 1;
}

int submit_alert(const ServerSession *s, const ConnectionInfo *c,
								const Threat *t)
{
	int sock;
	char arg[128];
	int ret;
	char *tmp;


	fprintf(stderr, "Connecting to the manager...");
	
	sock = tcp_connect(s);
	if(sock == 0) {
		fprintf(stderr, "connection failed\n");
		return 0;
	} else
		fprintf(stderr, "done\n");

	//sock = 1;

	/* first send the password */
	ret = readline(sock, arg, 127);
	if(ret <= 0)
		fprintf(stderr, "skata!\n");
	else
		fprintf(stderr, "%d: %s",ret, arg);
	ret = do_request_response(sock, s->password, NULL);
	if(!ret)
		goto err;

	ret = do_request_response(sock, "NEW_ALRT", NULL);
	if(!ret)
		goto err;

	uint_to_str(arg, c->proto);
	ret = do_request_response(sock, "PROTO", arg);
	if(!ret)
		goto err;

	addr_to_str(arg, c->s_addr, c->s_port);
	ret = do_request_response(sock, "SRC_ADDR", arg);
	if(!ret)
		goto err;

	addr_to_str(arg, c->d_addr, c->d_port);
	ret = do_request_response(sock, "DST_ADDR", arg);
	if(!ret)
		goto err;

	/* 
	 * for the MSG, things are more complicated. It needs to be protected
	 * with quotes if it is more than a word.
	 */

	/* first check if there are any quotes in the msg */
	if((index(t->msg, '\"') != NULL) || (index(t->msg, '\'') != NULL)) {
		fprintf(stderr, "The msg string of the threat has quotes. "
			"This is not allowed");
		goto err;
	}

	tmp = proper_msg(t->msg);
	if(tmp == NULL)
		goto err;
	fprintf(stderr, "PROPER_MSG: %s", tmp);
	ret = do_request_response(sock, "MSG", tmp);
	free(tmp);
	if(!ret)
		goto err;

	uint_to_str(arg, t->severity);
	ret = do_request_response(sock, "SEVERITY", arg);
	if(!ret)
		goto err;

	/*TODO: Payload Command is missing */

	ret = do_request_response(sock, "SUBMIT", NULL);
	if(!ret)
		goto err;

	if((ret = send_command(sock, "QUIT", NULL)) <= 0) {
		fprintf(stderr, "Unable to send QUIT command");
		goto err;
	}

//	close(sock);
	return 1;

err:
	close(sock);
	return 0;
}
