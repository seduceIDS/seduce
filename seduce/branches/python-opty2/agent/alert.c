#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/uio.h>

#include "sensor_contact.h"
#include "detect_engine.h"
#include "base64_encoder.h"
#include "utils.h"

#define MIN(a, b)  (((a) < (b)) ? (a) : (b))

static int tcp_connect(const SensorSession *s)
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

ssize_t writeall(int fd, const char *buf, size_t len)
{
	ssize_t numbytes, written = 0;
	const char *p = buf;

	while(written < len) {
		numbytes = write(fd, p, len - written);
		if(numbytes < 0) {
			if(errno == EINTR)
				continue;
			else
				return -1;
		}

		written += numbytes;
		p += numbytes;
	}

	return written;
}

static ssize_t do_read(int sock, char *ptr)
{
	static int read_cnt = 0;
	static char *read_ptr;
	static char read_buf[256];

	if(read_cnt <= 0) {
again:
		if((read_cnt = read(sock, read_buf, 256)) < 0) {
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

static char *prepare_msg(char *msg)
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

static int check_reply(int sock, const char *rep)
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

	if(strcmp(buf, rep) == 0)
		return 1;
	else {
		fprintf(stderr, "Error. Sensor Replied: %s\n", buf);
		return 0;
	}
}

static int send_payload(int sock, const Threat* t)
{
	const size_t default_block = 32;
	/* 
	 * The max output size is len*4/3 + len*4/(3*72) + 7
	 * So, for len = 64, the b[128] should be enough.
	 */
	char buf[128];
	size_t block_size;
	ssize_t numbytes;
	const unsigned char *p;
	size_t encoded_len, input_len;
	int state, save;

	if(t == NULL)
		return 0;

	p = t->payload;
	input_len = 0;
	encoded_len = 0;
	save = 0;
	state = 0;
	while(input_len < t->length) {
		block_size = MIN(default_block, t->length - input_len);

		numbytes = base64_encode_step(p + input_len, block_size, buf,
								&state, &save);
		if(numbytes <= 0)
			return -1;

		encoded_len += numbytes;
		input_len += block_size;

		numbytes = writeall(sock, buf, numbytes);
		if(numbytes < 0)
			return -1;
	}

	numbytes = base64_encode_close(buf, &state, &save);
	if(numbytes < 0)
		return -1;
	else if(numbytes > 0) {
		numbytes = writeall(sock, buf, numbytes);
		if(numbytes < 0)
			return -1;
	}

	/* At the end, send an empty line */
	numbytes = writeall(sock, "\n", 1);
	if(numbytes < 0)
		return -1;


	return check_reply(sock, "OK");
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

	ret = check_reply(sock, "OK");
	if(ret < 0) {
		fprintf(stderr, "Error when waiting sensors reply");
		return 0;
	} else if(ret == 0) {
		fprintf(stderr, "Sensor denied to fulfill the command %s\n", 
				com);
		return 0;
	}

	return 1;
}

int submit_alert(const SensorSession *s, const ConnectionInfo *c,
		 const Threat *t)
{
	int sock;
	char arg[128];
	int ret;
	char *tmp;

	/* TODO: I need to check if some threat fields are missing */

	DPRINTF("Connecting to the sensor...");
	
	sock = tcp_connect(s);
	if(sock == 0) {
		fprintf(stderr, "connection to sensor failed\n");
		return 0;
	} else
		DPRINTF("done\n");

	//sock = 1;

	/* first send the password */
	ret = readline(sock, arg, 127);
	if(ret <= 0) {
		fprintf(stderr, "Error wile executing readline\n");
		goto err;
	} else
		DPRINTF("%d: %s",ret, arg);

	ret = do_request_response(sock, s->password, NULL);
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

	tmp = prepare_msg(t->msg);
	if(tmp == NULL)
		goto err;

	ret = do_request_response(sock, "MSG", tmp);
	free(tmp);
	if(!ret)
		goto err;

	uint_to_str(arg, t->severity);
	ret = do_request_response(sock, "SVRTY", arg);
	if(!ret)
		goto err;

	uint_to_str(arg, t->length);
	if((ret = send_command(sock, "PAYLOAD", arg)) <= 0) {
		fprintf(stderr, "Unable to send PAYLOAD command\n");
		goto err;
	} else {
		if(check_reply(sock,"ADD PAYLOAD") == 0)
			goto err;
	}

	if((ret = send_payload(sock, t)) <= 0) {
		fprintf(stderr,"Unable to send the Payload data\n");
		goto err;
	}

	ret = do_request_response(sock, "SUBMIT", NULL);
	if(!ret)
		goto err;

	if((ret = send_command(sock, "QUIT", NULL)) <= 0) {
		fprintf(stderr, "Unable to send QUIT command");
		goto err;
	}

	close(sock);
	return 1;

err:
	close(sock);
	return 0;
}
