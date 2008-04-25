#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <search.h>
#include <ctype.h>

#include "utils.h"
#include "agent_contact.h"
#include "alert.h"

typedef struct _ProtocolEntry {
	char *command;
/*
 * Does the command an alert struct?
 * If yes, then we have to make sure the needed memory is allocated.
 */
	int need_alert;
/*
 * Does the command make use of an argument ?
 * 1 means YES, 0 means NO, 2 means MAYBE
 */
	int need_arg;

	int (*handler)(int sock, Alert *, char *);
} ProtocolEntry;

#define RST		0
#define SUBMIT		1
#define QUIT		2
#define PROTO		3
#define SRC_ADDR	4
#define DST_ADDR	5
#define MSG		6
#define SVRTY		7
#define PAYLOAD		8
#define HELP		9
#define PRINT		10

#define MAX_COMMAND 11

static const char *proto_usage[] = {
/*0*/	"RST\n\tClear all alert data.\n",
/*1*/	"SUBMIT\n\tSubmit the created alert.\n",
/*2*/	"QUIT\n\tExit Alert Receiver.\n",
/*3*/	"PROTO <protocol-number>\n\t Specify the threat's connection protocol "
	"(see /etc/protocol).\n",
/*4*/	"SRC_ADDR <IP>:<PORT>\n\t Specify the source address of the suspicious "
	"data.\n",
/*5*/	"DST_ADDR <IP>:<PORT>\n\t Specify the destination address of the "
	"suspicious data.\n",
/*6*/	"MSG <message>\n\t Message describing the threat. If it is more than "
	"one word, use quotes.\n",
/*7*/	"SVRTY 1-4\n\t Rank the severity of the threat. The highest is 1.\n",
/*8*/	"PAYLOAD <base64_encrypted_data>\n\t Adds the suspicious data payload "
	"to the alert.\n",
/*9*/	"HELP [<command>]\n\tThe HELP command gives help info.\n",
/*10*/  "PRINT\n\tPrint the currently supplied alert data\n"
};

static int new_alrt(Alert **ap);
static int exec_submit(int sock, Alert **ap);
static int exec_quit(int sock, Alert *p);

static int exec_proto(int sock, Alert *a, char *str);
static int exec_src_addr(int sock, Alert *a, char *str);
static int exec_dst_addr(int sock, Alert *a, char *str);
static int exec_msg(int sock, Alert *a, char *str);
static int exec_svrty(int sock, Alert *a, char *str);
static int exec_payload(int sock, Alert *a, char *str);
static int exec_help(int sock, Alert *a, char *str);
static int exec_print(int socket, Alert *a, char *str);

static ProtocolEntry proto_table[] = {
/*0*/	{"RST",		0,	0,	NULL},
/*1*/	{"SUBMIT",	1,	0,	NULL},
/*2*/	{"QUIT",	0,	0,	NULL},
/*3*/	{"PROTO",	1,	1,	exec_proto},
/*4*/	{"SRC_ADDR",	1,	1,	exec_src_addr},
/*5*/	{"DST_ADDR",	1,	1,	exec_dst_addr},
/*6*/	{"MSG",		1,	1,	exec_msg},
/*7*/	{"SVRTY",	1,	1,	exec_svrty},
/*8*/	{"PAYLOAD",	1,	1,	exec_payload},
/*9*/	{"HELP",	0,	2,	exec_help},
/*10*/  {"PRINT",	1,	0,	exec_print}
};

/*
 * Function: command_search(char *)
 *
 * Purpose: Searches the protocol table for a command with the given name.
 *
 * Arguments: command=> A string with the command name
 *
 * Returns: The command entry in the protocol table, if the command is found, 
 *          or NULL if the command is not found;
 */
static const ProtocolEntry *command_search(char *command)
{
	size_t len;
	int i;
	ENTRY e,*ep;

	len = strlen(command);
	for(i = 0; i < len; i++)
		command[i] = toupper(command[i]);

	e.key = command;
	ep = hsearch(e, FIND);

	return (ep) ? ep->data : NULL;
}

/*
 * Function: proto_reply(int, const char *)
 *
 * Purpose: Reply to a client command
 *
 * Arguments: sock=> The connection socket
 *            msg=> the reply message
 *
 * Returns:  0 => on success, -1 => if an error occurs
 */
static int proto_reply(int fd, const char *msg)
{
	size_t len;

	len = strlen(msg);
	if(writen(fd, msg, len) == -1) {
		DPRINTF("Error while writing...\n");
		return -1;
	}

	return 0;
}

inline void free_alrt(Alert *a)
{
	if(a->data)
		free(a->data);
	if(a->msg)
		free(a->msg);
	free(a);
}

/*
 * Function: new_alrt(Alert **)
 *
 * Purpose: Create a new alert
 *
 * Arguments: ap=> Pointer to point to the Alert struct that will be created
 *
 * Returns:  1=> success, -1=> if an internal error occurs
 */
static int new_alrt(Alert **ap)
{
	if(*ap != NULL) {
		/* free any allocated field data */
		if((*ap)->data)
			free((*ap)->data);
		if((*ap)->msg)
			free((*ap)->msg);
		/* zero the alert */
		memset(*ap, '\0', sizeof(Alert));
	} else {
		*ap = calloc(1, sizeof(Alert));
		if(*ap == NULL) {
			DPRINTF("memory allocating problem");
			return -1;
		}
	}
	return 1;
}

/*
 * Function: func_submit(int, Alert **ap)
 *
 * Purpose: Execute a SUBMIT command
 *
 * Arguments: sock => the socket of the connection (needed for replying)
 *            ap=> A pointer to a Alert struct pointer
 *
 * Returns:  1=> Success, 0=> Failure, -1=> Internal Error
 */
static int exec_submit(int sock, Alert **ap)
{
	/* check SRC_ADDRESS */
	if((*ap)->addr.s_port == 0) {
		if(proto_reply(sock, "ERROR: Source address is missing. "
				"Please run SRC_ADDR command\n")) return -1;
		return 0;
	}

	/* check DST_ADDRESS */
	if((*ap)->addr.d_port == 0) {
		if(proto_reply(sock, "ERROR: Destination address is missing. "
				"Please run SRC_ADDR command\n")) return -1;
		return 0;
	}

	/* check PROTOCOL */
	if((*ap)->proto == 0) {
		if(proto_reply(sock, "ERROR: Connection protocol is missing. "
				"Please run PROTO command\n")) return -1;
		return 0;
	}

	if((*ap)->severity == 0)
		(*ap)->severity = 1;

	/* the other Alert fields are optional*/

	if(push_alert(*ap) == 0)
		return -1;

	/* detach the alert */
	*ap = NULL;

	return 1;
}

/*
 * Function: exec_quit(int, Alert *)
 *
 * Purpose: Execute a QUIT command
 *
 * Arguments: sock=> the socket of the connection
 *            a=> A pointer pointing to the Alert struct currently used
 *
 * Returns:  1=> Success, -1=> Internal Error
 */

static int exec_quit(int sock, Alert *a)
{
	if(a != NULL)
		free_alrt(a);
	
	if(proto_reply(sock, "Quiting...\n"))
		return -1;

	return 1;
}

/*
 * Function:exec_proto(int, Alert *, char *)
 *
 * Purpose: Execute a PROTO command
 *
 * Arguments: sock=> the socket of the connection with the client
 *            a=> A pointer to the Alert struct currently used
 *            arg=> The argument supplied for this command
 *
 * Returns: 1=> Success, 0=> Failure, -1=> Internal Error
 */

static int exec_proto(int sock, Alert *a, char *arg)
{
	int proto;

	proto = str2num(arg);
	if(proto < 0) {
		if(proto_reply(sock, "ERROR: Supplied protocol does not seem "
					"to be a natural number at all\n"))
			return -1;
		return 0;
	} else if (proto == 0 || proto > 255) {
		if(proto_reply(sock, "ERROR: Valide protocol numbers: 1-255\n"))
			return -1;
		return 0;
	}

	a->proto = proto;
	return 1;
}

/*
 * Function: exec_src_addr(int, Alert *, char *)
 *
 * Purpose: Execute a SRC_ADDR command
 *
 * Arguments: sock=> the socket of the connection with the client
 *            a=> A pointer to the Alert struct currently used
 *            arg=> The argument supplied for this command
 *
 * Returns: 1=> Success, 0=> Failure, -1=> Internal Error
 */
static int exec_src_addr(int sock, Alert *a, char *str)
{
	unsigned short port;
	struct in_addr addr;

	if(addrtok(str, &addr, &port) == 0) {
		if(proto_reply(sock, "ERROR: Argument is not in the IP:Port "
					"format.\n"))
			return -1;
		return 0;
	}

	a->addr.s_port = port;
	a->addr.s_addr = (u_int32_t) addr.s_addr;

	return 1;
}

/*
 * Function: exec_dst_addr(int, Alert *, char *)
 *
 * Purpose: Execute a DST_ADDRESS command
 *
 * Arguments: sock=> the socket of the connection with the client
 *            a=> A pointer to the Alert struct currently used
 *            arg=> The argument supplied for this command
 *
 * Returns: 1=> Success, 0=> Failure, -1=> Internal Error
 */
static int exec_dst_addr(int sock, Alert *a, char *str)
{
	unsigned short port;
	struct in_addr addr;


	if(addrtok(str, &addr, &port) == 0) {
		if(proto_reply(sock, "ERROR: Argument is not in the IP:Port "
					"format.\n"))
			return -1;
		return 0;
	}

	a->addr.d_port = port;
	a->addr.d_addr = (u_int32_t) addr.s_addr;

	return 1;
}

/*
 * Function:exec_msg(int, Alert *, char *)
 *
 * Purpose: Execute a MSG command
 *
 * Arguments: sock=> the socket of the connection with the client
 *            a=> A pointer to the Alert struct currently used
 *            arg=> The argument supplied for this command
 *
 * Returns: 1=> Success, 0=> Failure, -1=> Internal Error
 */
static int exec_msg(int sock, Alert *a, char *arg)
{
	if(a->msg)
		free(a->msg);

	a->msg = strdup(arg);
	if(a->msg == NULL) {
		perror("strdup");
		return -1;
	}
	return 1;
}

/*
 * Function:exec_svrty(int, Alert *, char *)
 *
 * Purpose: Execute a SVRTY command
 *
 * Arguments: sock=> the socket of the connection with the client
 *            a=> A pointer to the Alert struct currently used
 *            arg=> The argument supplied for this command
 *
 * Returns: 1=> Success, 0=> Failure, -1=> Internal Error
 */
static int exec_svrty(int sock, Alert *a, char *arg)
{
	int severity;

	severity = str2num(arg);
	DPRINTF("severity %d\n", severity);

	if(severity < 0) {
		if(proto_reply(sock, "ERROR: SEVERITY's argument must be a "
					"natural number\n")) return -1;
		return 0;
	} else if(severity == 0 || severity > 4) {
		if(proto_reply(sock, "ERROR: SEVERITY must be between 1 - 4\n"))
			return -1;
		return 0;
	}

	DPRINTF("severity = %d\n", severity);
	a->severity = severity;
	return 1;
}

/*
 * Function:exec_payload(int, Alert *, char *)
 *
 * Purpose: Execute a PAYLOAD command
 *
 * Arguments: sock=> the socket of the connection with the client
 *            a=> A pointer to the Alert struct currently used
 *            arg=> The argument supplied for this command
 *
 * Returns: 1=> Success, 0=> Failure, -1=> Internal Error
 */
static int exec_payload(int sock, Alert *a, char *arg)
{
	DPRINTF("Not Implemented yet\n");
	return 1;
}

/*
 * Function:exec_help(int, Alert *, char *)
 *
 * Purpose: Execute a HELP command
 *
 * Arguments: sock=> the socket of the connection with the client
 *            a=> A pointer to the Alert struct currently used
 *            arg=> The argument supplied for this command
 *
 * Returns: 0=> Normal Exit, -1=> Internal Error
 */
static int exec_help(int sock, Alert *a, char *arg)
{
	if(arg) {
		const ProtocolEntry *ep;

		ep = command_search(arg);
		if(ep == NULL) {
			if(proto_reply(sock, "ERROR: HELP argument is not a "
						"valid command\n"))
				return -1;
		} else {
			size_t i;
			/* 
			 * this will return the index in the proto table
			 */
			i = ep - proto_table;
			if(proto_reply(sock, proto_usage[i]))
				return -1;
		}
	} else {
		int i;
		size_t len;
		char *delim;

		if(proto_reply(sock, "HELP <command>.\nValid Commands:\n"))
			return -1;

		for(i = 0; i < MAX_COMMAND; i++) {
			if(proto_reply(sock, proto_table[i].command))
				return -1;

			len = strlen(proto_table[i].command);
			if(i%4 == 3)
				delim = "\n";
			else
				delim = (len < 8) ? "\t\t" : "\t";

			if(proto_reply(sock, delim))
				return -1;
		}

		if(proto_reply(sock, "\n"))
			return -1;
	}

	return 0;
}

/*
 * Function:exec_print(int, Alert *, char *)
 *
 * Purpose: Execute a PRINT command
 *
 * Arguments: sock=> the socket of the connection with the client
 *            a=> A pointer to the Alert struct currently used
 *            arg=> The argument supplied for this command
 *
 * Returns:  0=> Normal Exit, -1=> Internal Error
 */
static int exec_print(int sock, Alert *a, char *arg)
{
	char buf[75];
	struct in_addr tmp_addr;
	int ret;

	if(proto_reply(sock, "\nCurrent Alert Data\n")) return -1;

	tmp_addr.s_addr = a->addr.s_addr;
	sprintf(buf, "Source Address:\t%s\n",inet_ntoa(tmp_addr));
	if(proto_reply(sock, buf)) return -1;

	sprintf(buf, "Source Port:\t%d\n", a->addr.s_port);
	if(proto_reply(sock, buf)) return -1;

	tmp_addr.s_addr = a->addr.d_addr;
	sprintf(buf, "Dest. Address:\t%s\n",inet_ntoa(tmp_addr));
	if(proto_reply(sock, buf)) return -1;

	sprintf(buf, "Dest. Port:\t%d\n", a->addr.d_port);
	if(proto_reply(sock, buf)) return -1;

	sprintf(buf, "Protocol Num.:\t%d\n", a->proto);
	if(proto_reply(sock, buf)) return -1;

	sprintf(buf, "Severity:\t%d\n", a->severity);
	if(proto_reply(sock, buf)) return -1;

	ret = snprintf(buf, 70, "Message:\t%s\n", a->msg);
	if(buf[69] == '\0') {
		buf[69] = buf[70] = buf[71] = '.';
		buf[72] = '\n';
		buf[73] = '\0';
	}
	if(proto_reply(sock, buf)) return -1;

	sprintf(buf, "Payload Length:\t%d\n", a->length);
	if(proto_reply(sock, buf)) return -1;

	return 0;
}

/*
 * Function: line_process(char *, char **, char **)
 *
 * Purpose: Process a line and split it to arguments. Only 2 arguments are 
 *          valide and the second is optional. The first argument is always one
 *          word. The second can be more if it is icluded in (')s or (")s
 *
 * Arguments: line=> A string containing a line
 *            arg1=> On successful return it should contain the first argument
 *            arg2=> On successful return it should contain the second argument
 *                   or NULL if the latter does not exist
 *
 * Returns:  1=> Success
 *           0=> The line is empty (contains only spaces), 
 *          -1=> The first arg is not valid (valid char [A-Z],[a-z],[0-9],_)
 *          -2=> Line is not in a proper format
 */
static int line_process(char *line, char **arg1, char **arg2)
{
	char *p;
	char quote;

	for(p = line; isspace(*p); p++)
		;

	if(*p == '\0') /* line contains only spaces */
		return 0;

	/* first argument */
	*arg1 = p;
	for(;isalnum(*p) || (*p == '_') ;p++)
		;

	if(*arg1 == p) /* arg1 is missing */ {
		DPRINTF("Arg1 missing\n");
		return -1;
	}

	if(!isspace(*p)) /* garbage */ {
		return -2;
	}else
		*p++ = 0;

	for(; isspace(*p); p++)
		;

	/* second argument */
	*arg2 = p;
	if(*p == '"' || *p == '\'') { /* We have quotes around arg2 */
		(*arg2)++; /*the quotes are not part of the arg2*/
		quote = *p;

		do{
			p++;
		} while(*p != 0 && *p != quote);

		if(*p == '\0') /* no ending quote*/
			return -2;
		else
			*p++ = '\0';
	} else {
		for(; isalnum(*p) || ispunct(*p); p++)
			;
	}

	/* is arg2 present ? */
	if(*arg2 == p) {
		*arg2 = NULL;
		return 1; /* arg2 is optional */
	}

	if(isspace(*p))
		*p++ = 0;

	for(; isspace(*p); p++)
		;

	if(*p != '\0') /* garbage */
		return -2;

	return 1;
}

/*
 * Function: protocol_decode(int)
 *
 * Purpose: The function implements the alert submission protocol. It decodes
 *          the commands supplied by the client and involves the proper handler.
 *
 * Arguments: sock=> The socket of the connection. Needed to communicate with
 *                   the client.
 */
static void protocol_decode(int sock)
{
	char buf[256],*command, *arg;
	int ret, code;
	ssize_t numbytes;
	Alert *a = NULL;
	int longline = 0;
	const ProtocolEntry *ep;

	for(;;) {
		numbytes = readline(sock, buf, 256);
		if(numbytes <= 0) {
			DPRINTF("Error while reading\n");
			return;
		}

		if(buf[numbytes - 1] != '\n') {
			longline = 1;
			continue;
		}

		if(longline) {
			longline = 0;
			if(proto_reply(sock, "ERROR: Line too long...\n"))
				return;
			continue;
		}

		ret = line_process(buf, &command, &arg);
		if(ret == 0) /* ignore the line */
			continue;

		if(ret < 0) {
			if(proto_reply(sock, "ERROR: Acceptable line: "
						"<command> [arg]\n"))
				return;
			continue;
		}

		ep = command_search(command);
		if(ep == NULL) {
			if(proto_reply(sock, "ERROR: Unknown command\n"))
				return;
			continue;
		}

		/* check if argument is present and/or needed */
		if((ep->need_arg == 1) && (arg == NULL)) {
			if(proto_reply(sock, "ERROR: This command needs an "
						"argument\n"))
				return;
			continue;
		}
		if((ep->need_arg == 0) && (arg != NULL)) {
			if(proto_reply(sock, "ERROR: This command does not use "
						"any arguments\n"))
				return;
			continue;
		}

		/* Check if the command needs to create a new alert */
		if((ep->need_alert == 1) && (a == NULL)) {
			if(new_alrt(&a) == -1)
		       		goto internal_error;
		}

	/*
	 * Everithing seems OK, execute the command handler
	 */
		code = ep - proto_table; /* proto table index */
		if(ep->handler != NULL) {
			ret = ep->handler(sock, a, arg);
		} else if(code == RST) {
			ret = new_alrt(&a);
		} else if(code == SUBMIT) {
			ret = exec_submit(sock, &a);
		} else if(code == QUIT) {
			ret = exec_quit(sock, a);
			return;
		}

		if(ret == 1)
			if(proto_reply(sock, "OK\n"))
				ret = -1;

		if(ret == -1)
			goto internal_error;
			
	}

internal_error:
	proto_reply(sock, "ERROR: Internal Server Error\n");
	return;
}

void *alert_receiver(int sock)
{
	char buf[64];
	ssize_t numbytes;
	int longline = 0;

	if(proto_reply(sock, "Please supply the Password:\n"))
		goto end;

again:
	/* read the password */
	numbytes = readline(sock, buf, 64);
	if(numbytes <= 0) {
		fprintf(stderr, "Error while reading...\n");
		goto end;
	}

	if(buf[numbytes - 1]  != '\n') {
		/* very long line. Call readline again to get it all */
		longline = 1;
		goto again;
	}

	if(longline) {
		proto_reply(sock, "I request a password, "
				"you send back malakies :-(\n");
		goto end;
	}

	/* remove the new line in the end of the password */
	buf[numbytes - 1] = '\0';

	/* fuck you microsoft */
	if((numbytes > 1) && (buf[numbytes - 2] == '\r'))
		buf[numbytes -2] = '\0';


	if(!check_password(buf)) {
		DPRINTF("Autentication Failed\n");
		proto_reply(sock, "Authentication Failed\n");
		goto end;
	} else {
		DPRINTF("Autentication OK\n");
		if(proto_reply(sock, "OK\n"))
			goto end;
	}

	protocol_decode(sock);
end:
	DPRINTF("Closing the socket\n");
	close(sock);
	return NULL;
}

void init_alert_receiver(void)
{
	ENTRY e, *ep;
	int i;

	hcreate(MAX_COMMAND);
	for(i = 0; i < MAX_COMMAND; i++) {
		e.key = proto_table[i].command;
		e.data = &proto_table[i];
		ep = hsearch(e, ENTER);
		if(ep == NULL) {
			fprintf(stderr, "Alert Receiver initialization error");
			exit(1);
		}
	}
}
