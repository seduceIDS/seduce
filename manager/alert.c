/* 
 * This file contains functions to deal with alerts
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <libprelude/prelude.h>

#include "alert.h"
#include "errors.h"

#define ANALYZER_CLASS "NIDS"
#define ANALYZER_MODEL "SEDUCE"
#define ANALYZER_MANUFACTURER "http://rainbow.cs.unipi.gr/projects/seduce"

#define DEFAULT_ANALYZER_NAME "seduce"
#define VERSION "0.1"

static AlertList alertlist;

static prelude_client_t *client = NULL; /* Prelude Client Pointer */
static char overflow_msg[]="A buffer overflow was detected";


/*
 * What Is the impact of the detected threat?
 * Since we deal with buffer overflows, we set the impact to be always high
 */
static int fill_threat_impact(idmef_alert_t *alert)
{
        int ret;
        idmef_impact_t *impact;
        idmef_assessment_t *assessment;
        idmef_impact_severity_t severity;
        
        ret = idmef_alert_new_assessment(alert, &assessment);
        if ( ret < 0 )
                return ret;

        ret = idmef_assessment_new_impact(assessment, &impact);
        if ( ret < 0 )
                return ret;

        severity = IDMEF_IMPACT_SEVERITY_HIGH;

        idmef_impact_set_severity(impact, severity);

        return 0;
}

static int fill_source_target(AlertNode *p, idmef_alert_t *alert)
{
        int ret;
        idmef_node_t *node;
        idmef_source_t *source;
        idmef_target_t *target;
        idmef_address_t *address;
        idmef_service_t *service;
        prelude_string_t *string;
	struct in_addr tmp_ip;
        static char saddr[128], daddr[128];

        if ( !p )
            return 0;

        ret = idmef_alert_new_source(alert, &source, -1);
        if ( ret < 0 )
                return ret;

        ret = idmef_source_new_service(source, &service);
        if ( ret < 0 )
                return ret;

        idmef_service_set_port(service, p->addr.s_port);
        
/*        idmef_service_set_ip_version(service, IP_VER(p->iph)); */
        idmef_service_set_iana_protocol_number(service, p->proto);
        
        ret = idmef_source_new_node(source, &node);
        if ( ret < 0 )
                return ret;

        ret = idmef_node_new_address(node, &address, -1);
        if ( ret < 0 )
                return ret;

        ret = idmef_address_new_address(address, &string);
        if ( ret < 0 )
                return ret;
        tmp_ip.s_addr = p->addr.s_addr;
        snprintf(saddr, sizeof(saddr), "%s", inet_ntoa(tmp_ip));
        prelude_string_set_ref(string, saddr);

        ret = idmef_alert_new_target(alert, &target, -1);
        if ( ret < 0 )
                return ret;

        ret = idmef_target_new_service(target, &service);
        if ( ! ret < 0 )
                return ret;
        
        idmef_service_set_port(service, p->addr.d_port);
        
/*        idmef_service_set_ip_version(service, IP_VER(p->iph)); */
        idmef_service_set_iana_protocol_number(service,p->proto);
        
        ret = idmef_target_new_node(target, &node);
        if ( ret < 0 )
                return ret;
        
        ret = idmef_node_new_address(node, &address, -1);
        if ( ret < 0 )
                return ret;
        
        ret = idmef_address_new_address(address, &string);
        if ( ret < 0 )
                return ret;

        tmp_ip.s_addr = p->addr.d_addr;        
        snprintf(daddr, sizeof(daddr), "%s", inet_ntoa(tmp_ip));
        prelude_string_set_ref(string, daddr);
        
        return 0;
}


static int add_int_data(idmef_alert_t *alert, const char *meaning,
			uint32_t data)
{
        int ret;
        prelude_string_t *str;
        idmef_additional_data_t *ad;
       
        ret = idmef_alert_new_additional_data(alert, &ad, -1);
        if ( ret < 0 )
                return ret;
        
        idmef_additional_data_set_integer(ad, data);

        ret = idmef_additional_data_new_meaning(ad, &str);
        if ( ret < 0 ) {
                errno_cont("%s: error creating additional-data meaning: %s.\n",
                             prelude_strsource(ret), prelude_strerror(ret));
                return -1;
        }
        
        ret = prelude_string_set_ref(str, meaning);
        if ( ret < 0 ) {
                errno_cont("%s: error setting integer data meaning: %s.\n",
                             prelude_strsource(ret), prelude_strerror(ret));
                return -1;
        }
        
        return 0;
}

static int add_byte_data(idmef_alert_t *alert, const char *meaning,
				const unsigned char *data, size_t size)
{
        int ret;
        prelude_string_t *str;
        idmef_additional_data_t *ad;

        if ( ! data || ! size )
                return 0;
        
        ret = idmef_alert_new_additional_data(alert, &ad, -1);
        if ( ret < 0 )
                return ret;

        ret = idmef_additional_data_set_byte_string_ref(ad, data, size);
        if ( ret < 0 ) {
                errno_cont("%s: error setting byte string data: %s.\n",
                             prelude_strsource(ret), prelude_strerror(ret));
                return -1;
        }

        ret = idmef_additional_data_new_meaning(ad, &str);
        if ( ret < 0 ) {
                errno_cont("%s: error creating additional-data meaning: %s.\n",
                             prelude_strsource(ret), prelude_strerror(ret));
                return -1;
        }
        
        ret = prelude_string_set_ref(str, meaning);
        if ( ret < 0 ) {
                errno_cont("%s: error setting byte string data meaning: %s.\n",
                             prelude_strsource(ret), prelude_strerror(ret));
        }
                
        return -1;
}

static int fill_data(AlertNode *p, idmef_alert_t *alert)
{

        if ( !p )
            return 0;
        
        add_int_data(alert, "ip_proto", p->proto);
#if 0
        if ( p->proto == IPPROTO_TCP )
                add_int_data(alert, "tcp_len", p->length);
        else /* p->proto == IPPROTO_UDP */
                add_int_data(alert, "udp_len", p->length);
#endif
        add_byte_data(alert, "payload", p->data, p->length);
        
        return 0;
}

static void send_alert(AlertNode *p)
{
        int ret;
        idmef_time_t *time;
        idmef_alert_t *alert;
        prelude_string_t *str;
        idmef_message_t *idmef;
        idmef_classification_t *class;

        if ( !p )
            return;

        ret = idmef_message_new(&idmef);
        if ( ret < 0 )
                return;

        ret = idmef_message_new_alert(idmef, &alert);
        if ( ret < 0 )
                goto err;

        ret = idmef_alert_new_classification(alert, &class);
        if ( ret < 0 )
                goto err;

        ret = idmef_classification_new_text(class, &str);
        if ( ret < 0 )
                goto err;

        prelude_string_set_ref(str, overflow_msg);

        ret = fill_threat_impact(alert);
        if ( ret < 0 )
                goto err;

        ret = fill_source_target(p, alert);
        if ( ret < 0 )
                goto err;

        ret = fill_data(p, alert); 
        if ( ret < 0 )
                goto err;

       /* TODO: I need to fix the times.
	* From the IDMEF RFC:
	*
	*	The CreateTime Class
	* The CreateTime class is used to indicate the date and time the alert
	* or heartbeat was created by the analyzer.
	*
	* 	The DetectTime Class
	* The DetectTime class is used to indicate the date and time that the
	* event(s) producing an alert was detected by the analyzer.
	*
	* 	The AnalyzerTime Class
	* The AnalyzerTime class is used to indicate the current date and time
	* on the analyzer.
	*/ 

	/*	Detect Time	*/
	/*
        ret = idmef_alert_new_detect_time(alert, &time);
        if ( ret < 0 )
                goto err;*/
	ret = idmef_time_new_from_gettimeofday(&time);
        if ( ret < 0 )
                goto err;
	idmef_alert_set_create_time (alert, time);

        /*	Create Time	*/	
        ret = idmef_time_new_from_gettimeofday(&time);
        if ( ret < 0 )
                goto err; 
        idmef_alert_set_create_time(alert, time);

	/*	Analyzer Time	*/
	/* Don't need to do this. libprelude will do it
	 *
	ret = idmef_time_new_from_gettimeofday(&time);
        if ( ret < 0 )
                goto err; 
        idmef_alert_set_analyzer_time(alert, time);*/

        idmef_alert_set_analyzer(alert, idmef_analyzer_ref(prelude_client_get_analyzer(client)), 0);
        
	prelude_client_send_idmef(client, idmef);
                
 err:
        idmef_message_destroy(idmef);
}

static int setup_analyzer(idmef_analyzer_t *analyzer)
{
        int ret;
        prelude_string_t *string;

        ret = idmef_analyzer_new_model(analyzer, &string);
        if ( ret < 0 )
                return ret;
        prelude_string_set_constant(string, ANALYZER_MODEL);

	ret = idmef_analyzer_new_class(analyzer, &string);
        if ( ret < 0 )
                return ret;
        prelude_string_set_constant(string, ANALYZER_CLASS);

	ret = idmef_analyzer_new_manufacturer(analyzer, &string);
        if ( ret < 0 ) 
                return ret;
        prelude_string_set_constant(string, ANALYZER_MANUFACTURER);

	ret = idmef_analyzer_new_version(analyzer, &string);
        if ( ret < 0 )
                return ret;
        prelude_string_set_constant(string, VERSION);

        return 0;
}

static void init_prelude(void)
{
        int ret;
        prelude_client_flags_t flags;
        
        ret = prelude_thread_init(NULL);
        if ( ret < 0 )
                errno_abort("%s: Unable to initialize the Prelude thread subsystem: %s.\n",
                           prelude_strsource(ret), prelude_strerror(ret));
        
        ret = prelude_init(NULL, NULL);
        if ( ret < 0 )
                errno_abort("%s: Unable to initialize the Prelude library: %s.\n",
                           prelude_strsource(ret), prelude_strerror(ret));
        
        ret = prelude_client_new(&client, DEFAULT_ANALYZER_NAME);
        if ( ret < 0 )
                errno_abort("%s: Unable to create a prelude client object: %s.\n",
                           prelude_strsource(ret), prelude_strerror(ret));
        
        flags = PRELUDE_CLIENT_FLAGS_ASYNC_SEND|PRELUDE_CLIENT_FLAGS_ASYNC_TIMER;
        ret = prelude_client_set_flags(client, prelude_client_get_flags(client) | flags);
        if ( ret < 0 )
                errno_abort("%s: Unable to set asynchronous send and timer: %s.\n",
                           prelude_strsource(ret), prelude_strerror(ret));
        
        setup_analyzer(prelude_client_get_analyzer(client));
        
        ret = prelude_client_start(client);
        if ( ret < 0 ) {
                if ( prelude_client_is_setup_needed(ret) )
                        prelude_client_print_setup_error(client);

                errno_abort("%s: Unable to initialize prelude client: %s.\n",
                           prelude_strsource(ret), prelude_strerror(ret));
        }
}

void init_alertlist(void)
{
	alertlist.head = alertlist.tail = NULL;
	alertlist.cnt = 0;

	mutex_init (&alertlist.mutex);
	cond_init (&alertlist.empty_cond);

	init_prelude();
}

void pop_alert(void (*func)(AlertNode *))
{
	AlertNode *alert_to_send;

	mutex_lock (&alertlist.mutex);

	while (alertlist.cnt == 0)
		cond_wait (&alertlist.empty_cond, &alertlist.mutex);

	/* Removing the alert */
	alert_to_send = alertlist.head;
	alertlist.head = alertlist.head->next;
	alertlist.cnt--;
	if (alertlist.cnt == 0)
		alertlist.tail = NULL;

	mutex_unlock (&alertlist.mutex);

	/* Execute the function on the alert data*/
	(*func)(alert_to_send);

	free(alert_to_send);
}

int push_alert(struct tuple4 *addr, int proto, unsigned char *data, int length)
{
	AlertNode *new_alert;

	new_alert = malloc(sizeof(AlertNode));
	if (new_alert == NULL) {
		errno_cont("Error in malloc");
		return 0;
	}
	
	new_alert->addr = *addr;
	new_alert->proto = proto;

	if(data) {
		new_alert->data = malloc(length);
		if(new_alert->data)
			memcpy(new_alert->data, data, length);
		else errno_cont("malloc");
	} else
		new_alert->data = NULL;

	new_alert->length = (new_alert->data) ? length : 0;
	new_alert->next = NULL;

	/* Now add it in the alert list */
	mutex_lock (&alertlist.mutex);

	if (alertlist.head == NULL)
		alertlist.head = alertlist.tail = new_alert;
	else {
		alertlist.tail->next = new_alert;
		alertlist.tail = new_alert;
	}

	alertlist.cnt++;
	if (alertlist.cnt == 1)
		cond_signal (&alertlist.empty_cond);

	mutex_unlock (&alertlist.mutex);

	return 1;
}


void *alert_thread(void *params)
{
	for(;;)
		pop_alert(send_alert);
}

#if 0
int main()
{
	struct tuple4 addr;
	char data[] = "Temporary Test Data";

	addr.s_addr = (in_addr_t) inet_addr("192.168.178.4");
	addr.d_addr = (in_addr_t) inet_addr("192.168.178.2");
	addr.s_port = 1024;
	addr.d_port = 80; 

	init_alertlist();

	push_alert(&addr,UDP, data, 19);

	alert_thread(NULL);

	return 0;
}
#endif
