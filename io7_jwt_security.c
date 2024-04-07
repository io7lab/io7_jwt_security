#include "config.h"
#include <stdio.h>
#include <string.h>
#include "mosquitto_broker.h"
#include "mosquitto_plugin.h"
#include "mosquitto.h"
#include "mqtt_protocol.h"

static mosquitto_plugin_id_t *mosq_pid = NULL;
char topic_buffer[100];

int match_topic(const char *sub) {
    // check if the sub is in the pattern : "iot3/+/evt/.*"

    strcpy(topic_buffer, sub);
    strtok(topic_buffer, "/");
    char* devid = strtok(NULL, "/");
    char* evt = strtok(NULL, "/");
	UNUSED(devid);

    if (!strcmp(topic_buffer, "iot3") && !strcmp(evt, "evt")) {
            return MOSQ_ERR_SUCCESS;
    } else {
            return MOSQ_ERR_ACL_DENIED;
    }
}

static int acl_check_callback(int event, void *event_data, void *userdata) {
	UNUSED(event);
	UNUSED(userdata);
	struct mosquitto_evt_acl_check *ed = event_data;

	if (ed->access == MOSQ_ACL_WRITE) {
		// this plugin doesn't allow publishing at all
		mosquitto_log_printf(MOSQ_LOG_INFO, "Publishing is not allowed\n");
		return MOSQ_ERR_ACL_DENIED;
	} else  if (match_topic(ed->topic) != MOSQ_ERR_SUCCESS) {
		mosquitto_log_printf(MOSQ_LOG_INFO, "Not authorized for (%s)\n", ed->topic);
		return MOSQ_ERR_ACL_DENIED;
	}

	if (ed->access == MOSQ_ACL_SUBSCRIBE || ed->access == MOSQ_ACL_READ || ed->access == MOSQ_ACL_UNSUBSCRIBE) {
		return MOSQ_ERR_SUCCESS;
	} else {
		return MOSQ_ERR_PLUGIN_DEFER;
	}
}

static int basic_auth_callback(int event, void *event_data, void *userdata)
{
	struct mosquitto_evt_basic_auth *ed = event_data;
	const char *ip_address;

	UNUSED(event);
	UNUSED(userdata);
	printf("\nBASIC AUTH PASS %s\n", ed->password);

	ip_address = mosquitto_client_address(ed->client);
	if(!strcmp(ip_address, "127.0.0.1")){
		/* Only allow connections from localhost */
		mosquitto_log_printf(MOSQ_LOG_INFO, "\nYUP Hi %s\n", ed->username);
		return MOSQ_ERR_SUCCESS;
	}else{
		return MOSQ_ERR_AUTH;
	}
}

int mosquitto_plugin_version(int supported_version_count, const int *supported_versions)
{
	int i;

	for(i=0; i<supported_version_count; i++){
		if(supported_versions[i] == 5){
			return 5;
		}
	}
	return -1;
}

int mosquitto_plugin_init(mosquitto_plugin_id_t *identifier, void **user_data, struct mosquitto_opt *opts, int opt_count)
{
	UNUSED(user_data);
	UNUSED(opts);
	UNUSED(opt_count);

	mosq_pid = identifier;
	int rc = mosquitto_callback_register(mosq_pid, MOSQ_EVT_ACL_CHECK, acl_check_callback, NULL, NULL);
	UNUSED(rc);
	return mosquitto_callback_register(mosq_pid, MOSQ_EVT_BASIC_AUTH, basic_auth_callback, NULL, NULL);
}

int mosquitto_plugin_cleanup(void *user_data, struct mosquitto_opt *opts, int opt_count)
{
	UNUSED(user_data);
	UNUSED(opts);
	UNUSED(opt_count);

	int rc = mosquitto_callback_unregister(mosq_pid, MOSQ_EVT_ACL_CHECK, acl_check_callback, NULL);
	UNUSED(rc);
	return mosquitto_callback_unregister(mosq_pid, MOSQ_EVT_BASIC_AUTH, basic_auth_callback, NULL);
}
