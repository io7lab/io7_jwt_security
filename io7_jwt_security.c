#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mosquitto_broker.h"
#include "mosquitto_plugin.h"
#include "mosquitto.h"
#include "mqtt_protocol.h"
#include "io7_jwt_util.h"

static mosquitto_plugin_id_t *mosq_pid = NULL;
char topic_buffer[100];

int match_topic(const char *sub) {
    // check if the sub is in the pattern : "iot3/+/evt/.*"

    strcpy(topic_buffer, sub);
    strtok(topic_buffer, "/");
    char* devid = strtok(NULL, "/");
    char* evt = strtok(NULL, "/");
	UNUSED(devid);

	if (strcmp(topic_buffer, "iot3")) {		// if the first token is not "iot3"
		return MOSQ_ERR_ACL_DENIED;
	}
	if (!strcmp(evt, "evt"))  { 				// if the third token is "evt"
		return MOSQ_ERR_SUCCESS;
	}

	char* device = strtok(NULL, "/");
	char* meta = strtok(NULL, "/");
	if (!strcmp(evt, "mgmt") && !strcmp(device, "device") && !strcmp(meta, "meta") ) {
		// if the third token is "mgmt", the fourth token is "device", and the fifth token is "meta"
		return MOSQ_ERR_SUCCESS;
	}

	return MOSQ_ERR_ACL_DENIED;
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

static int basic_auth_callback(int event, void *event_data, void *userdata) {
	struct mosquitto_evt_basic_auth *ed = event_data;

	UNUSED(event);
	UNUSED(userdata);

	int rc =  validateToken(ed->password);

	if(rc) {
		/* Only allow connections from localhost */
		return MOSQ_ERR_SUCCESS;
	}else{
		return MOSQ_ERR_AUTH;
	}
}

int mosquitto_plugin_version(int supported_version_count, const int *supported_versions) {
	int i;

	for(i=0; i<supported_version_count; i++){
		if(supported_versions[i] == 5){
			return 5;
		}
	}
	return -1;
}

int mosquitto_plugin_init(mosquitto_plugin_id_t *identifier, void **user_data, struct mosquitto_opt *opts, int opt_count) {
	UNUSED(user_data);
	static char *config_file = NULL;

	// get the config file name from the options
	for(int i=0; i<opt_count; i++){
		if(!strcasecmp(opts[i].key, "config_file")){
			config_file = mosquitto_strdup(opts[i].value);
			mosquitto_log_printf(MOSQ_LOG_INFO, "io7 jwt security plugin: config file is %s", config_file);
			break;
		}
	}

	jwt_conn_config_init(&conn_info, config_file);

	mosq_pid = identifier;
	int rc = mosquitto_callback_register(mosq_pid, MOSQ_EVT_ACL_CHECK, acl_check_callback, NULL, NULL);
	if (rc != MOSQ_ERR_SUCCESS) {
		mosquitto_log_printf(MOSQ_LOG_ERR, "IO7 JWT ACL Callback Loading failed\n");
		return rc;
	}
	rc = mosquitto_callback_register(mosq_pid, MOSQ_EVT_BASIC_AUTH, basic_auth_callback, NULL, NULL);
	if (rc != MOSQ_ERR_SUCCESS) {
		mosquitto_log_printf(MOSQ_LOG_ERR, "IO7 JWT AUTH Callback Loading failed\n");
		return rc;
	}
	return MOSQ_ERR_SUCCESS;
}

int mosquitto_plugin_cleanup(void *user_data, struct mosquitto_opt *opts, int opt_count) {
	UNUSED(user_data);
	UNUSED(opts);
	UNUSED(opt_count);

	int rc = mosquitto_callback_unregister(mosq_pid, MOSQ_EVT_ACL_CHECK, acl_check_callback, NULL);
	if (rc != MOSQ_ERR_SUCCESS) {
		mosquitto_log_printf(MOSQ_LOG_ERR, "IO7 JWT ACL Callback Unloading failed\n");
		return rc;
	}
	rc = mosquitto_callback_unregister(mosq_pid, MOSQ_EVT_BASIC_AUTH, basic_auth_callback, NULL);
	if (rc != MOSQ_ERR_SUCCESS) {
		mosquitto_log_printf(MOSQ_LOG_ERR, "IO7 JWT AUTH Callback Unloading failed\n");
		return rc;
	}

	regex_free();
	return MOSQ_ERR_SUCCESS;
}
