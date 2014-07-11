
#include <stdio.h>
#include <stdarg.h>
#include <string.h>


#include "listener_remote.h"



/******************************************************************************/
/* error management                                                           */
/******************************************************************************/
TLstError* listener_remote_error_new(int code, char* format, ...)
{
	gchar message[1024];
	va_list args;

    va_start(args, format);
    vsnprintf(message, 1024, format, args);
    va_end(args);

	TLstError* err = g_malloc0(sizeof(TLstError));
	if (err == NULL)
		return err;

	err->code = code;
	if (message == NULL)
		return err;

	int len = strlen(message);

	err->message = g_malloc0(len+2);
	g_strlcpy(err->message, message, len+1);

	return err;
}

void listener_remote_error_clean(TLstError* err)
{
	if (err == NULL) return;

	if (err->message != NULL)
		g_free(err->message);

	g_free(err);
}


/******************************************************************************/
/* ZMQ management                                                             */
/******************************************************************************/

/**
 * return : zmq_context
 */
void* listener_remote_init(void)
{
	return zmq_init(1);
}


/**
 * zmq_ctx: zmq contexts to close
 * zmq_sock: zmq socket to close
 */
void  listener_remote_close(void* zmq_ctx, void* zmq_sock)
{
	if (zmq_sock != NULL) zmq_close(zmq_sock);
    if (zmq_ctx != NULL)  zmq_term(zmq_ctx);
}



/**
 *  send a buffer to listener by zmq
 */
TLstError* listener_remote_sendBuffer(void* zmq_sock, const char* buf, int buflen)
{
    int rc = 0;
    zmq_msg_t msg;
	TLstError* err = NULL;

    if (!buf)
        return listener_remote_error_new(-1, "no buffer to send");

        rc = zmq_msg_init_size (&msg, buflen);
        memcpy(zmq_msg_data(&msg), &buf[0], buflen);
        if (rc == 0) {
            rc = zmq_sendmsg(zmq_sock, &msg, ZMQ_NOBLOCK);
            if (rc < 0) {
				err = listener_remote_error_new(-1, "zmq_send failed (%d)", errno);
            }

		 } else err = listener_remote_error_new(-2, "zmq_send failed (%d)", errno);

        zmq_msg_close(&msg);

	return err;
} 


TLstError* listener_remote_sendJSON(void* zmq_sock, json_object* j_root)
{
	char* buf = listener_remote_json_getStr(j_root);
	if (buf)
		return listener_remote_sendBuffer(zmq_sock, buf, strlen(buf));
	else
		return listener_remote_error_new(-1, "JSON build failed");
	return NULL;
}


///////////////////////////////////////////////////////////////////////////////

/**
 * listenerUrl: listener url: "<ip>:<port>"
 * linger: =-1: not init, see ZMQ_LINGER, duree de vie
 * hwm:    =-1: not init, see ZMQ_HWM     size queue
 * return zmq_sock
 */
void* listener_remote_connect(TLstError **err, void* zmq_ctx, const char* listenerUrl, int linger, int64_t hwm)
{
    int rc = 0;
    gboolean bInit = FALSE;
	void* zmq_sock = NULL;

	if (err == NULL)
		return NULL;

    if (!listenerUrl) {
		*err = listener_remote_error_new(-1, "bad listenerUrl");
        return NULL;
    }

    //init socket for com
    if (zmq_ctx == NULL) {
		*err = listener_remote_error_new(-1, "zmq_init failed (%d)", errno);
        return NULL;
    }

    zmq_sock = zmq_socket(zmq_ctx, ZMQ_PUSH);
    if (zmq_sock != NULL) {
        gchar tmp[100];
        g_snprintf(tmp, 100, "tcp://%s", listenerUrl);

    	// "duree de vie des messages au moment du zmq_term()
    	if (linger >= 0)
        	zmq_setsockopt(zmq_sock, ZMQ_LINGER, &linger, sizeof(linger));

    	// size of out queue
    	if (hwm >= 0)
			zmq_setsockopt(zmq_sock, ZMQ_SNDHWM, (uint64_t*) &hwm, sizeof(hwm)); 

        rc = zmq_connect(zmq_sock, tmp);
        if (rc == 0) {
			bInit= TRUE;// good init
		} else *err = listener_remote_error_new(-1, "zmq_connect failed (%d)", errno);
	} else *err = listener_remote_error_new(-1, "zmq_socket failed (%d)", errno);


	if (*err != NULL) {
		listener_remote_closesocket(zmq_sock);	
		bInit = FALSE;
		return NULL;
	}


    // "duree de vie des messages au moment du zmq_term()
    return zmq_sock;
}

void listener_remote_closesocket(void* zmq_sock)
{
	if (zmq_sock != NULL) {
		zmq_close(zmq_sock);
		zmq_sock = NULL;
	}
}




/******************************************************************************/
/* JSON management                                                             */
/******************************************************************************/
struct json_object * listener_remote_json_buildHEADObj(      TLstJSONHeader* msgH);


struct json_object * listener_remote_json_init(TLstJSONHeader* msgH, unsigned char bAllDataSection)
{
	struct json_object *j_root, *j_head, *j_datah, *j_data;

	j_root = listener_remote_json_newSection();
	if (!j_root)
		return NULL;

    //build header
    j_head = listener_remote_json_buildHEADObj(msgH);
	if (j_head) 
		listener_remote_json_addSection(j_root, LST_SECTION_HEAD, j_head);
	else 
		listener_remote_json_clean(j_root);
	
	if (bAllDataSection == TRUE) {
		j_datah = listener_remote_json_newSection();
		if (j_datah) 
			listener_remote_json_addSection(j_root, LST_SECTION_DATAH, j_datah);
		else
			listener_remote_json_clean(j_root);
	
	    j_data = listener_remote_json_newSection();
	    if (j_data)
	        listener_remote_json_addSection(j_root, LST_SECTION_DATAR, j_data);
		else
			listener_remote_json_clean(j_root);
	}

	return j_root;
}



struct json_object * listener_remote_json_buildHEADObj(TLstJSONHeader* msgH)
{
    struct json_object *j_head;

	j_head = listener_remote_json_newSection();
    if (!j_head)
        return NULL;

    if (  (listener_remote_json_addStringToSection(j_head, "SRC_NAME", msgH->action_name) != NULL)
        ||(listener_remote_json_addIntToSection(   j_head, "SRC_ID",   msgH->action_pid) != NULL)
        ||(listener_remote_json_addStringToSection(j_head, "STATUS",   msgH->status) != NULL)
        ||(listener_remote_json_addIntToSection(   j_head, "MSG_ID",   msgH->idmsg) != NULL)
		||(listener_remote_json_addStringToSection(j_head, "CRAWL_ID", msgH->idcrawl) != NULL))  {
        return NULL;
    } else
        return j_head;
}


TLstError*  listener_remote_json_addStringToSection(json_object* j_section, char* key, char* value)
{
	json_object* j_obj;

	if ((key == NULL)||(strlen(key) == 0)) 
		return listener_remote_error_new(-1, "JSON: bad key");
	
	if (value) 
		j_obj  = json_object_new_string(value);
	else 
		j_obj  = json_object_new_string("");

	json_object_object_add(j_section, key, j_obj);

	return NULL;
}


TLstError*  listener_remote_json_addIntToSection(json_object* j_section, char* key, int value)
{
    json_object* j_obj;

    if ((key == NULL)||(strlen(key) == 0))
        return listener_remote_error_new(-1, "JSON: bad key");

    j_obj  = json_object_new_int(value);
    json_object_object_add(j_section, key, j_obj);

    return NULL;
}




TLstError*  listener_remote_json_addSection(json_object* j_root, 
		ELstSection section, json_object* j_section)
{
	gchar c_section[LST_SECTION_max][10] = { "HEAD", "DATAH", "DATAR"};

	if (section >= LST_SECTION_max)
		return listener_remote_error_new(-1, "JSON: bad section");

	json_object_object_add(j_root, c_section[section], j_section);

	return NULL;
}


json_object* listener_remote_json_newSection(void)
{
	return json_object_new_object();
}


void listener_remote_json_clean(json_object* j_obj)
{
	if (j_obj)
		json_object_put(j_obj);
}

char* listener_remote_json_getStr(json_object* object)
{
    if (object)
        return (char*) json_object_to_json_string(object);

    return NULL;
}







