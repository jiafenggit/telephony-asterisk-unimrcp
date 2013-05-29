/* 
 * The implementation of Asterisk's Speech API via UniMRCP
 *
 * Copyright (C) 2009, Arsen Chaloyan  <achaloyan@gmail.com>
 *
 */

/*** MODULEINFO
	<depend>unimrcp</depend>
 ***/

#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION

#include "asterisk.h"
#define AST_MODULE "res_speech_unimrcp" 
ASTERISK_FILE_VERSION(__FILE__, "$Revision: $")

#include <asterisk/module.h>
#include <asterisk/logger.h>
#include <asterisk/strings.h>
#include <asterisk/config.h>
#include <asterisk/frame.h>
#include <asterisk/dsp.h>
#include <asterisk/speech.h>
#include <asterisk/cli.h>

#include <apr_thread_cond.h>
#include <apr_thread_proc.h>
#include <apr_tables.h>
#include <apr_hash.h>
#include <unimrcp_client.h>
#include <mrcp_application.h>
#include <mrcp_message.h>
#include <mrcp_generic_header.h>
#include <mrcp_recog_header.h>
#include <mrcp_recog_resource.h>
#include <mpf_frame_buffer.h>
#include <apt_nlsml_doc.h>
#include <apt_pool.h>
#include <apt_log.h>


#define UNI_ENGINE_NAME "unimrcp"
#define UNI_ENGINE_CONFIG "res-speech-unimrcp.conf"

/** Timeout to wait for asynchronous response (actually this timeout shouldn't expire) */
#define MRCP_APP_REQUEST_TIMEOUT 60 * 1000000

typedef enum {
         RESULTS_FORMAT_RAW,
         RESULTS_FORMAT_INSTANCE,
         RESULTS_FORMAT_INPUT
} results_format_type_e;

#define RESULTS_FORMAT_DEFAULT          RESULTS_FORMAT_INSTANCE

#define RESULTS_FORMAT_RAW_ID           "raw"
#define RESULTS_FORMAT_INSTANCE_ID      "instance"
#define RESULTS_FORMAT_INPUT_ID         "input"

/** \brief Forward declaration of speech */
typedef struct uni_speech_t uni_speech_t;
/** \brief Forward declaration of engine */
typedef struct uni_engine_t uni_engine_t;


/** \brief Declaration of UniMRCP based speech structure */
struct uni_speech_t {
	/* Client session */
	mrcp_session_t        *session;
	/* Client channel */
	mrcp_channel_t        *channel;
	/* Asterisk speech base */
	struct ast_speech     *speech_base;

	/* Conditional wait object */
	apr_thread_cond_t     *wait_object;
        apr_thread_cond_t     *wait_object2;

	/* Mutex of the wait object */
	apr_thread_mutex_t    *mutex;
        apr_thread_mutex_t    *mutex2;

	/* Buffer of media frames */
	mpf_frame_buffer_t    *media_buffer;

	/* Active grammars (Content-IDs) */
	apr_hash_t            *active_grammars;
	
	/* Is session management request in-progress or not */
	apt_bool_t             is_sm_request;
	/* Session management request sent to server */
	mrcp_sig_command_e     sm_request;
	/* Satus code of session management response */
	mrcp_sig_status_code_e sm_response;

	/* Is recognition in-progress or not */
	apt_bool_t             is_inprogress;
	
	/* In-progress request sent to server */
	mrcp_message_t        *mrcp_request;
        mrcp_message_t        *mrcp_request2;
	/* Response received from server */
	mrcp_message_t        *mrcp_response;
        mrcp_message_t        *mrcp_response2;
	/* Event received from server */
	mrcp_message_t        *mrcp_event;
        /* Format of the results returned by SPEECH(results) */
        results_format_type_e results_format;
        /* Values for RECOGNIZE parameters */
        apt_bool_t            start_input_timers;
        apt_bool_t            input_timers_started;
};

/** \brief Declaration of UniMRCP based recognition engine */
struct uni_engine_t {
	/* Memory pool */
	apr_pool_t            *pool;
	/* Client stack instance */
	mrcp_client_t         *client;
	/* Application instance */
	mrcp_application_t    *application;

	/* Profile name */
	const char            *profile;
	/* Log level */
	apt_log_priority_e     log_level;
	/* Log output */
	apt_log_output_e       log_output;

	/* Grammars to be preloaded with each MRCP session, if anything specified in config [grammars] */
	apr_table_t           *grammars;
	/* MRCPv2 properties (header fields) loaded from config */
	mrcp_message_header_t *v2_properties;
	/* MRCPv1 properties (header fields) loaded from config */
	mrcp_message_header_t *v1_properties;

        /* Default format of the results returned by SPEECH(results) */
        results_format_type_e  results_format;

        /* Default values for RECOGNIZE parameters */
        apt_bool_t             start_input_timers;
};

static struct uni_engine_t uni_engine;

static apt_bool_t uni_recog_channel_create(uni_speech_t *uni_speech, int format);
static apt_bool_t uni_recog_properties_set(uni_speech_t *uni_speech);
static apt_bool_t uni_recog_grammars_preload(uni_speech_t *uni_speech);
static apt_bool_t uni_recog_sm_request_send(uni_speech_t *uni_speech, mrcp_sig_command_e sm_request);
static apt_bool_t uni_recog_mrcp_request_send(uni_speech_t *uni_speech, mrcp_message_t *message);
static apt_bool_t uni_recog_mrcp_request_send2(uni_speech_t *uni_speech, mrcp_message_t *message);
static void uni_recog_cleanup(uni_speech_t *uni_speech);

static const char* uni_speech_id_get(uni_speech_t *uni_speech)
{
	const apt_str_t *id = mrcp_application_session_id_get(uni_speech->session);
	if(id && id->buf) {
		return id->buf;
	}
	return "none";
}

/** \brief Set up the speech structure within the engine */
#if defined(ASTERISK14)
static int uni_recog_create(struct ast_speech *speech)
#else
static int uni_recog_create(struct ast_speech *speech, int format)
#endif
{
	uni_speech_t *uni_speech;
	mrcp_session_t *session;
	apr_pool_t *pool;
	const mpf_codec_descriptor_t *descriptor;
#if defined(ASTERISK14)
	int format = 0;
#endif

	/* Create session instance */
	session = mrcp_application_session_create(uni_engine.application,uni_engine.profile,speech);
	if(!session) {
		ast_log(LOG_ERROR, "Failed to create session\n");
		return -1;
	}
	pool = mrcp_application_session_pool_get(session);
	uni_speech = apr_palloc(pool,sizeof(uni_speech_t));
	uni_speech->session = session;
	uni_speech->channel = NULL;
	uni_speech->wait_object = NULL;
	uni_speech->mutex = NULL;
	uni_speech->media_buffer = NULL;
	uni_speech->active_grammars = apr_hash_make(pool);
	uni_speech->is_sm_request = FALSE;
	uni_speech->is_inprogress = FALSE;
	uni_speech->sm_request = 0;
	uni_speech->sm_response = MRCP_SIG_STATUS_CODE_SUCCESS;
	uni_speech->mrcp_request = NULL;
	uni_speech->mrcp_response = NULL;
	uni_speech->mrcp_event = NULL;
        uni_speech->wait_object2 = NULL;
        uni_speech->mutex2 = NULL;
        uni_speech->mrcp_request2 = NULL;
        uni_speech->mrcp_response2 = NULL;

	uni_speech->speech_base = speech;
	speech->data = uni_speech;

        /* Initialize from defaults */
        uni_speech->start_input_timers = uni_engine.start_input_timers;
        uni_speech->input_timers_started = FALSE;
        ast_log(LOG_DEBUG, "uni_recog_create uni_speech->start_input_timers %s\n",uni_speech->start_input_timers ? "TRUE" : "FALSE");
        uni_speech->results_format= uni_engine.results_format;

	/* Create cond wait object and mutex */
	apr_thread_mutex_create(&uni_speech->mutex,APR_THREAD_MUTEX_DEFAULT,pool);
	apr_thread_cond_create(&uni_speech->wait_object,pool);
        apr_thread_mutex_create(&uni_speech->mutex2,APR_THREAD_MUTEX_DEFAULT,pool);
        apr_thread_cond_create(&uni_speech->wait_object2,pool);

	/* Create recognition channel instance */
	if(uni_recog_channel_create(uni_speech,format) != TRUE) {
		ast_log(LOG_ERROR, "Failed to create channel\n");
		uni_recog_cleanup(uni_speech);
		return -1;
	}

	/* Send add channel request and wait for response */
	if(uni_recog_sm_request_send(uni_speech,MRCP_SIG_COMMAND_CHANNEL_ADD) != TRUE) {
		ast_log(LOG_WARNING, "Failed to send add channel request\n");
		uni_recog_cleanup(uni_speech);
		return -1;
	}

	/* Check received response */
	if(uni_speech->sm_response != MRCP_SIG_STATUS_CODE_SUCCESS) {
		ast_log(LOG_WARNING, "Failed to add channel\n");
		uni_recog_sm_request_send(uni_speech,MRCP_SIG_COMMAND_SESSION_TERMINATE);
		uni_recog_cleanup(uni_speech);
		return -1;
	}

	descriptor = mrcp_application_source_descriptor_get(uni_speech->channel);
	if(descriptor) {
		mpf_frame_buffer_t *media_buffer;
		apr_size_t frame_size = mpf_codec_linear_frame_size_calculate(descriptor->sampling_rate,descriptor->channel_count);
		/* Create media buffer */
		ast_log(LOG_DEBUG, "Create media buffer frame_size:%"APR_SIZE_T_FMT"\n",frame_size);
		media_buffer = mpf_frame_buffer_create(frame_size,20,pool);
		uni_speech->media_buffer = media_buffer;
	}
	
	if(!uni_speech->media_buffer) {
		ast_log(LOG_WARNING, "Failed to create media buffer\n");
		uni_recog_sm_request_send(uni_speech,MRCP_SIG_COMMAND_SESSION_TERMINATE);
		uni_recog_cleanup(uni_speech);
		return -1;
	}

	ast_log(LOG_NOTICE, "Created speech instance '%s'\n",uni_speech_id_get(uni_speech));

	/* Set properties for session */
	uni_recog_properties_set(uni_speech);
	/* Preload grammars */
	uni_recog_grammars_preload(uni_speech);
	return 0;
}

/** \brief Destroy any data set on the speech structure by the engine */
static int uni_recog_destroy(struct ast_speech *speech)
{
	uni_speech_t *uni_speech = speech->data;
	ast_log(LOG_NOTICE, "Destroy speech instance '%s'\n",uni_speech_id_get(uni_speech));

	/* Terminate session first */
	uni_recog_sm_request_send(uni_speech,MRCP_SIG_COMMAND_SESSION_TERMINATE);
	/* Then cleanup it */
	uni_recog_cleanup(uni_speech);
	return 0;
}

/*! \brief Cleanup already allocated data */
static void uni_recog_cleanup(uni_speech_t *uni_speech)
{
	if(uni_speech->speech_base) {
		uni_speech->speech_base->data = NULL;
	}
	if(uni_speech->mutex) {
		apr_thread_mutex_destroy(uni_speech->mutex);
		uni_speech->mutex = NULL;
	}
	if(uni_speech->wait_object) {
		apr_thread_cond_destroy(uni_speech->wait_object);
		uni_speech->wait_object = NULL;
	}
        if(uni_speech->mutex2) {
                apr_thread_mutex_destroy(uni_speech->mutex2);
                uni_speech->mutex2 = NULL;
        }
        if(uni_speech->wait_object2) {
                apr_thread_cond_destroy(uni_speech->wait_object2);
                uni_speech->wait_object2 = NULL;
        }
	if(uni_speech->media_buffer) {
		mpf_frame_buffer_destroy(uni_speech->media_buffer);
		uni_speech->media_buffer = NULL;
	}

	mrcp_application_session_destroy(uni_speech->session);
}

/*! \brief Stop the in-progress recognition */
static int uni_recog_stop(struct ast_speech *speech)
{
	uni_speech_t *uni_speech = speech->data;
	mrcp_message_t *mrcp_message;
	mrcp_generic_header_t *generic_header;
	mrcp_recog_header_t *recog_header;
	
	if(!uni_speech->is_inprogress) {
		return 0;
	}
 
	ast_log(LOG_NOTICE, "Stop recognition '%s'\n",uni_speech_id_get(uni_speech));
	mrcp_message = mrcp_application_message_create(
								uni_speech->session,
								uni_speech->channel,
								RECOGNIZER_STOP);
	if(!mrcp_message) {
		ast_log(LOG_WARNING, "Failed to create MRCP message\n");
		return -1;
	}
	
	/* Reset last event (if any) */
	uni_speech->mrcp_event = NULL;

	/* Send MRCP request and wait for response */
	if(uni_recog_mrcp_request_send(uni_speech,mrcp_message) != TRUE) {
		ast_log(LOG_WARNING, "Failed to send MRCP message\n");
		return -1;
	}

	/* Check received response */
	if(!uni_speech->mrcp_response || uni_speech->mrcp_response->start_line.status_code != MRCP_STATUS_CODE_SUCCESS) {
		ast_log(LOG_WARNING, "Received failure response\n");
		return -1;
	}
	
	/* Reset media buffer */
	mpf_frame_buffer_restart(uni_speech->media_buffer);
	
	ast_speech_change_state(speech, AST_SPEECH_STATE_NOT_READY);
	
	uni_speech->is_inprogress = FALSE;
	return 0;
}

/*! \brief Load a local grammar on the speech structure */
static int uni_recog_load_grammar(struct ast_speech *speech, char *grammar_name, char *grammar_path)
{
	uni_speech_t *uni_speech = speech->data;
	mrcp_message_t *mrcp_message;
	mrcp_generic_header_t *generic_header;
	const char *content_type = NULL;
	apt_bool_t inline_content = FALSE;
	char *tmp;
	apr_file_t *file;
	apt_str_t *body = NULL;

	mrcp_message = mrcp_application_message_create(
								uni_speech->session,
								uni_speech->channel,
								RECOGNIZER_DEFINE_GRAMMAR);
	if(!mrcp_message) {
		ast_log(LOG_WARNING, "Failed to create MRCP message\n");
		return -1;
	}

	/* 
	 * Grammar name and path are mandatory attributes, 
	 * grammar type can be optionally specified with path.
	 *
	 * SpeechLoadGrammar(name|path)
	 * SpeechLoadGrammar(name|type:path)
	 * SpeechLoadGrammar(name|uri:path)
	 * SpeechLoadGrammar(name|builtin:grammar/digits)
	 */

	tmp = strchr(grammar_path,':');
	if(tmp) {
		const char builtin_token[] = "builtin";
		const char uri_token[] = "uri";
		if(strncmp(grammar_path,builtin_token,sizeof(builtin_token)-1) == 0) {
			content_type = "text/uri-list";
			inline_content = TRUE;
		}
		else if(strncmp(grammar_path,uri_token,sizeof(uri_token)-1) == 0) {
			content_type = "text/uri-list";
			inline_content = TRUE;
			grammar_path = tmp+1;
		}
		else {
			*tmp = '\0';
			content_type = grammar_path;
			grammar_path = tmp+1;
		}
	}

	if(inline_content == TRUE) {
		body = &mrcp_message->body;
		apt_string_assign(body,grammar_path,mrcp_message->pool);
	}
	else {
		if(apr_file_open(&file,grammar_path,APR_FOPEN_READ|APR_FOPEN_BINARY,0,mrcp_message->pool) == APR_SUCCESS) {
			apr_finfo_t finfo;
			if(apr_file_info_get(&finfo,APR_FINFO_SIZE,file) == APR_SUCCESS) {
				/* Read message body */
				body = &mrcp_message->body;
				body->buf = apr_palloc(mrcp_message->pool,finfo.size+1);
				body->length = (apr_size_t)finfo.size;
				if(apr_file_read(file,body->buf,&body->length) != APR_SUCCESS) {
					ast_log(LOG_WARNING, "Failed to read the content of grammar file: %s\n",grammar_path);
				}
				body->buf[body->length] = '\0';
			}
			apr_file_close(file);
		}
		else {
			ast_log(LOG_WARNING, "No such grammar file available: %s\n",grammar_path);
			return -1;
		}
	}

	if(!body || !body->buf) {
		ast_log(LOG_WARNING, "No content available: %s\n",grammar_path);
		return -1;
	}

	/* Try to implicitly detect content type, if it's not specified */
	if(!content_type) {
		if(strstr(body->buf,"#JSGF")) {
			content_type = "application/x-jsgf";
		}
		else if(strstr(body->buf,"#ABNF")) {
			content_type = "application/srgs";
		}
		else {
			content_type = "application/srgs+xml";
		}
	}

	ast_log(LOG_NOTICE, "Load grammar name:%s type:%s path:%s '%s'\n",
				grammar_name,
				content_type,
				grammar_path,
				uni_speech_id_get(uni_speech));
	/* Get/allocate generic header */
	generic_header = mrcp_generic_header_prepare(mrcp_message);
	if(generic_header) {
		/* Set generic header fields */
		apt_string_assign(&generic_header->content_type,content_type,mrcp_message->pool);
		mrcp_generic_header_property_add(mrcp_message,GENERIC_HEADER_CONTENT_TYPE);
		apt_string_assign(&generic_header->content_id,grammar_name,mrcp_message->pool);
		mrcp_generic_header_property_add(mrcp_message,GENERIC_HEADER_CONTENT_ID);
	}

	/* Send MRCP request and wait for response */
	if(uni_recog_mrcp_request_send(uni_speech,mrcp_message) != TRUE) {
		ast_log(LOG_WARNING, "Failed to send MRCP message\n");
		return -1;
	}

	/* Check received response */
	if(!uni_speech->mrcp_response || uni_speech->mrcp_response->start_line.status_code != MRCP_STATUS_CODE_SUCCESS) {
		ast_log(LOG_WARNING, "Received failure response\n");
		return -1;
	}
	return 0;
}

/** \brief Unload a local grammar */
static int uni_recog_unload_grammar(struct ast_speech *speech, char *grammar_name)
{
	uni_speech_t *uni_speech = speech->data;
	mrcp_message_t *mrcp_message;
	mrcp_generic_header_t *generic_header;

	if(uni_speech->is_inprogress) {
		uni_recog_stop(speech);
	}

	ast_log(LOG_NOTICE, "Unload grammar name:%s '%s'\n",
				grammar_name,
				uni_speech_id_get(uni_speech));

	apr_hash_set(uni_speech->active_grammars,grammar_name,APR_HASH_KEY_STRING,NULL);

	mrcp_message = mrcp_application_message_create(
								uni_speech->session,
								uni_speech->channel,
								RECOGNIZER_DEFINE_GRAMMAR);
	if(!mrcp_message) {
		ast_log(LOG_WARNING, "Failed to create MRCP message\n");
		return -1;
	}
	
	/* Get/allocate generic header */
	generic_header = mrcp_generic_header_prepare(mrcp_message);
	if(generic_header) {
		/* Set generic header fields */
		apt_string_assign(&generic_header->content_id,grammar_name,mrcp_message->pool);
		mrcp_generic_header_property_add(mrcp_message,GENERIC_HEADER_CONTENT_ID);
	}

	/* Send MRCP request and wait for response */
	if(uni_recog_mrcp_request_send(uni_speech,mrcp_message) != TRUE) {
		ast_log(LOG_WARNING, "Failed to send MRCP message\n");
		return -1;
	}

	/* Check received response */
	if(!uni_speech->mrcp_response || uni_speech->mrcp_response->start_line.status_code != MRCP_STATUS_CODE_SUCCESS) {
		ast_log(LOG_WARNING, "Received failure response\n");
		return -1;
	}
	return 0;
}

/** \brief Activate a loaded grammar */
static int uni_recog_activate_grammar(struct ast_speech *speech, char *grammar_name)
{
	uni_speech_t *uni_speech = speech->data;
	apr_pool_t *pool = mrcp_application_session_pool_get(uni_speech->session);
	const char *entry;

	ast_log(LOG_NOTICE, "Activate grammar name:%s '%s'\n",
						grammar_name,
						uni_speech_id_get(uni_speech));
	entry = apr_pstrdup(pool,grammar_name);
	apr_hash_set(uni_speech->active_grammars,entry,APR_HASH_KEY_STRING,entry);
	return 0;
}

/** \brief Deactivate a loaded grammar */
static int uni_recog_deactivate_grammar(struct ast_speech *speech, char *grammar_name)
{
	uni_speech_t *uni_speech = speech->data;

	if(uni_speech->is_inprogress) {
		uni_recog_stop(speech);
	}

	ast_log(LOG_NOTICE, "Deactivate grammar name:%s '%s'\n",
						grammar_name,
						uni_speech_id_get(uni_speech));
	apr_hash_set(uni_speech->active_grammars,grammar_name,APR_HASH_KEY_STRING,NULL);
	return 0;
}

/** brief Send RECOGNITION-START-TIMERS message */
static apt_bool_t uni_recog_start_timers(struct ast_speech *speech)
{
        uni_speech_t *uni_speech = speech->data;
        mrcp_message_t *mrcp_message;
        mrcp_generic_header_t *generic_header;
        mrcp_recog_header_t *recog_header;

        ast_log(LOG_NOTICE, "Start timers '%s'\n",uni_speech_id_get(uni_speech));
        mrcp_message = mrcp_application_message_create(
                                                                uni_speech->session,
                                                                uni_speech->channel,
                                                                RECOGNIZER_START_INPUT_TIMERS);
        if(!mrcp_message) {
                ast_log(LOG_WARNING, "Failed to create MRCP message\n");
                return FALSE;
        }

        /* Send MRCP request and wait for response */
        if(uni_recog_mrcp_request_send2(uni_speech,mrcp_message) != TRUE) {
                ast_log(LOG_WARNING, "Failed to send MRCP message\n");
                return FALSE;
        }

        /* Check received response */
        if(!uni_speech->mrcp_response2 || uni_speech->mrcp_response->start_line.status_code != MRCP_STATUS_CODE_SUCCESS) {
                ast_log(LOG_WARNING, "Received failure response\n");
                return FALSE;
        }

        return TRUE;
}

/** \brief Write audio to the speech engine */
static int uni_recog_write(struct ast_speech *speech, void *data, int len)
{
	uni_speech_t *uni_speech = speech->data;
	mpf_frame_t frame;

#if 0
	ast_log(LOG_DEBUG, "Write audio '%s' len:%d\n",uni_speech_id_get(uni_speech),len);
#endif
	frame.type = MEDIA_FRAME_TYPE_AUDIO;
	frame.marker = MPF_MARKER_NONE;
	frame.codec_frame.buffer = data;
	frame.codec_frame.size = len;

	if(mpf_frame_buffer_write(uni_speech->media_buffer,&frame) != TRUE) {
		ast_log(LOG_DEBUG, "Failed to write audio len:%d\n",len);
	}

#ifdef AST_SPEECH_IN_PROMPT_PATCH
        if(uni_speech->input_timers_started == FALSE && ast_test_flag(speech,AST_SPEECH_IN_PROMPT) == 0) {
                if (uni_recog_start_timers(speech)) {
                        uni_speech->input_timers_started = TRUE;
                }
        }
#endif

	return 0;
}

/** \brief Signal DTMF was received */
static int uni_recog_dtmf(struct ast_speech *speech, const char *dtmf)
{
	uni_speech_t *uni_speech = speech->data;
	ast_log(LOG_NOTICE, "Signal DTMF '%s'\n",uni_speech_id_get(uni_speech));
	return 0;
}

/** brief Prepare engine to accept audio */
static int uni_recog_start(struct ast_speech *speech)
{
	uni_speech_t *uni_speech = speech->data;
	mrcp_message_t *mrcp_message;
	mrcp_generic_header_t *generic_header;
	mrcp_recog_header_t *recog_header;

	if(uni_speech->is_inprogress) {
		uni_recog_stop(speech);
	}

	ast_log(LOG_NOTICE, "Start audio '%s'\n",uni_speech_id_get(uni_speech));
	mrcp_message = mrcp_application_message_create(
								uni_speech->session,
								uni_speech->channel,
								RECOGNIZER_RECOGNIZE);
	if(!mrcp_message) {
		ast_log(LOG_WARNING, "Failed to create MRCP message\n");
		return -1;
	}
	
	/* Get/allocate generic header */
	generic_header = mrcp_generic_header_prepare(mrcp_message);
	if(generic_header) {
		apr_hash_index_t *it;
		void *val;
		const char *grammar_name;
		const char *content;
		/* Set generic header fields */
		apt_string_assign(&generic_header->content_type,"text/uri-list",mrcp_message->pool);
		mrcp_generic_header_property_add(mrcp_message,GENERIC_HEADER_CONTENT_TYPE);

		/* Construct and set message body */
		it = apr_hash_first(mrcp_message->pool,uni_speech->active_grammars);
		if(it) {
			apr_hash_this(it,NULL,NULL,&val);
			grammar_name = val;
			content = apr_pstrcat(mrcp_message->pool,"session:",grammar_name,NULL);
			it = apr_hash_next(it);
		}
		for(; it; it = apr_hash_next(it)) {
			apr_hash_this(it,NULL,NULL,&val);
			grammar_name = val;
			content = apr_pstrcat(mrcp_message->pool,content,"\nsession:",grammar_name,NULL);
		}
		apt_string_set(&mrcp_message->body,content);
	}

	/* Get/allocate recognizer header */
	recog_header = (mrcp_recog_header_t*) mrcp_resource_header_prepare(mrcp_message);
	if(recog_header) {
		/* Set recognizer header fields */
		if(mrcp_message->start_line.version == MRCP_VERSION_2) {
			recog_header->cancel_if_queue = FALSE;
			mrcp_resource_header_property_add(mrcp_message,RECOGNIZER_HEADER_CANCEL_IF_QUEUE);
		}
                recog_header->start_input_timers = uni_speech->start_input_timers;
                ast_log(LOG_DEBUG, "uni_recog_start uni_speech->start_input_timers %s\n",uni_speech->start_input_timers ? "TRUE" : "FALSE");
		mrcp_resource_header_property_add(mrcp_message,RECOGNIZER_HEADER_START_INPUT_TIMERS);
	}

        uni_speech->input_timers_started = uni_speech->start_input_timers;
        ast_log(LOG_DEBUG, "uni_recog_start uni_speech->input_timers_started %s\n",uni_speech->input_timers_started ? "TRUE" : "FALSE");

	/* Reset last event (if any) */
	uni_speech->mrcp_event = NULL;

	/* Send MRCP request and wait for response */
	if(uni_recog_mrcp_request_send(uni_speech,mrcp_message) != TRUE) {
		ast_log(LOG_WARNING, "Failed to send MRCP message\n");
		return -1;
	}

	/* Check received response */
	if(!uni_speech->mrcp_response || uni_speech->mrcp_response->start_line.status_code != MRCP_STATUS_CODE_SUCCESS) {
		ast_log(LOG_WARNING, "Received failure response\n");
		return -1;
	}
	
	/* Reset media buffer */
	mpf_frame_buffer_restart(uni_speech->media_buffer);
	
	ast_speech_change_state(speech, AST_SPEECH_STATE_READY);
	
	uni_speech->is_inprogress = TRUE;
	return 0;
}

/** \brief Change an engine specific setting */
static int uni_recog_change(struct ast_speech *speech, char *name, const char *value)
{
	uni_speech_t *uni_speech = speech->data;
        mrcp_message_t *mrcp_message;
        mrcp_generic_header_t *generic_header;
        mrcp_recog_header_t *recog_header;

	if(uni_speech->is_inprogress) {
		uni_recog_stop(speech);
	}

        ast_log(LOG_NOTICE, "Change setting of '%s' to '%s' for '%s'\n",name,value,uni_speech_id_get(uni_speech));

        if(strcasecmp(name,"results_format") == 0) {
                if(strcasecmp(value, RESULTS_FORMAT_RAW_ID) == 0)
                        uni_speech->results_format = RESULTS_FORMAT_RAW;
                else if(strcasecmp(value, RESULTS_FORMAT_INPUT_ID) == 0)
                        uni_speech->results_format = RESULTS_FORMAT_INPUT;
                else if(strcasecmp(value, RESULTS_FORMAT_INSTANCE_ID) == 0)
                        uni_speech->results_format = RESULTS_FORMAT_INSTANCE;
                else
                        ast_log(LOG_WARNING, "results_format %s is invalid\n", value);
                ast_log(LOG_DEBUG, "uni_speech->results_format=%d\n", uni_speech->results_format);
        }
        else if(strcasecmp(name,"start_input_timers") == 0) {
                ast_log(LOG_NOTICE, "start_input_timers changed from %s to %s\n",uni_speech->start_input_timers ? "TRUE" : "FALSE",ast_true(value) ? "TRUE" : "FALSE");
                uni_speech->start_input_timers = ast_true(value);
                ast_log(LOG_DEBUG, "uni_recog_create uni_speech->start_input_timers %s\n",uni_speech->start_input_timers ? "TRUE" : "FALSE");
        }
        else {
                apt_pair_t pair;
                mrcp_message = mrcp_application_message_create(
                                                                        uni_speech->session,
                                                                        uni_speech->channel,
                                                                        RECOGNIZER_SET_PARAMS);
                if(!mrcp_message) {
                        ast_log(LOG_WARNING, "Failed to create MRCP message\n");
                        return 0;
                }

                /* Get/allocate generic header */
                generic_header = mrcp_generic_header_prepare(mrcp_message);
                /* Get/allocate recognizer header */
                recog_header = (mrcp_recog_header_t*) mrcp_resource_header_prepare(mrcp_message);

                apt_string_set(&pair.name,name);
                apt_string_set(&pair.value,value);
/*
 *                 if(mrcp_header_parse(&mrcp_message->header.resource_header_accessor,&pair,uni_engine.pool) != TRUE) {
 *                                         if(mrcp_header_parse(&mrcp_message->header.generic_header_accessor,&pair,uni_engine.pool) != TRUE) {
 *                                                                         ast_log(LOG_WARNING, "Unknown MRCP header %s=%s\n", name, value);
 *                                                                                                 }
 *                                                                                                                 }
 *                                                                                                                 */

                /* Send MRCP request and wait for response */
                if(uni_recog_mrcp_request_send(uni_speech,mrcp_message) != TRUE) {
                        ast_log(LOG_WARNING, "Failed to send MRCP message\n");
                        return 0;
                }

                /* Check received response */
                if(!uni_speech->mrcp_response || uni_speech->mrcp_response->start_line.status_code != MRCP_STATUS_CODE_SUCCESS) {
                        ast_log(LOG_WARNING, "Received failure response\n");
                        return 0;
                }

        }

        return 0;
}

/** \brief Change the type of results we want back */
static int uni_recog_change_results_type(struct ast_speech *speech,enum ast_speech_results_type results_type)
{
	uni_speech_t *uni_speech = speech->data;

	if(uni_speech->is_inprogress) {
		uni_recog_stop(speech);
	}

        ast_log(LOG_WARNING, "Change result type '%s' - Not implemented yet\n",uni_speech_id_get(uni_speech));  	
	return -1;
}

/** \brief Build ast_speech_result based on the NLSML result */
static struct ast_speech_result* uni_recog_speech_result_build(const apt_str_t *nlsml_result, mrcp_version_e mrcp_version, apr_pool_t *pool, results_format_type_e results_format)
{
	apr_xml_doc *doc; /* xml document */
	apr_xml_elem *interpret; /* <interpret> element */
	apr_xml_elem *instance; /* <instance> element */
	apr_xml_elem *input; /* <input> element */
	apr_xml_elem *text_elem; /* the element which contains the target, interpreted text */
	apr_xml_elem *elem; /* temp element */
	const char *confidence;
	const char *grammar;
	struct ast_speech_result *speech_result;

	/* Load NLSML document */
	doc = nlsml_doc_load(nlsml_result,pool);
	if(!doc) {
		ast_log(LOG_WARNING, "Failed to load NLSML document\n");
		return NULL;
	}

	/* Get interpretation element */
	interpret = nlsml_first_interpret_get(doc);
	if(!interpret) {
		ast_log(LOG_WARNING, "Missing <interpretation> element\n");
		return NULL;
	}

	/* Get instance and input elements */
	nlsml_interpret_results_get(interpret,&instance,&input);

	if(!instance || !input) {
		ast_log(LOG_WARNING, "Missing either <instance> or <input> element\n");
		return NULL;
	}

	/* <input> element can also contain additional <input> element(s); if so, use the child one */
	elem = input->first_child;
	if(elem && strcmp(elem->name,"input") == 0) {
		input = elem;
	}		
	
	speech_result = ast_calloc(sizeof(struct ast_speech_result), 1);
	speech_result->text = NULL;
	speech_result->score = 0;
	speech_result->grammar = NULL;

        if(results_format == RESULTS_FORMAT_RAW) {
                speech_result->text = strdup(nlsml_result->buf);
                ast_log(LOG_NOTICE, "speech->results->text (RAW) %s\n", speech_result->text);
        }
        else {
		text_elem = NULL;

		elem = instance->first_child;
		if(elem && elem->first_cdata.first) {
			text_elem = elem;
			ast_log(LOG_DEBUG, "Found speech result in the child element of the <instance> element = %s\n",text_elem->first_cdata.first->text);
		}

		if(!text_elem) {
			if(instance->first_cdata.first) {
				text_elem = instance;
				ast_log(LOG_DEBUG, "Found speech result in the <instance> element = %s\n",text_elem->first_cdata.first->text);
			}
		}

		if(!text_elem) {
			if(input->first_cdata.first) {
				text_elem = input;
				ast_log(LOG_DEBUG, "Found speech result in the <input> element = %s\n",text_elem->first_cdata.first->text);
			}
		}
		
		if(text_elem && text_elem->first_cdata.first->text) {
			speech_result->text = strdup(text_elem->first_cdata.first->text);
			if(speech_result->text[0] == 10 && text_elem->first_cdata.first->next) {
				free(speech_result->text);
				speech_result->text = strdup(text_elem->first_cdata.first->next->text);
				
				if(speech_result->text[0] == 9) {
					char *skip = speech_result->text;
					while(*skip==9) skip++;

					skip = strdup(skip);
					free(speech_result->text);
					speech_result->text = skip;    
				}     
			}
		}
	}
		
	confidence = nlsml_input_attrib_get(instance,"confidence",TRUE);
	if(!confidence) {
		confidence = nlsml_input_attrib_get(input,"confidence",TRUE);
	}

	if(confidence) {
		if(mrcp_version == MRCP_VERSION_2) {
			speech_result->score = (int)(atof(confidence) * 100);
		}
		else {
			speech_result->score = atoi(confidence);
		}
	}

	grammar = nlsml_input_attrib_get(interpret,"grammar",TRUE);
	if(grammar) {
		char *str = strstr(grammar,"session:");
		if(str) {
			grammar = str + strlen("session:");
		}
		if(grammar && *grammar != '\0') {
			speech_result->grammar = strdup(grammar);
		}
	}
	
	ast_log(LOG_NOTICE, "Interpreted text:%s score:%d grammar:%s\n",
		speech_result->text ? speech_result->text : "none",
		speech_result->score,
		speech_result->grammar ? speech_result->grammar : "none");
	return speech_result;
}

/** \brief Try to get result */
struct ast_speech_result* uni_recog_get(struct ast_speech *speech)
{
	mrcp_recog_header_t *recog_header;

	uni_speech_t *uni_speech = speech->data;

	if(uni_speech->is_inprogress) {
		uni_recog_stop(speech);
	}
  
	ast_log(LOG_NOTICE, "Get result '%s'\n",uni_speech_id_get(uni_speech));
	if(!uni_speech->mrcp_event) {
		ast_log(LOG_WARNING, "No RECOGNITION-COMPLETE message received\n");
		return NULL;
	}

	/* Get recognizer header */
	recog_header = mrcp_resource_header_get(uni_speech->mrcp_event);
	if(!recog_header || mrcp_resource_header_property_check(uni_speech->mrcp_event,RECOGNIZER_HEADER_COMPLETION_CAUSE) != TRUE) {
		ast_log(LOG_WARNING, "Missing Completion-Cause in RECOGNITION-COMPLETE message\n");
		return NULL;
	}

	if(recog_header->completion_cause != RECOGNIZER_COMPLETION_CAUSE_SUCCESS) {
		ast_log(LOG_WARNING, "Unsuccessful completion cause:%d reason:%s\n",
			recog_header->completion_cause,
			recog_header->completion_reason.buf ? recog_header->completion_reason.buf : "none");
		return NULL;
	}

	if(speech->results) {
		ast_speech_results_free(speech->results);
	}

	speech->results = uni_recog_speech_result_build(
		&uni_speech->mrcp_event->body,
		uni_speech->mrcp_event->start_line.version,
		mrcp_application_session_pool_get(uni_speech->session),
                uni_speech->results_format);
	
	if(speech->results) {
		ast_set_flag(speech,AST_SPEECH_HAVE_RESULTS);
	}
	return speech->results;
}


/*! \brief Signal session management response */
static apt_bool_t uni_recog_sm_response_signal(uni_speech_t *uni_speech, mrcp_sig_command_e request, mrcp_sig_status_code_e status)
{
	apr_thread_mutex_lock(uni_speech->mutex);

	if(uni_speech->sm_request == request) {
		uni_speech->sm_response = status;
		apr_thread_cond_signal(uni_speech->wait_object);
	}
	else {
		ast_log(LOG_WARNING, "Received unexpected response :%d, while waiting for :%d\n",
			request, uni_speech->sm_request);
	}

	apr_thread_mutex_unlock(uni_speech->mutex);
	return TRUE;
}

/*! \brief Signal MRCP response */
static apt_bool_t uni_recog_mrcp_response_signal(uni_speech_t *uni_speech, mrcp_message_t *message)
{
        ast_log(LOG_DEBUG, "uni_recog_mrcp_response_signal response request_id=%d method_name=%s method_id=%d\n",
                                                                message->start_line.request_id,
                                                                message->start_line.method_name.buf,
                                                                message->start_line.method_id);

        if(uni_speech->mrcp_request &&  message->start_line.method_id == uni_speech->mrcp_request->start_line.method_id) {
                apr_thread_mutex_lock(uni_speech->mutex);
                ast_log(LOG_DEBUG, "uni_recog_mrcp_response_signal request request_id=%d method_name=%s method_id=%d\n",
                                                                uni_speech->mrcp_request->start_line.request_id,
                                                                uni_speech->mrcp_request->start_line.method_name.buf,
                                                                uni_speech->mrcp_request->start_line.method_id);
                uni_speech->mrcp_response = message;
                apr_thread_cond_signal(uni_speech->wait_object);
                apr_thread_mutex_unlock(uni_speech->mutex);
        }
        else if(uni_speech->mrcp_request2 &&  message->start_line.method_id == uni_speech->mrcp_request2->start_line.method_id) {
                apr_thread_mutex_lock(uni_speech->mutex2);
                ast_log(LOG_DEBUG, "uni_recog_mrcp_response_signal request2 request_id=%d method_name=%s method_id=%d\n",
                                                                uni_speech->mrcp_request2->start_line.request_id,
                                                                uni_speech->mrcp_request2->start_line.method_name.buf,
                                                                uni_speech->mrcp_request2->start_line.method_id);
                uni_speech->mrcp_response2 = message;
                apr_thread_cond_signal(uni_speech->wait_object2);
                apr_thread_mutex_unlock(uni_speech->mutex2);
        }
        else {
                ast_log(LOG_WARNING, "Received unexpected MRCP response\n");
        }

        return TRUE;
}

/** \brief Received session update response */
static apt_bool_t on_session_update(mrcp_application_t *application, mrcp_session_t *session, mrcp_sig_status_code_e status)
{
	struct ast_speech *speech = mrcp_application_session_object_get(session);
	uni_speech_t *uni_speech = speech->data;

	ast_log(LOG_DEBUG, "On session update\n");
	return uni_recog_sm_response_signal(uni_speech,MRCP_SIG_COMMAND_SESSION_UPDATE,status);
}

/** \brief Received session termination response */
static apt_bool_t on_session_terminate(mrcp_application_t *application, mrcp_session_t *session, mrcp_sig_status_code_e status)
{
	struct ast_speech *speech = mrcp_application_session_object_get(session);
	uni_speech_t *uni_speech = speech->data;

	ast_log(LOG_DEBUG, "On session terminate\n");
	return uni_recog_sm_response_signal(uni_speech,MRCP_SIG_COMMAND_SESSION_TERMINATE,status);
}

/** \brief Received channel add response */
static apt_bool_t on_channel_add(mrcp_application_t *application, mrcp_session_t *session, mrcp_channel_t *channel, mrcp_sig_status_code_e status)
{
	uni_speech_t *uni_speech = mrcp_application_channel_object_get(channel);

	ast_log(LOG_DEBUG, "On channel add\n");
	return uni_recog_sm_response_signal(uni_speech,MRCP_SIG_COMMAND_CHANNEL_ADD,status);
}

/** \brief Received channel remove response */
static apt_bool_t on_channel_remove(mrcp_application_t *application, mrcp_session_t *session, mrcp_channel_t *channel, mrcp_sig_status_code_e status)
{
	uni_speech_t *uni_speech = mrcp_application_channel_object_get(channel);

	ast_log(LOG_DEBUG, "On channel remove\n");
	return uni_recog_sm_response_signal(uni_speech,MRCP_SIG_COMMAND_CHANNEL_REMOVE,status);
}

/** \brief Received MRCP message */
static apt_bool_t on_message_receive(mrcp_application_t *application, mrcp_session_t *session, mrcp_channel_t *channel, mrcp_message_t *message)
{
	uni_speech_t *uni_speech = mrcp_application_channel_object_get(channel);

        ast_log(LOG_DEBUG, "On message receive message_type=%d request_id=%d method_id=%d\n", message->start_line.message_type,message->start_line.request_id,message->start_line.method_id);
	if(message->start_line.message_type == MRCP_MESSAGE_TYPE_RESPONSE) {
                ast_log(LOG_DEBUG, "On message receive MRCP_MESSAGE_TYPE_RESPONSE\n");
		return uni_recog_mrcp_response_signal(uni_speech,message);
	}
	
	if(message->start_line.message_type == MRCP_MESSAGE_TYPE_EVENT) {
		if(message->start_line.method_id == RECOGNIZER_RECOGNITION_COMPLETE) {
                        ast_log(LOG_DEBUG, "On message receive RECOGNIZER_RECOGNITION_COMPLETE\n");
			uni_speech->is_inprogress = FALSE;			
			if (uni_speech->speech_base->state != AST_SPEECH_STATE_NOT_READY) {
				uni_speech->mrcp_event = message;
				ast_speech_change_state(uni_speech->speech_base,AST_SPEECH_STATE_DONE);
			}
			else {
				uni_speech->mrcp_event = NULL;
				ast_speech_change_state(uni_speech->speech_base,AST_SPEECH_STATE_NOT_READY);
			}
		}
		else if(message->start_line.method_id == RECOGNIZER_START_OF_INPUT) {
                        ast_log(LOG_DEBUG, "On message receive RECOGNIZER_START_OF_INPUT\n");
			ast_set_flag(uni_speech->speech_base,AST_SPEECH_QUIET);
		}
	}

	return TRUE;
}

/** \brief Received unexpected session/channel termination event */
static apt_bool_t on_terminate_event(mrcp_application_t *application, mrcp_session_t *session, mrcp_channel_t *channel)
{
	return TRUE;
}

/** \brief Received response to resource discovery request */
static apt_bool_t on_resource_discover(mrcp_application_t *application, mrcp_session_t *session, mrcp_session_descriptor_t *descriptor, mrcp_sig_status_code_e status)
{
	return TRUE;
}

static const mrcp_app_message_dispatcher_t uni_dispatcher = {
	on_session_update,
	on_session_terminate,
	on_channel_add,
	on_channel_remove,
	on_message_receive,
	on_terminate_event,
	on_resource_discover
};

/** \brief UniMRCP message handler */
static apt_bool_t uni_message_handler(const mrcp_app_message_t *app_message)
{
/*
        ast_log(LOG_DEBUG, "Received message from client stack \n");
*/
        const apt_str_t *id = mrcp_application_session_id_get(app_message->session);
        ast_log(LOG_DEBUG, "Received message from client stack for '%s'\n", id && id->buf ? id->buf : "NULL");
	return mrcp_application_message_dispatch(&uni_dispatcher,app_message);
}



/** \brief Process MPF frame */
static apt_bool_t uni_recog_stream_read(mpf_audio_stream_t *stream, mpf_frame_t *frame)
{
	uni_speech_t *uni_speech = stream->obj;

	if(uni_speech->media_buffer) {
		mpf_frame_buffer_read(uni_speech->media_buffer,frame);
#if 0
		ast_log(LOG_DEBUG, "Read audio '%s' type:%d len:%d\n",
			uni_speech_id_get(uni_speech),
			frame->type,
			frame->codec_frame.size);
#endif
	}
	return TRUE;
}

/** \brief Methods of audio stream */
static const mpf_audio_stream_vtable_t audio_stream_vtable = {
	NULL,
	NULL,
	NULL,
	uni_recog_stream_read,
	NULL,
	NULL,
	NULL
};

/** \brief Create recognition channel */
static apt_bool_t uni_recog_channel_create(uni_speech_t *uni_speech, int format)
{
	mrcp_channel_t *channel;
	mpf_termination_t *termination;
	mpf_stream_capabilities_t *capabilities;
	apr_pool_t *pool = mrcp_application_session_pool_get(uni_speech->session);
	
	/* Create source stream capabilities */
	capabilities = mpf_source_stream_capabilities_create(pool);
	/* Add codec capabilities (Linear PCM) */
	mpf_codec_capabilities_add(
			&capabilities->codecs,
			MPF_SAMPLE_RATE_8000,
			"LPCM");

	/* Create media termination */
	termination = mrcp_application_audio_termination_create(
			uni_speech->session,      /* session, termination belongs to */
			&audio_stream_vtable,     /* virtual methods table of audio stream */
			capabilities,             /* stream capabilities */
			uni_speech);              /* object to associate */
	
	/* Create MRCP channel */
	channel = mrcp_application_channel_create(
			uni_speech->session,      /* session, channel belongs to */
			MRCP_RECOGNIZER_RESOURCE, /* MRCP resource identifier */
			termination,              /* media termination, used to terminate audio stream */
			NULL,                     /* RTP descriptor, used to create RTP termination (NULL by default) */
			uni_speech);              /* object to associate */

	if(!channel) {
		return FALSE;
	}
	uni_speech->channel = channel;
	return TRUE;
}

/** \brief Set properties */
static apt_bool_t uni_recog_properties_set(uni_speech_t *uni_speech)
{
	mrcp_message_t *mrcp_message;
	mrcp_message_header_t *properties;
	ast_log(LOG_DEBUG, "Set properties '%s'\n",uni_speech_id_get(uni_speech));
	mrcp_message = mrcp_application_message_create(
								uni_speech->session,
								uni_speech->channel,
								RECOGNIZER_SET_PARAMS);
	if(!mrcp_message) {
		ast_log(LOG_WARNING, "Failed to create MRCP message\n");
		return FALSE;
	}
	
	/* Inherit properties loaded from config */
	if(mrcp_message->start_line.version == MRCP_VERSION_2) {
		properties = uni_engine.v2_properties;
	}
	else {
		properties = uni_engine.v1_properties;
	}

	if(properties) {
#if defined(TRANSPARENT_HEADER_FIELDS_SUPPORT)
		mrcp_header_fields_inherit(&mrcp_message->header,properties,mrcp_message->pool);
#else
		mrcp_message_header_inherit(&mrcp_message->header,properties,mrcp_message->pool);
#endif
	}

	/* Send MRCP request and wait for response */
	if(uni_recog_mrcp_request_send(uni_speech,mrcp_message) != TRUE) {
		ast_log(LOG_WARNING, "Failed to send MRCP message\n");
		return FALSE;
	}

	/* Check received response */
	if(!uni_speech->mrcp_response || uni_speech->mrcp_response->start_line.status_code != MRCP_STATUS_CODE_SUCCESS) {
		ast_log(LOG_WARNING, "Received failure response\n");
		return FALSE;
	}
	return TRUE;
}

/** \brief Preload grammar */
static apt_bool_t uni_recog_grammars_preload(uni_speech_t *uni_speech)
{
	apr_table_t *grammars = uni_engine.grammars;
	if(grammars && uni_speech->session) {
		int i;
		char *grammar_name;
		char *grammar_path;
		apr_pool_t *pool = mrcp_application_session_pool_get(uni_speech->session);
		const apr_array_header_t *header = apr_table_elts(grammars);
		apr_table_entry_t *entry = (apr_table_entry_t *) header->elts;
		for(i=0; i<header->nelts; i++) {
			grammar_name = apr_pstrdup(pool,entry[i].key);
			grammar_path = apr_pstrdup(pool,entry[i].val);
			uni_recog_load_grammar(uni_speech->speech_base,grammar_name,grammar_path);
		}
	}
	return TRUE;
}

/** \brief Send session management request to client stack and wait for async response */
static apt_bool_t uni_recog_sm_request_send(uni_speech_t *uni_speech, mrcp_sig_command_e sm_request)
{
	apt_bool_t res = FALSE;
	ast_log(LOG_DEBUG, "Send session request type:%d\n",sm_request);
	apr_thread_mutex_lock(uni_speech->mutex);
	uni_speech->is_sm_request = TRUE;
	uni_speech->sm_request = sm_request;
	switch(sm_request) {
		case MRCP_SIG_COMMAND_SESSION_UPDATE:
			res = mrcp_application_session_update(uni_speech->session);
			break;
		case MRCP_SIG_COMMAND_SESSION_TERMINATE:
			res = mrcp_application_session_terminate(uni_speech->session);
			break;
		case MRCP_SIG_COMMAND_CHANNEL_ADD:
			res = mrcp_application_channel_add(uni_speech->session,uni_speech->channel);
			break;
		case MRCP_SIG_COMMAND_CHANNEL_REMOVE:
    			res = mrcp_application_channel_remove(uni_speech->session,uni_speech->channel);
			break;
		case MRCP_SIG_COMMAND_RESOURCE_DISCOVER:
    			res = mrcp_application_resource_discover(uni_speech->session);
			break;
		default:
			break;
	}

	if(res == TRUE) {
		/* Wait for session response */
		ast_log(LOG_DEBUG, "Wait for session response\n");
		if(apr_thread_cond_timedwait(uni_speech->wait_object,uni_speech->mutex,MRCP_APP_REQUEST_TIMEOUT) != APR_SUCCESS) {
		    ast_log(LOG_ERROR, "Failed to get response, request timed out\n");
		    uni_speech->sm_response = MRCP_SIG_STATUS_CODE_FAILURE;
		}
		ast_log(LOG_DEBUG, "Waked up, status code: %d\n",uni_speech->sm_response);
	}
	
	uni_speech->is_sm_request = FALSE;
	apr_thread_mutex_unlock(uni_speech->mutex);
	return res;
}

/** \brief Send MRCP request to client stack and wait for async response */
static apt_bool_t uni_recog_mrcp_request_send(uni_speech_t *uni_speech, mrcp_message_t *message)
{
	apt_bool_t res = FALSE;
	apr_thread_mutex_lock(uni_speech->mutex);
	uni_speech->mrcp_request = message;

	/* Send MRCP request */
        ast_log(LOG_DEBUG, "Send MRCP request method_name=%s\n", message->start_line.method_name.buf);
        ast_log(LOG_DEBUG, "Send MRCP request body=%d ->%s\n", message->body.length, message->body.buf);
        ast_log(LOG_DEBUG, "Send MRCP request header=0X%X generic header=0X%X resource header=0X%X\n", message->header, message->header.generic_header_accessor, message->header.resource_header_accessor);
	res = mrcp_application_message_send(uni_speech->session,uni_speech->channel,message);
        ast_log(LOG_DEBUG, "Send MRCP request request_id=%d method_id=%d\n", message->start_line.request_id,  message->start_line.method_id);

	if(res == TRUE) {
		/* Wait for MRCP response */
		ast_log(LOG_DEBUG, "Wait for MRCP response\n");
		if(apr_thread_cond_timedwait(uni_speech->wait_object,uni_speech->mutex,MRCP_APP_REQUEST_TIMEOUT) != APR_SUCCESS) {
		    ast_log(LOG_ERROR, "Failed to get response, request timed out\n");
		    uni_speech->mrcp_response = NULL;
		}
		ast_log(LOG_DEBUG, "Waked up\n");
	}
	uni_speech->mrcp_request = NULL;
	apr_thread_mutex_unlock(uni_speech->mutex);
	return res;
}

/** \brief Send MRCP request to client stack and wait for async response */
static apt_bool_t uni_recog_mrcp_request_send2(uni_speech_t *uni_speech, mrcp_message_t *message)
{
        apt_bool_t res = FALSE;
        apr_thread_mutex_lock(uni_speech->mutex2);
        uni_speech->mrcp_request2 = message;

        /* Send MRCP request */
        ast_log(LOG_DEBUG, "Send MRCP request2 method_name=%s\n", message->start_line.method_name.buf);
        ast_log(LOG_DEBUG, "Send MRCP request body=%d ->%s\n", message->body.length, message->body.buf);
        ast_log(LOG_DEBUG, "Send MRCP request header=0X%X generic header=0X%X resource header=0X%X\n", message->header, message->header.generic_header_accessor, message->header.resource_header_accessor);
        res = mrcp_application_message_send(uni_speech->session,uni_speech->channel,message);
        ast_log(LOG_DEBUG, "Send MRCP request2 request_id=%d method_id=%d\n", message->start_line.request_id,  message->start_line.method_id);

        if(res == TRUE) {
                /* Wait for MRCP response */
                ast_log(LOG_DEBUG, "Wait for MRCP response\n");
                if(apr_thread_cond_timedwait(uni_speech->wait_object2,uni_speech->mutex2,MRCP_APP_REQUEST_TIMEOUT) != APR_SUCCESS) {
                    ast_log(LOG_ERROR, "Failed to get response, request timed out\n");
                    uni_speech->mrcp_response2 = NULL;
                }
                ast_log(LOG_DEBUG, "Waked up\n");
        }
        uni_speech->mrcp_request2 = NULL;
        apr_thread_mutex_unlock(uni_speech->mutex2);
        return res;
}

/** \brief Speech engine declaration */
static struct ast_speech_engine ast_engine = { 
    UNI_ENGINE_NAME,
    uni_recog_create,
    uni_recog_destroy,
    uni_recog_load_grammar,
    uni_recog_unload_grammar,
    uni_recog_activate_grammar,
    uni_recog_deactivate_grammar,
    uni_recog_write,
    uni_recog_dtmf,
    uni_recog_start,
    uni_recog_change,
    uni_recog_change_results_type,
    uni_recog_get,
    AST_FORMAT_SLINEAR
};

/** \brief Load properties from config */
static mrcp_message_header_t* uni_engine_properties_load(struct ast_config *cfg, const char *category, mrcp_version_e version, apr_pool_t *pool)
{
	struct ast_variable *var;
	mrcp_message_header_t *properties = NULL;

#if defined(TRANSPARENT_HEADER_FIELDS_SUPPORT)
	apt_header_field_t *header_field;
	properties = mrcp_message_header_create(
		mrcp_generic_header_vtable_get(version),
		mrcp_recog_header_vtable_get(version),
		pool);
	for(var = ast_variable_browse(cfg, category); var; var = var->next) {
		ast_log(LOG_DEBUG, "%s.%s=%s\n", category, var->name, var->value);
		header_field = apt_header_field_create_c(var->name,var->value,pool);
		if(header_field) {
			if(mrcp_header_field_add(properties,header_field,pool) == FALSE) {
				ast_log(LOG_WARNING, "Unknown MRCP header %s.%s=%s\n", category, var->name, var->value);
			}
		}
	}
#else
	apt_pair_t pair;
	properties = apr_palloc(pool,sizeof(mrcp_message_header_t));
	mrcp_message_header_init(properties);
	properties->generic_header_accessor.vtable = mrcp_generic_header_vtable_get(version);
	properties->resource_header_accessor.vtable = mrcp_recog_header_vtable_get(version);
	mrcp_header_allocate(&properties->generic_header_accessor,pool);
	mrcp_header_allocate(&properties->resource_header_accessor,pool);
	for(var = ast_variable_browse(cfg, category); var; var = var->next) {
		ast_log(LOG_DEBUG, "%s.%s=%s\n", category, var->name, var->value);
		apt_string_set(&pair.name,var->name);
		apt_string_set(&pair.value,var->value);
		if(mrcp_header_parse(&properties->resource_header_accessor,&pair,pool) != TRUE) {
			if(mrcp_header_parse(&properties->generic_header_accessor,&pair,pool) != TRUE) {
				ast_log(LOG_WARNING, "Unknown MRCP header %s.%s=%s\n", category, var->name, var->value);
			}
		}
	}
#endif
	return properties;
}

/** \brief Load grammars from config */
static apr_table_t* uni_engine_grammars_load(struct ast_config *cfg, const char *category, apr_pool_t *pool)
{
	struct ast_variable *var;
	apr_table_t *grammars = apr_table_make(pool,0);
	for(var = ast_variable_browse(cfg, category); var; var = var->next) {
		ast_log(LOG_DEBUG, "%s.%s=%s\n", category, var->name, var->value);
		apr_table_set(grammars,var->name,var->value);
	}
	return grammars;
}

/** \brief Load UniMRCP engine configuration (/etc/asterisk/res_speech_unimrcp.conf)*/
static apt_bool_t uni_engine_config_load(apr_pool_t *pool)
{
	const char *value = NULL;
#if defined(ASTERISK14)
	struct ast_config *cfg = ast_config_load(UNI_ENGINE_CONFIG);
#else
	struct ast_flags config_flags = { 0 };
	struct ast_config *cfg = ast_config_load(UNI_ENGINE_CONFIG, config_flags);
#endif
	if(!cfg) {
		ast_log(LOG_WARNING, "No such configuration file %s\n", UNI_ENGINE_CONFIG);
		return FALSE;
	}

	if((value = ast_variable_retrieve(cfg, "general", "unimrcp-profile")) != NULL) {
		ast_log(LOG_DEBUG, "general.unimrcp-profile=%s\n", value);
		uni_engine.profile = apr_pstrdup(uni_engine.pool, value);
	} 

	if((value = ast_variable_retrieve(cfg, "general", "log-level")) != NULL) {
		ast_log(LOG_DEBUG, "general.log-level=%s\n", value);
		uni_engine.log_level = apt_log_priority_translate(value);
	}

	if((value = ast_variable_retrieve(cfg, "general", "log-output")) != NULL) {
		ast_log(LOG_DEBUG, "general.log-output=%s\n", value);
		uni_engine.log_output = atoi(value);
	}

        if((value = ast_variable_retrieve(cfg, "general", "results-format")) != NULL) {
                ast_log(LOG_DEBUG, "general.results-format=%s\n", value);
                if(strcasecmp(value, RESULTS_FORMAT_RAW_ID) == 0)
                        uni_engine.results_format = RESULTS_FORMAT_RAW;
                else if(strcasecmp(value, RESULTS_FORMAT_INPUT_ID) == 0)
                        uni_engine.results_format = RESULTS_FORMAT_INPUT;
                else if(strcasecmp(value, RESULTS_FORMAT_INSTANCE_ID) == 0)
                        uni_engine.results_format = RESULTS_FORMAT_INSTANCE;
                else {
                        uni_engine.results_format = RESULTS_FORMAT_DEFAULT;
                        ast_log(LOG_WARNING, "results-format %s is invalid\n", value);
                }
        }

	uni_engine.grammars = uni_engine_grammars_load(cfg,"grammars",pool);

	uni_engine.v2_properties = uni_engine_properties_load(cfg,"mrcpv2-properties",MRCP_VERSION_2,pool);
	uni_engine.v1_properties = uni_engine_properties_load(cfg,"mrcpv1-properties",MRCP_VERSION_1,pool);

	ast_config_destroy(cfg);
	return TRUE;
}


/** \brief Unload UniMRCP engine */
static apt_bool_t uni_engine_unload()
{
	if(uni_engine.client) {
		mrcp_client_destroy(uni_engine.client);
		uni_engine.client = NULL;
	}

	/* Destroy singleton logger */
	apt_log_instance_destroy();

	if(uni_engine.pool) {
		apr_pool_destroy(uni_engine.pool);
		uni_engine.pool = NULL;
	}

	/* APR global termination */
	apr_terminate();
	return TRUE;
}

/* --- ASTERISK/MRCP LOGGING --- */

/* Connects UniMRCP logging to Asterisk. */
static apt_bool_t unimrcp_log(const char *file, int line, const char *id, apt_log_priority_e priority, const char *format, va_list arg_ptr)
{
        /* Same size as MAX_LOG_ENTRY_SIZE in UniMRCP apt_log.c. */
        char log_message[4096] = { 0 };

        if (strlen(format) == 0)
                return TRUE;

        /* Assume apr_vsnprintf supports format extensions required by UniMRCP. */
        apr_vsnprintf(log_message, sizeof(log_message) - 1, format, arg_ptr);
        log_message[sizeof(log_message) - 1] = '\0';

        switch(priority) {
                case APT_PRIO_EMERGENCY:
                        ast_log(LOG_WARNING, "%s\n", log_message);
                        break;
                case APT_PRIO_ALERT:
                        ast_log(LOG_WARNING, "%s\n", log_message);
                        break;
                case APT_PRIO_CRITICAL:
                         ast_log(LOG_WARNING, "%s\n", log_message);
                        break;
                case APT_PRIO_ERROR:
                        ast_log(LOG_ERROR, "%s\n", log_message);
                        break;
                case APT_PRIO_WARNING:
                        ast_log(LOG_WARNING, "%s\n", log_message);
                        break;
                case APT_PRIO_NOTICE:
                        ast_log(LOG_NOTICE, "%s\n", log_message);
                        break;
                case APT_PRIO_INFO:
                        ast_log(LOG_DEBUG, "%s\n", log_message);
                        break;
                case APT_PRIO_DEBUG:
                        ast_log(LOG_DEBUG, "%s\n", log_message);
                        break;
                default:
                        ast_log(LOG_DEBUG, "%s\n", log_message);
                        break;
        }

        return TRUE;
}

/** \brief Load UniMRCP engine */
static apt_bool_t uni_engine_load()
{
	apr_pool_t *pool;
	apt_dir_layout_t *dir_layout;

	/* APR global initialization */
	if(apr_initialize() != APR_SUCCESS) {
		ast_log(LOG_ERROR, "Failed to initialize APR\n");
		return FALSE;
	}

	uni_engine.pool = NULL;
	uni_engine.client = NULL;
	uni_engine.application = NULL;
	uni_engine.profile = NULL;
	uni_engine.log_level = APT_PRIO_INFO;
	uni_engine.log_output = APT_LOG_OUTPUT_CONSOLE | APT_LOG_OUTPUT_FILE;
	uni_engine.grammars = NULL;

        uni_engine.start_input_timers = FALSE;

        uni_engine.results_format = RESULTS_FORMAT_DEFAULT;

	pool = apt_pool_create();
	if(!pool) {
		ast_log(LOG_ERROR, "Failed to create APR pool\n");
		uni_engine_unload();
		return FALSE;
	}

	uni_engine.pool = pool;
	uni_engine.v2_properties = NULL;
	uni_engine.v1_properties = NULL;

	/* Load engine configuration */
	uni_engine_config_load(pool);

	if(!uni_engine.profile) {
		uni_engine.profile = "uni2";
	}

	dir_layout = apt_default_dir_layout_create(UNIMRCP_DIR_LOCATION,pool);

        if(uni_engine.log_output == APT_LOG_OUTPUT_NONE) {
                /* Link UniMRCP logs to Asterisk. */
                if (apt_log_instance_create(APT_LOG_OUTPUT_NONE, uni_engine.log_level, pool) == FALSE) {
                        /* Already created. */
                        ast_log(LOG_WARNING, "apt_log_instance_create already called\n");
                }
                else {
                        apt_log_ext_handler_set(unimrcp_log);
                }
        }
        else {
                /* Create singleton logger */
                apt_log_instance_create(uni_engine.log_output, uni_engine.log_level, pool);
                /* Open the log file */
		apt_log_file_open(dir_layout->log_dir_path,"astuni",MAX_LOG_FILE_SIZE,MAX_LOG_FILE_COUNT,TRUE,pool);
        }

	uni_engine.client = unimrcp_client_create(dir_layout);
	if(uni_engine.client) {
		uni_engine.application = mrcp_application_create(
										uni_message_handler,
										&uni_engine,
										pool);
		if(uni_engine.application) {
			mrcp_client_application_register(
							uni_engine.client,
							uni_engine.application,
							"ASTMRCP");
		}
	}

	if(!uni_engine.client || !uni_engine.application) {
		ast_log(LOG_ERROR, "Failed to initialize client stack\n");
		uni_engine_unload();
		return FALSE;
	}

	return TRUE;
}

#ifndef ASTERISK14

/*  New-style CLI */
/*! \brief CLI command "unimrcp set start_input_timers  */
static char *set_start_input_timers(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
        switch (cmd) {
        case CLI_INIT:
                e->command = "unimrcp set start_input_timers {true|false}";
                e->usage =
                        "Usage: unimrcp set start_input_timers {true|false}\n"
                        "       Send the START_INPUT_TIMERS on the REGOGNIZE command\n\n";
                return NULL;

        case CLI_GENERATE:
                return NULL;

        default:
                if (a->argc < 4)
                        return CLI_SHOWUSAGE;

                if (strcasecmp(a->argv[2], "start_input_timers") == 0 )
                {
                        uni_engine.start_input_timers = ast_true(a->argv[3]);
                        ast_cli(a->fd, "start_input_timers=%s\n", uni_engine.start_input_timers ? "TRUE" : "FALSE");
                }
                return CLI_SUCCESS;
        }
}

/*  New-style CLI */
/*! \brief CLI command "unimrcp set results_format  */
static char *set_results_format(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
        switch (cmd) {
        case CLI_INIT:
                e->command = "unimrcp set results_format {raw|instance|input}";
                e->usage =
                        "Usage: unimrcp set results_format {raw|instance|input}\n"
                        "       Set the result format for SPEECH(results)\n\n";
                return NULL;

        case CLI_GENERATE:
                return NULL;

        default:
                if (a->argc < 4)
                        return CLI_SHOWUSAGE;

                if (strcasecmp(a->argv[2], "results_format") == 0 )
                {
                        uni_engine.start_input_timers = ast_true(a->argv[3]);
                        if(strcasecmp(a->argv[3], RESULTS_FORMAT_RAW_ID) == 0)
                                uni_engine.results_format = RESULTS_FORMAT_RAW;
                        else if(strcasecmp(a->argv[3], RESULTS_FORMAT_INPUT_ID) == 0)
                                uni_engine.results_format = RESULTS_FORMAT_INPUT;
                        else if(strcasecmp(a->argv[3], RESULTS_FORMAT_INSTANCE_ID) == 0)
                                uni_engine.results_format = RESULTS_FORMAT_INSTANCE;
                        else
                                ast_log(LOG_WARNING, "results_format %s is invalid\n", a->argv[3]);

                        switch (uni_engine.results_format) {
                                case RESULTS_FORMAT_RAW:
                                        ast_cli(a->fd, "results_format=%s\n", RESULTS_FORMAT_RAW_ID);
                                        break;
                                case RESULTS_FORMAT_INPUT:
                                        ast_cli(a->fd, "results_format=%s\n", RESULTS_FORMAT_INPUT_ID);
                                        break;
                                case RESULTS_FORMAT_INSTANCE:
                                        ast_cli(a->fd, "results_format=%s\n", RESULTS_FORMAT_INSTANCE_ID);
                                        break;
                        }
                }
                return CLI_SUCCESS;
        }
}

/*  New-style CLI */
/*  New-style CLI */
/*! \brief CLI command "unimrcp show params" */
static char *show_param_values(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
        switch (cmd) {
        case CLI_INIT:
                e->command = "unimrcp show params";
                e->usage =
                        "Usage: unimrcp show params\n"
                        "       Show the values of the following paramters:\n"
                        "       -   start_input_timers\n";
                        "       -   results_format\n";
                return NULL;
        case CLI_GENERATE:
                return NULL;
        }


        if (a->argc != 3)
                return CLI_SHOWUSAGE;

        ast_cli(a->fd, "start_input_timers=%s\n", uni_engine.start_input_timers ? "TRUE" : "FALSE");
        switch (uni_engine.results_format) {
                case RESULTS_FORMAT_RAW:
                        ast_cli(a->fd, "results_format=%s\n", RESULTS_FORMAT_RAW_ID);
                        break;
                case RESULTS_FORMAT_INPUT:
                        ast_cli(a->fd, "results_format=%s\n", RESULTS_FORMAT_INPUT_ID);
                        break;
                case RESULTS_FORMAT_INSTANCE:
                        ast_cli(a->fd, "results_format=%s\n", RESULTS_FORMAT_INSTANCE_ID);
                        break;
        }

        return CLI_SUCCESS;
}

static char *complete_set_start_input_timers(const char *line, const char *word, int pos, int state)
{
        static const char * const choices[] = { "true", "false", NULL };

        return (pos != 3) ? NULL : ast_cli_complete(word, choices, state);
}

#else
/* Old-style CLI */
static char set_param_usage_start_input_timers[] =
"Usage: unimrcp set start_input_timers {true | false}\n"
"       Send the START_INPUT_TIMERS on the REGOGNIZE command\n";

static char show_param_usage[] =
"Usage: unimrcp show params\n"
"       Show the values of the following paramters:\n"
"       -   start_input_timers\n"
"       -   results_format\n";

/*! \brief CLI command "unimrcp set sensitivity" */
static int set_param_values(int fd, int argc, char **argv)
{
        float temp;
        if (argc != 4)
                return RESULT_SHOWUSAGE;

        if (strcasecmp(argv[2], "start_input_timers") == 0 )
        {
                uni_engine.start_input_timers = ast_true(argv[3]);
                ast_cli(fd, "start_input_timers=%s\n", uni_engine.start_input_timers ? "TRUE" : "FALSE");
        }
        return RESULT_SUCCESS;
}

/*! \brief CLI command "unimrcp show params" */
static int show_param_values(int fd, int argc, char **argv)
{
        ast_cli(fd, "start_input_timers=%s\n", uni_engine.start_input_timers ? "TRUE" : "FALSE");
         switch (uni_engine.results_format) {
                case RESULTS_FORMAT_RAW:
                        ast_cli(fd, "results_format=%s\n", RESULTS_FORMAT_RAW_ID);
                        break;
                case RESULTS_FORMAT_INPUT:
                        ast_cli(fd, "results_format=%s\n", RESULTS_FORMAT_INPUT_ID);
                        break;
                case RESULTS_FORMAT_INSTANCE:
                        ast_cli(fd, "results_format=%s\n", RESULTS_FORMAT_INSTANCE_ID);
                        break;
        }

       return RESULT_SUCCESS;
}

static char *complete_set_start_input_timers(const char *line, const char *word, int pos, int state)
{
        static char* choices[] = { "true", "false", NULL };

        return (pos != 3) ? NULL : ast_cli_complete(word, choices, state);
}

#endif

static struct ast_cli_entry cli_unimrcp[] = {
#ifndef ASTERISK14
        AST_CLI_DEFINE(set_start_input_timers, "Set start_input_timers parameter"),
        AST_CLI_DEFINE(set_results_format, "Set results format for SPEECH(results)"),
        AST_CLI_DEFINE(show_param_values, "Show the values of the various parameters"),
#else
        { { "unimrcp", "set", "start_input_timers", NULL },
        set_param_values, "Set start_input_timers parameter",
        set_param_usage_start_input_timers, complete_set_start_input_timers },

        { { "unimrcp", "show", "params", NULL },
        show_param_values, "Show the values of the various parameters",
        show_param_usage },

#endif
};


/** \brief Load module */
static int load_module(void)
{
	ast_log(LOG_NOTICE, "Load UniMRCP module\n");

	if(uni_engine_load() == FALSE) {
		return AST_MODULE_LOAD_FAILURE;
	}
	
	if(mrcp_client_start(uni_engine.client) != TRUE) {
		ast_log(LOG_ERROR, "Failed to start client stack\n");
		uni_engine_unload();
		return AST_MODULE_LOAD_FAILURE;
	}

	if(ast_speech_register(&ast_engine)) {
		ast_log(LOG_ERROR, "Failed to register module\n");
		mrcp_client_shutdown(uni_engine.client);
		uni_engine_unload();
		return AST_MODULE_LOAD_FAILURE;
	}

        /* Register all CLI functions for unimrcp */
        ast_cli_register_multiple(cli_unimrcp, sizeof(cli_unimrcp)/ sizeof(struct ast_cli_entry));

	return AST_MODULE_LOAD_SUCCESS;
}

/** \brief Unload module */
static int unload_module(void)
{
	ast_log(LOG_NOTICE, "Unload UniMRCP module\n");
	if(ast_speech_unregister(UNI_ENGINE_NAME)) {
		ast_log(LOG_ERROR, "Failed to unregister module\n");
	}

        /*  Unregister all CLI functions for unimrcp */
        ast_cli_unregister_multiple(cli_unimrcp, sizeof(cli_unimrcp)/ sizeof(struct ast_cli_entry));

	if(uni_engine.client) {
		mrcp_client_shutdown(uni_engine.client);
	}

	uni_engine_unload();
	return 0;
}

AST_MODULE_INFO_STANDARD(ASTERISK_GPL_KEY, "UniMRCP Speech Engine");
