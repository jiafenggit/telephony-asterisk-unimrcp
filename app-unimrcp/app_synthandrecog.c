/*
 * Asterisk -- An open source telephony toolkit.
 *
 * See http://www.asterisk.org for more information about
 * the Asterisk project. Please do not directly contact
 * any of the maintainers of this project for assistance;
 * the project provides a web site, mailing lists and IRC
 * channels for your use.
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 *
 * Please follow coding guidelines 
 * http://svn.digium.com/view/asterisk/trunk/doc/CODING-GUIDELINES
 */

/*! \file
 *
 * \brief MRCP synthesis and recognition application
 *
 * \author\verbatim Arsen Chaloyan <arsen.chaloyan@unimrcp.org> \endverbatim
 * 
 * \ingroup applications
 */

/* Asterisk includes. */
#include "ast_compat_defs.h"

#include "asterisk/channel.h"
#include "asterisk/pbx.h"
#include "asterisk/module.h"
#include "asterisk/lock.h"
#include "asterisk/file.h"
#include "asterisk/app.h"

/* UniMRCP includes. */
#include "ast_unimrcp_framework.h"
#include "recog_datastore.h"
#include "audio_queue.h"
#include "speech_channel.h"

/*** DOCUMENTATION
	<application name="SynthAndRecog" language="en_US">
		<synopsis>
			Play a synthesized prompt and wait for speech to be recognized.
		</synopsis>
		<syntax>
			<parameter name="prompt" required="true">
				<para>A plain text or SSML prompt to be synthesized and played to the caller.</para>
			</parameter>
			<parameter name="grammar" required="true">
				<para>An inline or URI grammar to be used for recognition.</para>
			</parameter>
			<parameter name="options" required="false">
				<optionlist>
					<option name="p"> <para>Profile to use in mrcp.conf.</para> </option>
					<option name="t"> <para>Recognition timeout (msec).</para> </option>
					<option name="b"> <para>Bargein value (0: no barge-in, 1: enable barge-in).</para> </option>
					<option name="dt"> <para>Grammar delimiters.</para> </option>
					<option name="ct"> <para>Confidence threshold (0.0 - 1.0).</para> </option>
					<option name="sl"> <para>Sensitivity level (0.0 - 1.0).</para> </option>
					<option name="sva"> <para>Speed vs accuracy (0.0 - 1.0).</para> </option>
					<option name="nb"> <para>N-best list length.</para> </option>
					<option name="nit"> <para>No input timeout (msec).</para> </option>
					<option name="sct"> <para>Speech complete timeout (msec).</para> </option>
					<option name="sint"> <para>Speech incomplete timeout (msec).</para> </option>
					<option name="dit"> <para>DTMF interdigit timeout (msec).</para> </option>
					<option name="dtt"> <para>DTMF terminate timeout (msec).</para> </option>
					<option name="dttc"> <para>DTMF terminate characters.</para> </option>
					<option name="sw"> <para>Save waveform (true/false).</para> </option>
					<option name="nac"> <para>New audio channel (true/false).</para> </option>
					<option name="spl"> <para>Speech language (en-US/en-GB/etc).</para> </option>
					<option name="rm"> <para>Recognition mode (normal/hotword).</para> </option>
					<option name="hmaxd"> <para>Hotword max duration (msec).</para> </option>
					<option name="hmind"> <para>Hotword min duration (msec).</para> </option>
					<option name="cdb"> <para>Clear DTMF buffer (true/false).</para> </option>
					<option name="enm"> <para>Early nomatch (true/false).</para> </option>
					<option name="iwu"> <para>Input waveform URI.</para> </option>
					<option name="mt"> <para>Media type.</para> </option>
					<option name="pv"> <para>Prosody volume (silent/x-soft/soft/medium/load/x-loud/default).</para> </option>
					<option name="pr"> <para>Prosody rate (x-slow/slow/medium/fast/x-fast/default).</para> </option>
					<option name="vn"> <para>Voice name to use (e.g. "Daniel", "Karin", etc.).</para> </option>
					<option name="vg"> <para>Voice gender to use (e.g. "male", "female").</para> </option>
					<option name="vv"> <para>Voice variant.</para> </option>
					<option name="a"> <para>Voice age.</para> </option>
					<option name="uer"> <para>URI-encoded results 
						(1: URI-encode NLMSL results, 0: do not encode).</para>
					</option>
				</optionlist>
			</parameter>
		</syntax>
		<description>
			<para>This application establishes two MRCP sessions: one for speech synthesis and the other for speech recognition.
			Once the user starts speaking (barge-in occurred), the synthesis session is stopped, and the recognition engine
			starts processing the input. Once recognition completes, the application exits and returns results to the dialplan.</para>
			<para>If recognition successfully started, the variable ${RECOG_STATUS} is set to "OK"; otherwise, if recognition
			terminated prematurely, the variable ${RECOG_STATUS} is set to "ERROR".</para>
			<para>The variable ${RECOG_COMPLETION_CAUSE} indicates whether recognition completed successfully with a match or
			an error occurred. ("000" - success, "001" - nomatch, "002" - noinput) </para>
			<para>If recognition completed successfully, the variable ${RECOG_RESULT} is set to an NLSML result received from
			the MRCP server.</para>
		</description>
		<see-also>
			<ref type="application">MRCPSynth</ref>
			<ref type="application">MRCPRecog</ref>
			<ref type="function">RECOG_CONFIDENCE</ref>
			<ref type="function">RECOG_GRAMMAR</ref>
			<ref type="function">RECOG_INPUT</ref>
			<ref type="function">RECOG_INSTANCE</ref>
		</see-also>
	</application>
 ***/

/* The name of the application. */
static const char *synthandrecog_name = "SynthAndRecog";

/* The application instance. */
static ast_mrcp_application_t *synthandrecog = NULL;

/* The enumeration of application options (excluding the MRCP params). */
enum sar_option_flags {
	SAR_RECOG_PROFILE          = (1 << 0),
	SAR_SYNTH_PROFILE          = (2 << 0),
	SAR_BARGEIN                = (3 << 0),
	SAR_GRAMMAR_DELIMITERS     = (4 << 0),
	SAR_URI_ENCODED_RESULTS    = (5 << 0)
};

/* The enumeration of option arguments. */
enum sar_option_args {
	OPT_ARG_RECOG_PROFILE       = 0,
	OPT_ARG_SYNTH_PROFILE       = 1,
	OPT_ARG_BARGEIN             = 2,
	OPT_ARG_GRAMMAR_DELIMITERS  = 3,
	OPT_ARG_URI_ENCODED_RESULTS = 4,

	/* This MUST be the last value in this enum! */
	OPT_ARG_ARRAY_SIZE          = 5
};

/* The structure which holds the application options (including the MRCP params). */
struct sar_options_t {
	apr_hash_t *synth_hfs;
	apr_hash_t *recog_hfs;

	int         flags;
	const char *params[OPT_ARG_ARRAY_SIZE];
};

typedef struct sar_options_t sar_options_t;

/* The application session. */
struct sar_session_t {
	apr_pool_t         *pool;
	speech_channel_t   *synth_channel;
	speech_channel_t   *recog_channel;
	ast_format_compat  *readformat;
	ast_format_compat  *writeformat;
};

typedef struct sar_session_t sar_session_t;

/* --- MRCP SPEECH CHANNEL INTERFACE TO UNIMRCP --- */
static apt_bool_t synth_on_message_receive(speech_channel_t *schannel, mrcp_message_t *message);
static apt_bool_t recog_on_message_receive(speech_channel_t *schannel, mrcp_message_t *message);

/* Handle the UniMRCP responses sent to session terminate requests. */
static apt_bool_t speech_on_session_terminate(mrcp_application_t *application, mrcp_session_t *session, mrcp_sig_status_code_e status)
{
	speech_channel_t *schannel;

	if (session != NULL)
		schannel = (speech_channel_t *)mrcp_application_session_object_get(session);
	else
		schannel = NULL;

	ast_log(LOG_DEBUG, "(%s) speech_on_session_terminate\n", schannel->name);

	if (schannel != NULL) {
		if (schannel->dtmf_generator != NULL) {
			ast_log(LOG_DEBUG, "(%s) DTMF generator destroyed\n", schannel->name);
			mpf_dtmf_generator_destroy(schannel->dtmf_generator);
			schannel->dtmf_generator = NULL;
		}

		ast_log(LOG_DEBUG, "(%s) Destroying MRCP session\n", schannel->name);

		if (!mrcp_application_session_destroy(session))
			ast_log(LOG_WARNING, "(%s) Unable to destroy application session\n", schannel->name);

		speech_channel_set_state(schannel, SPEECH_CHANNEL_CLOSED);
	} else
		ast_log(LOG_ERROR, "(unknown) channel error!\n");

	return TRUE;
}

/* Handle the UniMRCP responses sent to channel add requests. */
static apt_bool_t speech_on_channel_add(mrcp_application_t *application, mrcp_session_t *session, mrcp_channel_t *channel, mrcp_sig_status_code_e status)
{
	speech_channel_t *schannel;

	if (channel != NULL)
		schannel = (speech_channel_t *)mrcp_application_channel_object_get(channel);
	else
		schannel = NULL;

	ast_log(LOG_DEBUG, "(%s) speech_on_channel_add\n", schannel->name);

	if ((schannel != NULL) && (application != NULL) && (session != NULL) && (channel != NULL)) {
		if ((session != NULL) && (status == MRCP_SIG_STATUS_CODE_SUCCESS)) {
			const mpf_codec_descriptor_t *descriptor = NULL;
			if (schannel->type == SPEECH_CHANNEL_SYNTHESIZER)
				descriptor = mrcp_application_sink_descriptor_get(channel);
			else
				descriptor = mrcp_application_source_descriptor_get(channel);
			
			if (!descriptor) {
				ast_log(LOG_ERROR, "(%s) Unable to determine codec descriptor\n", schannel->name);
				speech_channel_set_state(schannel, SPEECH_CHANNEL_ERROR);
				ast_log(LOG_DEBUG, "(%s) Terminating MRCP session\n", schannel->name);
				if (!mrcp_application_session_terminate(session))
					ast_log(LOG_WARNING, "(%s) Unable to terminate application session\n", schannel->name);
				return FALSE;
			}

			if (schannel->type == SPEECH_CHANNEL_RECOGNIZER && schannel->stream != NULL) {
				schannel->dtmf_generator = mpf_dtmf_generator_create(schannel->stream, schannel->pool);
				/* schannel->dtmf_generator = mpf_dtmf_generator_create_ex(schannel->stream, MPF_DTMF_GENERATOR_OUTBAND, 70, 50, schannel->pool); */

				if (schannel->dtmf_generator != NULL)
					ast_log(LOG_DEBUG, "(%s) DTMF generator created\n", schannel->name);
				else
					ast_log(LOG_WARNING, "(%s) Unable to create DTMF generator\n", schannel->name);
			}

			schannel->rate = descriptor->sampling_rate;
			const char *codec_name = NULL;
			if (descriptor->name.length > 0)
				codec_name = descriptor->name.buf;
			else
				codec_name = "unknown";

			ast_log(LOG_NOTICE, "(%s) Channel ready codec=%s, sample rate=%d\n",
				schannel->name,
				codec_name,
				schannel->rate);
			speech_channel_set_state(schannel, SPEECH_CHANNEL_READY);
		} else {
			ast_log(LOG_ERROR, "(%s) Channel error!\n", schannel->name);

			if (session != NULL) {
				ast_log(LOG_DEBUG, "(%s) Terminating MRCP session\n", schannel->name);
				speech_channel_set_state(schannel, SPEECH_CHANNEL_ERROR);

				if (!mrcp_application_session_terminate(session))
					ast_log(LOG_WARNING, "(%s) Unable to terminate application session\n", schannel->name);
			}
		}
	} else
		ast_log(LOG_ERROR, "(unknown) channel error!\n");

	return TRUE;
}

/* Handle the UniMRCP responses sent to channel remove requests. */
static apt_bool_t speech_on_channel_remove(mrcp_application_t *application, mrcp_session_t *session, mrcp_channel_t *channel, mrcp_sig_status_code_e status)
{
	speech_channel_t *schannel;

	if (channel != NULL)
		schannel = (speech_channel_t *)mrcp_application_channel_object_get(channel);
	else
		schannel = NULL;

	ast_log(LOG_DEBUG, "(%s) speech_on_channel_remove\n", schannel->name);

	if (schannel != NULL) {
		ast_log(LOG_NOTICE, "(%s) Channel removed\n", schannel->name);
		schannel->unimrcp_channel = NULL;

		if (session != NULL) {
			ast_log(LOG_DEBUG, "(%s) Terminating MRCP session\n", schannel->name);

			if (!mrcp_application_session_terminate(session))
				ast_log(LOG_WARNING, "(%s) Unable to terminate application session\n", schannel->name);
		}
	} else
		ast_log(LOG_ERROR, "(unknown) channel error!\n");

	return TRUE;
}

/* Handle the MRCP responses/events from UniMRCP. */
static apt_bool_t speech_on_message_receive(mrcp_application_t *application, mrcp_session_t *session, mrcp_channel_t *channel, mrcp_message_t *message)
{
	speech_channel_t *schannel = NULL;

	if (channel != NULL)
		schannel = (speech_channel_t *)mrcp_application_channel_object_get(channel);

	if (schannel != NULL && message != NULL) {
		if(schannel && schannel->type == SPEECH_CHANNEL_SYNTHESIZER)
			return synth_on_message_receive(schannel, message);
		else if(schannel && schannel->type == SPEECH_CHANNEL_RECOGNIZER)
			return recog_on_message_receive(schannel, message);
	}

	return TRUE;
}

/* --- MRCP TTS --- */

/* Handle the MRCP synthesizer responses/events from UniMRCP. */
static apt_bool_t synth_on_message_receive(speech_channel_t *schannel, mrcp_message_t *message)
{
	if (message->start_line.message_type == MRCP_MESSAGE_TYPE_RESPONSE) {
		/* Received MRCP response. */
		if (message->start_line.method_id == SYNTHESIZER_SPEAK) {
			/* received the response to SPEAK request */
			if (message->start_line.request_state == MRCP_REQUEST_STATE_INPROGRESS) {
				/* Waiting for SPEAK-COMPLETE event. */
				ast_log(LOG_DEBUG, "(%s) REQUEST IN PROGRESS\n", schannel->name);
				speech_channel_set_state(schannel, SPEECH_CHANNEL_PROCESSING);
			} else {
				/* Received unexpected request_state. */
				ast_log(LOG_DEBUG, "(%s) Unexpected SPEAK response, request_state = %d\n", schannel->name, message->start_line.request_state);
				speech_channel_set_state(schannel, SPEECH_CHANNEL_ERROR);
			}
		} else if (message->start_line.method_id == SYNTHESIZER_STOP) {
			/* Received response to the STOP request. */
			if (message->start_line.request_state == MRCP_REQUEST_STATE_COMPLETE) {
				/* Got COMPLETE. */
				ast_log(LOG_DEBUG, "(%s) COMPLETE\n", schannel->name);
				speech_channel_set_state(schannel, SPEECH_CHANNEL_READY);
			} else {
				/* Received unexpected request state. */
				ast_log(LOG_DEBUG, "(%s) Unexpected STOP response, request_state = %d\n", schannel->name, message->start_line.request_state);
				speech_channel_set_state(schannel, SPEECH_CHANNEL_ERROR);
			}
		} else if (message->start_line.method_id == SYNTHESIZER_BARGE_IN_OCCURRED) {
			/* Received response to the BARGE_IN_OCCURRED request. */
			if (message->start_line.request_state == MRCP_REQUEST_STATE_COMPLETE) {
				/* Got COMPLETE. */
				ast_log(LOG_DEBUG, "(%s) COMPLETE\n", schannel->name);
				speech_channel_set_state(schannel, SPEECH_CHANNEL_READY);
			} else {
				/* Received unexpected request state. */
				ast_log(LOG_DEBUG, "(%s) Unexpected BARGE_IN_OCCURRED response, request_state = %d\n", schannel->name, message->start_line.request_state);
				speech_channel_set_state(schannel, SPEECH_CHANNEL_ERROR);
			}
		} else {
			/* Received unexpected response. */
			ast_log(LOG_DEBUG, "(%s) Unexpected response, method_id = %d\n", schannel->name, (int)message->start_line.method_id);
			speech_channel_set_state(schannel, SPEECH_CHANNEL_ERROR); 
		}
	} else if (message->start_line.message_type == MRCP_MESSAGE_TYPE_EVENT) {
		/* Received MRCP event. */
		if (message->start_line.method_id == SYNTHESIZER_SPEAK_COMPLETE) {
			/* Got SPEAK-COMPLETE. */
			ast_log(LOG_DEBUG, "(%s) SPEAK-COMPLETE\n", schannel->name);
			speech_channel_set_state(schannel, SPEECH_CHANNEL_READY);
		} else {
			ast_log(LOG_DEBUG, "(%s) Unexpected event, method_id = %d\n", schannel->name, (int)message->start_line.method_id);
			speech_channel_set_state(schannel, SPEECH_CHANNEL_ERROR);
		}
	} else {
		ast_log(LOG_DEBUG, "(%s) Unexpected message type, message_type = %d\n", schannel->name, message->start_line.message_type);
		speech_channel_set_state(schannel, SPEECH_CHANNEL_ERROR);
	}

	return TRUE;
}

/* Fill the frame with data. */
static APR_INLINE void ast_frame_fill(struct ast_channel *chan, struct ast_frame *fr, void *data, apr_size_t size)
{
	ast_format_compat format;
	get_synth_format(chan, &format);
	memset(fr, 0, sizeof(*fr));
	fr->frametype = AST_FRAME_VOICE;
	ast_frame_set_format(fr, &format);
	fr->datalen = size;
	fr->samples = size / format_to_bytes_per_sample(&format);
	ast_frame_set_data(fr, data);
	fr->mallocd = 0;
	fr->offset = AST_FRIENDLY_OFFSET;
	fr->src = __PRETTY_FUNCTION__;
	fr->delivery.tv_sec = 0;
	fr->delivery.tv_usec = 0;
}

/* Incoming TTS data from UniMRCP. */
static apt_bool_t synth_stream_write(mpf_audio_stream_t *stream, const mpf_frame_t *frame)
{
	speech_channel_t *schannel = NULL;

	if (stream != NULL)
		schannel = (speech_channel_t *)stream->obj;

	if ((schannel != NULL) && (stream != NULL) && (frame != NULL)) {
		if (frame->codec_frame.size > 0) {
			struct ast_frame fr;
			ast_frame_fill(schannel->chan, &fr, frame->codec_frame.buffer, frame->codec_frame.size);

			if (ast_write(schannel->chan, &fr) < 0) {
				ast_log(LOG_WARNING, "(%s) Unable to write frame to channel: %s\n", schannel->name, strerror(errno));
			}
		}
	} else
		ast_log(LOG_ERROR, "(unknown) channel error!\n");

	return TRUE;
}

/* Send SPEAK request to synthesizer. */
static int synth_channel_speak(speech_channel_t *schannel, const char *content, const char *content_type, apr_hash_t *header_fields)
{
	int status = 0;
	mrcp_message_t *mrcp_message = NULL;
	mrcp_generic_header_t *generic_header = NULL;
	mrcp_synth_header_t *synth_header = NULL;

	if ((schannel != NULL) && (content != NULL)  && (content_type != NULL)) {
		if (schannel->mutex != NULL)
			apr_thread_mutex_lock(schannel->mutex);

		if (schannel->state != SPEECH_CHANNEL_READY) {
			if (schannel->mutex != NULL)
				apr_thread_mutex_unlock(schannel->mutex);

			return -1;
		}

		if ((mrcp_message = mrcp_application_message_create(schannel->unimrcp_session, schannel->unimrcp_channel, SYNTHESIZER_SPEAK)) == NULL) {
			ast_log(LOG_ERROR, "(%s) Failed to create SPEAK message\n", schannel->name);

			if (schannel->mutex != NULL)
				apr_thread_mutex_unlock(schannel->mutex);
			return -1;
		}

		/* Set generic header fields (content-type). */
		if ((generic_header = (mrcp_generic_header_t *)mrcp_generic_header_prepare(mrcp_message)) == NULL) {	
			if (schannel->mutex != NULL)
				apr_thread_mutex_unlock(schannel->mutex);

			return -1;
		}

		apt_string_assign(&generic_header->content_type, content_type, mrcp_message->pool);
		mrcp_generic_header_property_add(mrcp_message, GENERIC_HEADER_CONTENT_TYPE);

		/* Set synthesizer header fields (voice, rate, etc.). */
		if ((synth_header = (mrcp_synth_header_t *)mrcp_resource_header_prepare(mrcp_message)) == NULL) {
			if (schannel->mutex != NULL)
				apr_thread_mutex_unlock(schannel->mutex);

			return -1;
		}

		/* Add params to MRCP message. */
		speech_channel_set_params(schannel, mrcp_message, header_fields);

		/* Set body (plain text or SSML). */
		apt_string_assign(&mrcp_message->body, content, schannel->pool);

		/* Empty audio queue and send SPEAK to MRCP server. */
		audio_queue_clear(schannel->audio_queue);

		if (!mrcp_application_message_send(schannel->unimrcp_session, schannel->unimrcp_channel, mrcp_message)) {
			ast_log(LOG_ERROR,"(%s) Failed to send SPEAK message", schannel->name);

			if (schannel->mutex != NULL)
				apr_thread_mutex_unlock(schannel->mutex);

			return -1;
		}

		/* Wait for IN PROGRESS. */
		if ((schannel->mutex != NULL) && (schannel->cond != NULL))
			apr_thread_cond_timedwait(schannel->cond, schannel->mutex, SPEECH_CHANNEL_TIMEOUT_USEC);

		if (schannel->state != SPEECH_CHANNEL_PROCESSING) {
			if (schannel->mutex != NULL)
				apr_thread_mutex_unlock(schannel->mutex);

			return -1;
		}

		if (schannel->mutex != NULL)
			apr_thread_mutex_unlock(schannel->mutex);
	} else
		ast_log(LOG_ERROR, "(unknown) channel error!\n");

	return status;
}

/* Send BARGE-IN-OCCURRED. */
int synth_channel_bargein_occurred(speech_channel_t *schannel) 
{
	int status = 0;
	
	if (schannel == NULL)
		return -1;

	if (schannel->mutex != NULL)
		apr_thread_mutex_lock(schannel->mutex);

	if (schannel->state == SPEECH_CHANNEL_PROCESSING) {
		mrcp_method_id method;
		mrcp_message_t *mrcp_message;

#if 1	/* Use STOP instead of BARGE-IN-OCCURRED for now. */
		method = SYNTHESIZER_STOP;
#else
		method = SYNTHESIZER_BARGE_IN_OCCURRED;
#endif
		ast_log(LOG_DEBUG, "(%s) Sending BARGE-IN-OCCURRED request\n", schannel->name);

		/* Send BARGE-IN-OCCURRED to MRCP server. */
		mrcp_message = mrcp_application_message_create(schannel->unimrcp_session, schannel->unimrcp_channel, method);

		if (mrcp_message) {
			mrcp_application_message_send(schannel->unimrcp_session, schannel->unimrcp_channel, mrcp_message);
		} else {
			ast_log(LOG_ERROR, "(%s) Failed to create BARGE-IN-OCCURRED message\n", schannel->name);
			status = -1;
		}
	}

	if (schannel->mutex != NULL)
		apr_thread_mutex_unlock(schannel->mutex);

	return status;
}

/* --- MRCP ASR --- */

/* Start recognizer's input timers. */
static int recog_channel_start_input_timers(speech_channel_t *schannel)
{   
	int status = 0;

	if (schannel == NULL) {
		ast_log(LOG_ERROR, "(unknown) channel error!\n");
		return -1;
	}

	if (schannel->mutex != NULL)
		apr_thread_mutex_lock(schannel->mutex);

	recognizer_data_t *r = (recognizer_data_t *)schannel->data;

	if (r == NULL) {
		ast_log(LOG_ERROR, "(%s) Recognizer data struct is NULL\n", schannel->name);

		if (schannel->mutex != NULL)
			apr_thread_mutex_unlock(schannel->mutex);

		return -1;
	}

	if ((schannel->state == SPEECH_CHANNEL_PROCESSING) && (!r->timers_started)) {
		mrcp_message_t *mrcp_message;
		ast_log(LOG_DEBUG, "(%s) Sending START-INPUT-TIMERS request\n", schannel->name);

		/* Send START-INPUT-TIMERS to MRCP server. */
		mrcp_message = mrcp_application_message_create(schannel->unimrcp_session, schannel->unimrcp_channel, RECOGNIZER_START_INPUT_TIMERS);

		if (mrcp_message) {
			mrcp_application_message_send(schannel->unimrcp_session, schannel->unimrcp_channel, mrcp_message);
		} else {
			ast_log(LOG_ERROR, "(%s) Failed to create START-INPUT-TIMERS message\n", schannel->name);
			status = -1;
		}
	}
 
	if (schannel->mutex != NULL)
		apr_thread_mutex_unlock(schannel->mutex);

	return status;
}

/* Flag that input has started. */
static int recog_channel_set_start_of_input(speech_channel_t *schannel)
{
	int status = 0;

	if (schannel == NULL) {
		ast_log(LOG_ERROR, "(unknown) channel error!\n");
		return -1;
	}

	if (schannel->mutex != NULL)
		apr_thread_mutex_lock(schannel->mutex);

	recognizer_data_t *r = (recognizer_data_t *)schannel->data;

	if (r == NULL) {
		ast_log(LOG_ERROR, "(%s) Recognizer data struct is NULL\n", schannel->name);

		if (schannel->mutex != NULL)
			apr_thread_mutex_unlock(schannel->mutex);

		return -1;
	}

	r->start_of_input = 1;

	if (schannel->mutex != NULL)
		apr_thread_mutex_unlock(schannel->mutex);

	return status;
}

/* Set the recognition results. */
static int recog_channel_set_results(speech_channel_t *schannel, int completion_cause, const apt_str_t *result, const apt_str_t *waveform_uri)
{
	int status = 0;

	if (schannel == NULL) {
		ast_log(LOG_ERROR, "(unknown) channel error!\n");
		return -1;
	}

	if (schannel->mutex != NULL)
		apr_thread_mutex_lock(schannel->mutex);

	recognizer_data_t *r = (recognizer_data_t *)schannel->data;

	if (r == NULL) {
		ast_log(LOG_ERROR, "(%s) Recognizer data struct is NULL\n", schannel->name);

		if (schannel->mutex != NULL)
			apr_thread_mutex_unlock(schannel->mutex);

		return -1;
	}

	if (r->completion_cause >= 0) {
		ast_log(LOG_DEBUG, "(%s) Result is already set\n", schannel->name);

		if (schannel->mutex != NULL)
			apr_thread_mutex_unlock(schannel->mutex);

		return -1;
	}

	if (result && result->length > 0) {
		/* The duplicated string will always be NUL-terminated. */
		r->result = apr_pstrndup(schannel->pool, result->buf, result->length);
		ast_log(LOG_DEBUG, "(%s) Set result:\n\n%s\n", schannel->name, r->result);
	}
	r->completion_cause = completion_cause;
	if (waveform_uri && waveform_uri->length > 0)
		r->waveform_uri = apr_pstrndup(schannel->pool, waveform_uri->buf, waveform_uri->length);

	if (schannel->mutex != NULL)
		apr_thread_mutex_unlock(schannel->mutex);

	return status;
}

/* Get the recognition results. */
static int recog_channel_get_results(speech_channel_t *schannel, int uri_encoded, const char **completion_cause, const char **result, const char **waveform_uri)
{
	if (schannel == NULL) {
		ast_log(LOG_ERROR, "(unknown) channel error!\n");
		return -1;
	}

	if (schannel->mutex != NULL)
		apr_thread_mutex_lock(schannel->mutex);

	recognizer_data_t *r = (recognizer_data_t *)schannel->data;

	if (r == NULL) {
		ast_log(LOG_ERROR, "(%s) Recognizer data struct is NULL\n", schannel->name);

		if (schannel->mutex != NULL)
			apr_thread_mutex_unlock(schannel->mutex);

		return -1;
	}

	if (r->completion_cause < 0) {
		ast_log(LOG_ERROR, "(%s) Recognition terminated prematurely\n", schannel->name);

		if (schannel->mutex != NULL)
			apr_thread_mutex_unlock(schannel->mutex);

		return -1;
	}

	if (completion_cause) {
		*completion_cause = apr_psprintf(schannel->pool, "%03d", r->completion_cause);
		ast_log(LOG_DEBUG, "(%s) Completion-Cause: %s\n", schannel->name, *completion_cause);
		r->completion_cause = 0;
	}

	if (result && r->result && (strlen(r->result) > 0)) {
		/* Store the results for further reference from the dialplan. */
		recog_datastore_result_set(schannel->chan, r->result);

		if (uri_encoded == 0) {
			*result = apr_pstrdup(schannel->pool, r->result);
		}
		else {
			apr_size_t len = strlen(r->result) * 2;
			char *res = apr_palloc(schannel->pool, len);
			*result = ast_uri_encode_http(r->result, res, len);
		}
		ast_log(LOG_NOTICE, "(%s) Result:\n\n%s\n", schannel->name, *result);
		r->result = NULL;
	}

	if (waveform_uri && r->waveform_uri && (strlen(r->waveform_uri)) > 0) {
		*waveform_uri = apr_pstrdup(schannel->pool, r->waveform_uri);
		ast_log(LOG_DEBUG, "(%s) Waveform-URI: %s\n", schannel->name, *waveform_uri);
		r->waveform_uri = NULL;
	}

	if (schannel->mutex != NULL)
		apr_thread_mutex_unlock(schannel->mutex);

	return 0;
}

/* Flag that the recognizer channel timers are started. */
static int recog_channel_set_timers_started(speech_channel_t *schannel)
{
	if (schannel == NULL) {
		ast_log(LOG_ERROR, "(unknown) channel error!\n");
		return -1;
	}

	if (schannel->mutex != NULL)
		apr_thread_mutex_lock(schannel->mutex);

	recognizer_data_t *r = (recognizer_data_t *)schannel->data;

	if (r == NULL) {
		ast_log(LOG_ERROR, "(%s) Recognizer data struct is NULL\n", schannel->name);

		if (schannel->mutex != NULL)
			apr_thread_mutex_unlock(schannel->mutex);

		return -1;
	}

	r->timers_started = 1;

	if (schannel->mutex != NULL)
		apr_thread_mutex_unlock(schannel->mutex);

	return 0;
}

/* Start RECOGNIZE request. */
static int recog_channel_start(speech_channel_t *schannel, const char *name, int start_input_timers, apr_hash_t *header_fields)
{
	int status = 0;
	mrcp_message_t *mrcp_message = NULL;
	mrcp_generic_header_t *generic_header = NULL;
	mrcp_recog_header_t *recog_header = NULL;
	recognizer_data_t *r = NULL;
	grammar_t *grammar = NULL;

	if ((schannel != NULL) && (name != NULL)) {
		if (schannel->mutex != NULL)
			apr_thread_mutex_lock(schannel->mutex);

		if (schannel->state != SPEECH_CHANNEL_READY) {
			if (schannel->mutex != NULL)
				apr_thread_mutex_unlock(schannel->mutex);

			return -1;
		}

		if (schannel->data == NULL) {
			if (schannel->mutex != NULL)
				apr_thread_mutex_unlock(schannel->mutex);

			return -1;
		}

		if ((r = (recognizer_data_t *)schannel->data) == NULL) {
			ast_log(LOG_ERROR, "(%s) Recognizer data struct is NULL\n", schannel->name);

			if (schannel->mutex != NULL)
				apr_thread_mutex_unlock(schannel->mutex);

			return -1;
		}

		r->result = NULL;
		r->completion_cause = -1;
		r->start_of_input = 0;

		r->timers_started = start_input_timers;

		apr_hash_index_t *hi;
		void *val;
		int length = 0;
		char grammar_refs[4096];
		for (hi = apr_hash_first(schannel->pool, r->grammars); hi; hi = apr_hash_next(hi)) {
			apr_hash_this(hi, NULL, NULL, &val);
			grammar = val;
			if (!grammar) 	continue;

			int grammar_len = strlen(grammar->data);
			if (length + grammar_len + 2 > sizeof(grammar_refs) - 1) {
				break;
			}

			if (length) {
				grammar_refs[length++] = '\r';
				grammar_refs[length++] = '\n';
			}
			memcpy(grammar_refs + length, grammar->data, grammar_len);
			length += grammar_len;
		}
		if (length == 0) {
			ast_log(LOG_ERROR, "(%s) No grammars specified\n", schannel->name);

			if (schannel->mutex != NULL)
				apr_thread_mutex_unlock(schannel->mutex);

			return -1;
		}
		grammar_refs[length] = '\0';

		/* Create MRCP message. */
		if ((mrcp_message = mrcp_application_message_create(schannel->unimrcp_session, schannel->unimrcp_channel, RECOGNIZER_RECOGNIZE)) == NULL) {
			if (schannel->mutex != NULL)
				apr_thread_mutex_unlock(schannel->mutex);

			return -1;
		}

		/* Allocate generic header. */
		if ((generic_header = (mrcp_generic_header_t *)mrcp_generic_header_prepare(mrcp_message)) == NULL) {
			if (schannel->mutex != NULL)
				apr_thread_mutex_unlock(schannel->mutex);

			return -1;
		}

		/* Set Content-Type to text/uri-list. */
		const char *mime_type = grammar_type_to_mime(GRAMMAR_TYPE_URI, schannel->profile);
		apt_string_assign(&generic_header->content_type, mime_type, mrcp_message->pool);
		mrcp_generic_header_property_add(mrcp_message, GENERIC_HEADER_CONTENT_TYPE);

		/* Allocate recognizer-specific header. */
		if ((recog_header = (mrcp_recog_header_t *)mrcp_resource_header_prepare(mrcp_message)) == NULL) {
			if (schannel->mutex != NULL)
				apr_thread_mutex_unlock(schannel->mutex);

			return -1;
		}

		/* Set Cancel-If-Queue. */
		if (mrcp_message->start_line.version == MRCP_VERSION_2) {
			recog_header->cancel_if_queue = FALSE;
			mrcp_resource_header_property_add(mrcp_message, RECOGNIZER_HEADER_CANCEL_IF_QUEUE);
		}

		/* Set Start-Input-Timers. */
		recog_header->start_input_timers = start_input_timers ? TRUE : FALSE;
		mrcp_resource_header_property_add(mrcp_message, RECOGNIZER_HEADER_START_INPUT_TIMERS);

		/* Set parameters. */
		speech_channel_set_params(schannel, mrcp_message, header_fields);

		/* Set message body. */
		apt_string_assign_n(&mrcp_message->body, grammar_refs, length, mrcp_message->pool);

		/* Empty audio queue and send RECOGNIZE to MRCP server. */
		audio_queue_clear(schannel->audio_queue);

		if (mrcp_application_message_send(schannel->unimrcp_session, schannel->unimrcp_channel, mrcp_message) == FALSE) {
			if (schannel->mutex != NULL)
				apr_thread_mutex_unlock(schannel->mutex);

			return -1;
		}

		/* Wait for IN PROGRESS. */
		if ((schannel->mutex != NULL) && (schannel->cond != NULL))
			apr_thread_cond_timedwait(schannel->cond, schannel->mutex, SPEECH_CHANNEL_TIMEOUT_USEC);

		if (schannel->state != SPEECH_CHANNEL_PROCESSING) {
			if (schannel->mutex != NULL)
				apr_thread_mutex_unlock(schannel->mutex);

			return -1;
		}

		if (schannel->mutex != NULL)
			apr_thread_mutex_unlock(schannel->mutex);
	} else
		ast_log(LOG_ERROR, "(unknown) channel error!\n");

	return status;
}

/* Load speech recognition grammar. */
static int recog_channel_load_grammar(speech_channel_t *schannel, const char *name, grammar_type_t type, const char *data)
{
	int status = 0;
	grammar_t *g = NULL;
	char ldata[256];

	if ((schannel != NULL) && (name != NULL) && (data != NULL)) {
		const char *mime_type;
		if (((mime_type = grammar_type_to_mime(type, schannel->profile)) == NULL) || (strlen(mime_type) == 0)) {
			ast_log(LOG_WARNING, "(%s) Unable to get MIME type: %i\n", schannel->name, type);
			return -1;
		}
		ast_log(LOG_DEBUG, "(%s) Loading grammar name=%s, type=%s, data=%s\n", schannel->name, name, mime_type, data);

		if (schannel->mutex != NULL)
			apr_thread_mutex_lock(schannel->mutex);

		if (schannel->state != SPEECH_CHANNEL_READY) {
			if (schannel->mutex != NULL)
				apr_thread_mutex_unlock(schannel->mutex);

			return -1;
		}

		/* If inline, use DEFINE-GRAMMAR to cache it on the server. */
		if (type != GRAMMAR_TYPE_URI) {
			mrcp_message_t *mrcp_message;
			mrcp_generic_header_t *generic_header;

			/* Create MRCP message. */
			if ((mrcp_message = mrcp_application_message_create(schannel->unimrcp_session, schannel->unimrcp_channel, RECOGNIZER_DEFINE_GRAMMAR)) == NULL) {
				if (schannel->mutex != NULL)
					apr_thread_mutex_unlock(schannel->mutex);

				return -1;
			}

			/* Set Content-Type and Content-ID in message. */
			if ((generic_header = (mrcp_generic_header_t *)mrcp_generic_header_prepare(mrcp_message)) == NULL) {
				if (schannel->mutex != NULL)
					apr_thread_mutex_unlock(schannel->mutex);

				return -1;
			}

			apt_string_assign(&generic_header->content_type, mime_type, mrcp_message->pool);
			mrcp_generic_header_property_add(mrcp_message, GENERIC_HEADER_CONTENT_TYPE);
			apt_string_assign(&generic_header->content_id, name, mrcp_message->pool);
			mrcp_generic_header_property_add(mrcp_message, GENERIC_HEADER_CONTENT_ID);

			/* Put grammar in message body. */
			apt_string_assign(&mrcp_message->body, data, mrcp_message->pool);

			/* Send message and wait for response. */
			speech_channel_set_state_unlocked(schannel, SPEECH_CHANNEL_PROCESSING);

			if (mrcp_application_message_send(schannel->unimrcp_session, schannel->unimrcp_channel, mrcp_message) == FALSE) {
				if (schannel->mutex != NULL)
					apr_thread_mutex_unlock(schannel->mutex);

				return -1;
			}

			if ((schannel->mutex != NULL) && (schannel->cond != NULL))
				apr_thread_cond_timedwait(schannel->cond, schannel->mutex, SPEECH_CHANNEL_TIMEOUT_USEC);

			if (schannel->state != SPEECH_CHANNEL_READY) {
				if (schannel->mutex != NULL)
					apr_thread_mutex_unlock(schannel->mutex);

				return -1;
			}

			/* Set up name, type for future RECOGNIZE requests.  We'll reference this cached grammar by name. */
			apr_snprintf(ldata, sizeof(ldata) - 1, "session:%s", name);
			ldata[sizeof(ldata) - 1] = '\0';

			data = ldata;
			type = GRAMMAR_TYPE_URI;
		}

		/* Create the grammar and save it. */
		if ((status = grammar_create(&g, name, type, data, schannel->pool)) == 0) {
			recognizer_data_t *r = (recognizer_data_t *)schannel->data;
	
			if (r != NULL)
				apr_hash_set(r->grammars, apr_pstrdup(schannel->pool, g->name), APR_HASH_KEY_STRING, g);
		}

		if (schannel->mutex != NULL)
			apr_thread_mutex_unlock(schannel->mutex);
	} else
		ast_log(LOG_ERROR, "(unknown) channel error!\n");

	return status;
}

/* Handle the MRCP responses/events. */
static apt_bool_t recog_on_message_receive(speech_channel_t *schannel, mrcp_message_t *message)
{
	mrcp_recog_header_t *recog_hdr = (mrcp_recog_header_t *)mrcp_resource_header_get(message);
	if (message->start_line.message_type == MRCP_MESSAGE_TYPE_RESPONSE) {
		/* Received MRCP response. */
		if (message->start_line.method_id == RECOGNIZER_RECOGNIZE) {
			/* Received the response to RECOGNIZE request. */
			if (message->start_line.request_state == MRCP_REQUEST_STATE_INPROGRESS) {
				/* RECOGNIZE in progress. */
				ast_log(LOG_DEBUG, "(%s) RECOGNIZE IN PROGRESS\n", schannel->name);
				speech_channel_set_state(schannel, SPEECH_CHANNEL_PROCESSING);
			} else if (message->start_line.request_state == MRCP_REQUEST_STATE_COMPLETE) {
				/* RECOGNIZE failed to start. */
				if (recog_hdr->completion_cause == RECOGNIZER_COMPLETION_CAUSE_UNKNOWN)
					ast_log(LOG_DEBUG, "(%s) RECOGNIZE failed: status = %d\n", schannel->name, message->start_line.status_code);
				else
					ast_log(LOG_DEBUG, "(%s) RECOGNIZE failed: status = %d, completion-cause = %03d\n", schannel->name, message->start_line.status_code, recog_hdr->completion_cause);
				speech_channel_set_state(schannel, SPEECH_CHANNEL_ERROR);
			} else if (message->start_line.request_state == MRCP_REQUEST_STATE_PENDING)
				/* RECOGNIZE is queued. */
				ast_log(LOG_DEBUG, "(%s) RECOGNIZE PENDING\n", schannel->name);
			else {
				/* Received unexpected request_state. */
				ast_log(LOG_DEBUG, "(%s) Unexpected RECOGNIZE request state: %d\n", schannel->name, message->start_line.request_state);
				speech_channel_set_state(schannel, SPEECH_CHANNEL_ERROR);
			}
		} else if (message->start_line.method_id == RECOGNIZER_STOP) {
			/* Received response to the STOP request. */
			if (message->start_line.request_state == MRCP_REQUEST_STATE_COMPLETE) {
				/* Got COMPLETE. */
				ast_log(LOG_DEBUG, "(%s) RECOGNIZE STOPPED\n", schannel->name);
				speech_channel_set_state(schannel, SPEECH_CHANNEL_READY);
			} else {
				/* Received unexpected request state. */
				ast_log(LOG_DEBUG, "(%s) Unexpected STOP request state: %d\n", schannel->name, message->start_line.request_state);
				speech_channel_set_state(schannel, SPEECH_CHANNEL_ERROR);
			}
		} else if (message->start_line.method_id == RECOGNIZER_START_INPUT_TIMERS) {
			/* Received response to START-INPUT-TIMERS request. */
			if (message->start_line.request_state == MRCP_REQUEST_STATE_COMPLETE) {
				if (message->start_line.status_code >= 200 && message->start_line.status_code <= 299) {
					ast_log(LOG_DEBUG, "(%s) Timers started\n", schannel->name);
					recog_channel_set_timers_started(schannel);
				} else
					ast_log(LOG_DEBUG, "(%s) Timers failed to start, status code = %d\n", schannel->name, message->start_line.status_code);
			}
		} else if (message->start_line.method_id == RECOGNIZER_DEFINE_GRAMMAR) {
			/* Received response to DEFINE-GRAMMAR request. */
			if (message->start_line.request_state == MRCP_REQUEST_STATE_COMPLETE) {
				if (message->start_line.status_code >= 200 && message->start_line.status_code <= 299) {
					ast_log(LOG_DEBUG, "(%s) Grammar loaded\n", schannel->name);
					speech_channel_set_state(schannel, SPEECH_CHANNEL_READY);
				} else {
					ast_log(LOG_DEBUG, "(%s) Grammar failed to load, status code = %d\n", schannel->name, message->start_line.status_code);
					speech_channel_set_state(schannel, SPEECH_CHANNEL_ERROR);
				}
			}
		} else {
			/* Received unexpected response. */
			ast_log(LOG_DEBUG, "(%s) Unexpected response, method_id = %d\n", schannel->name, (int)message->start_line.method_id);
			speech_channel_set_state(schannel, SPEECH_CHANNEL_ERROR);
		}
	} else if (message->start_line.message_type == MRCP_MESSAGE_TYPE_EVENT) {
		/* Received MRCP event. */
		if (message->start_line.method_id == RECOGNIZER_RECOGNITION_COMPLETE) {
			ast_log(LOG_DEBUG, "(%s) RECOGNITION COMPLETE, Completion-Cause: %03d\n", schannel->name, recog_hdr->completion_cause);
			recog_channel_set_results(schannel, recog_hdr->completion_cause, &message->body, &recog_hdr->waveform_uri);
			speech_channel_set_state(schannel, SPEECH_CHANNEL_READY);
		} else if (message->start_line.method_id == RECOGNIZER_START_OF_INPUT) {
			ast_log(LOG_DEBUG, "(%s) START OF INPUT\n", schannel->name);
			recog_channel_set_start_of_input(schannel);
		} else {
			ast_log(LOG_DEBUG, "(%s) Unexpected event, method_id = %d\n", schannel->name, (int)message->start_line.method_id);
			speech_channel_set_state(schannel, SPEECH_CHANNEL_ERROR);
		}
	} else {
		ast_log(LOG_DEBUG, "(%s) Unexpected message type, message_type = %d\n", schannel->name, message->start_line.message_type);
		speech_channel_set_state(schannel, SPEECH_CHANNEL_ERROR);
	}

	return TRUE;
}

/* UniMRCP callback requesting stream to be opened. */
static apt_bool_t recog_stream_open(mpf_audio_stream_t* stream, mpf_codec_t *codec)
{
	speech_channel_t* schannel;

	if (stream != NULL)
		schannel = (speech_channel_t*)stream->obj;
	else
		schannel = NULL;

	schannel->stream = stream;

	if ((schannel == NULL) || (stream == NULL))
		ast_log(LOG_ERROR, "(unknown) channel error opening stream!\n");

	return TRUE;
}

/* UniMRCP callback requesting next frame for speech recognition. */
static apt_bool_t recog_stream_read(mpf_audio_stream_t *stream, mpf_frame_t *frame)
{
	speech_channel_t *schannel;

	if (stream != NULL)
		schannel = (speech_channel_t *)stream->obj;
	else
		schannel = NULL;

	if ((schannel != NULL) && (stream != NULL) && (frame != NULL)) {
		if (schannel->dtmf_generator != NULL) {
			if (mpf_dtmf_generator_sending(schannel->dtmf_generator)) {
				ast_log(LOG_DEBUG, "(%s) DTMF frame written\n", schannel->name);
				mpf_dtmf_generator_put_frame(schannel->dtmf_generator, frame);
				return TRUE;
			}
		}

		apr_size_t to_read = frame->codec_frame.size;

		/* Grab the data. Pad it if there isn't enough. */
		if (speech_channel_read(schannel, frame->codec_frame.buffer, &to_read, 0) == 0) {
			if (to_read < frame->codec_frame.size)
				memset((apr_byte_t *)frame->codec_frame.buffer + to_read, schannel->silence, frame->codec_frame.size - to_read);

			frame->type |= MEDIA_FRAME_TYPE_AUDIO;
		}
	} else
		ast_log(LOG_ERROR, "(unknown) channel error!\n");

	return TRUE;
}

/* Apply application options. */
static int synthandrecog_option_apply(sar_options_t *options, const char *key, const char *value)
{
	if (strcasecmp(key, "ct") == 0) {
		apr_hash_set(options->recog_hfs, "Confidence-Threshold", APR_HASH_KEY_STRING, value);
	} else if (strcasecmp(key, "sva") == 0) {
		apr_hash_set(options->recog_hfs, "Speed-vs-Accuracy", APR_HASH_KEY_STRING, value);
	} else if (strcasecmp(key, "nb") == 0) {
		apr_hash_set(options->recog_hfs, "N-Best-List-Length", APR_HASH_KEY_STRING, value);
	} else if (strcasecmp(key, "nit") == 0) {
		apr_hash_set(options->recog_hfs, "No-Input-Timeout", APR_HASH_KEY_STRING, value);
	} else if (strcasecmp(key, "sct") == 0) {
		apr_hash_set(options->recog_hfs, "Speech-Complete-Timeout", APR_HASH_KEY_STRING, value);
	} else if (strcasecmp(key, "sint") == 0) {
		apr_hash_set(options->recog_hfs, "Speech-Incomplete-Timeout", APR_HASH_KEY_STRING, value);
	} else if (strcasecmp(key, "dit") == 0) {
		apr_hash_set(options->recog_hfs, "Dtmf-Interdigit-Timeout", APR_HASH_KEY_STRING, value);
	} else if (strcasecmp(key, "dtt") == 0) {
		apr_hash_set(options->recog_hfs, "Dtmf-Term-Timeout", APR_HASH_KEY_STRING, value);
	} else if (strcasecmp(key, "dttc") == 0) {
		apr_hash_set(options->recog_hfs, "Dtmf-Term-Char", APR_HASH_KEY_STRING, value);
	} else if (strcasecmp(key, "sw") == 0) {
		apr_hash_set(options->recog_hfs, "Save-Waveform", APR_HASH_KEY_STRING, value);
	} else if (strcasecmp(key, "nac") == 0) {
		apr_hash_set(options->recog_hfs, "New-Audio-Channel", APR_HASH_KEY_STRING, value);
	} else if (strcasecmp(key, "rm") == 0) {
		apr_hash_set(options->recog_hfs, "Recognition-Mode", APR_HASH_KEY_STRING, value);
	} else if (strcasecmp(key, "hmaxd") == 0) {
		apr_hash_set(options->recog_hfs, "Hotword-Max-Duration", APR_HASH_KEY_STRING, value);
	} else if (strcasecmp(key, "hmind") == 0) {
		apr_hash_set(options->recog_hfs, "Hotword-Min-Duration", APR_HASH_KEY_STRING, value);
	} else if (strcasecmp(key, "cdb") == 0) {
		apr_hash_set(options->recog_hfs, "Clear-Dtmf-Buffer", APR_HASH_KEY_STRING, value);
	} else if (strcasecmp(key, "enm") == 0) {
		apr_hash_set(options->recog_hfs, "Early-No-Match", APR_HASH_KEY_STRING, value);
	} else if (strcasecmp(key, "iwu") == 0) {
		apr_hash_set(options->recog_hfs, "Input-Waveform-URI", APR_HASH_KEY_STRING, value);
	} else if (strcasecmp(key, "sl") == 0) {
		apr_hash_set(options->recog_hfs, "Sensitivity-Level", APR_HASH_KEY_STRING, value);
	} else if (strcasecmp(key, "spl") == 0) {
		apr_hash_set(options->recog_hfs, "Speech-Language", APR_HASH_KEY_STRING, value);
		apr_hash_set(options->synth_hfs, "Speech-Language", APR_HASH_KEY_STRING, value);
	} else if (strcasecmp(key, "mt") == 0) {
		apr_hash_set(options->recog_hfs, "Media-Type", APR_HASH_KEY_STRING, value);
	} else if (strcasecmp(key, "pv") == 0) {
		apr_hash_set(options->synth_hfs, "Prosody-Volume", APR_HASH_KEY_STRING, value);
	} else if (strcasecmp(key, "pr") == 0) {
		apr_hash_set(options->synth_hfs, "Prosody-Rate", APR_HASH_KEY_STRING, value);
	} else if (strcasecmp(key, "vn") == 0) {
		apr_hash_set(options->synth_hfs, "Voice-Name", APR_HASH_KEY_STRING, value);
	} else if (strcasecmp(key, "vv") == 0) {
		apr_hash_set(options->synth_hfs, "Voice-Variant", APR_HASH_KEY_STRING, value);
	} else if (strcasecmp(key, "vg") == 0) {
		apr_hash_set(options->synth_hfs, "Voice-Gender", APR_HASH_KEY_STRING, value);
	} else if (strcasecmp(key, "a") == 0) {
		apr_hash_set(options->synth_hfs, "Voice-Age", APR_HASH_KEY_STRING, value);
	} else if (strcasecmp(key, "p") == 0) {
		/* Set the same profile for synth and recog. There might be a separate 
		configuration option for each of them in the future. */
		options->flags |= SAR_RECOG_PROFILE | SAR_SYNTH_PROFILE;
		options->params[OPT_ARG_RECOG_PROFILE] = value;
		options->params[OPT_ARG_SYNTH_PROFILE] = value;
	} else if (strcasecmp(key, "t") == 0) {
		apr_hash_set(options->recog_hfs, "Recognition-Timeout", APR_HASH_KEY_STRING, value);
	} else if (strcasecmp(key, "b") == 0) {
		options->flags |= SAR_BARGEIN;
		options->params[OPT_ARG_BARGEIN] = value;
	} else if (strcasecmp(key, "gd") == 0) {
		options->flags |= SAR_GRAMMAR_DELIMITERS;
		options->params[OPT_ARG_GRAMMAR_DELIMITERS] = value;
	} else if (strcasecmp(key, "uer") == 0) {
		options->flags |= SAR_URI_ENCODED_RESULTS;
		options->params[OPT_ARG_URI_ENCODED_RESULTS] = value;
	}
	else {
		ast_log(LOG_WARNING, "Unknown option: %s\n", key);
	}
	return 0;
}

/* Parse application options. */
static int synthandrecog_options_parse(char *str, sar_options_t *options, apr_pool_t *pool)
{
	char *s;
	char *name, *value;

	if (!str) 
		return 0;

	if ((options->recog_hfs = apr_hash_make(pool)) == NULL) {
		return -1;
	}
	if ((options->synth_hfs = apr_hash_make(pool)) == NULL) {
		return -1;
	}

	while ((s = strsep(&str, "&"))) {
		value = s;
		if ((name = strsep(&value, "=")) && value) {
			ast_log(LOG_DEBUG, "Apply option %s: %s\n", name, value);
			synthandrecog_option_apply(options, name, value);
		}
	}
	return 0;
}

/* Exit the application. */
static int synthandrecog_exit(struct ast_channel *chan, sar_session_t *sar_session, speech_channel_status_t status)
{
	if (sar_session) {
		if (sar_session->writeformat)
			ast_channel_set_writeformat(chan, sar_session->writeformat);

		if (sar_session->readformat)
			ast_channel_set_readformat(chan, sar_session->readformat);

		if (sar_session->synth_channel)
			speech_channel_destroy(sar_session->synth_channel);

		if (sar_session->recog_channel)
			speech_channel_destroy(sar_session->recog_channel);

		if (sar_session->pool)
			apr_pool_destroy(sar_session->pool);
	}

	const char *status_str = speech_channel_status_to_string(status);
	pbx_builtin_setvar_helper(chan, "RECOG_STATUS", status_str);
	ast_log(LOG_NOTICE, "%s() exiting status: %s on %s\n", synthandrecog_name, status_str, ast_channel_name(chan));

	return status != SPEECH_CHANNEL_STATUS_ERROR ? 0 : -1;
}

/* The entry point of the application. */
static int app_synthandrecog_exec(struct ast_channel *chan, ast_app_data data)
{
	int samplerate = 8000;
	struct ast_frame *f = NULL;
	apr_size_t len;

	ast_mrcp_profile_t *recog_profile = NULL;
	const char *recog_name;
	ast_mrcp_profile_t *synth_profile = NULL;
	const char *synth_name;
	apr_uint32_t speech_channel_number = get_next_speech_channel_number();
	speech_channel_status_t status = SPEECH_CHANNEL_STATUS_OK;

	sar_session_t sar_session;
	sar_options_t sar_options;
	char *parse;
	int i;

	AST_DECLARE_APP_ARGS(args,
		AST_APP_ARG(prompt);
		AST_APP_ARG(grammar);
		AST_APP_ARG(options);
	);

	if (ast_strlen_zero(data)) {
		ast_log(LOG_WARNING, "%s() requires arguments (prompt,grammar[,options])\n", synthandrecog_name);
		return synthandrecog_exit(chan, NULL, SPEECH_CHANNEL_STATUS_ERROR);
	}

	/* We need to make a copy of the input string if we are going to modify it! */
	parse = ast_strdupa(data);
	AST_STANDARD_APP_ARGS(args, parse);

	if (ast_strlen_zero(args.prompt)) {
		ast_log(LOG_WARNING, "%s() requires a prompt argument (prompt,grammar[,options])\n", synthandrecog_name);
		return synthandrecog_exit(chan, NULL, SPEECH_CHANNEL_STATUS_ERROR);
	}

	args.prompt = normalize_input_string(args.prompt);
	ast_log(LOG_NOTICE, "%s() prompt: %s\n", synthandrecog_name, args.prompt);

	if (ast_strlen_zero(args.grammar)) {
		ast_log(LOG_WARNING, "%s() requires a grammar argument (prompt,grammar[,options])\n", synthandrecog_name);
		return synthandrecog_exit(chan, NULL, SPEECH_CHANNEL_STATUS_ERROR);
	}

	args.grammar = normalize_input_string(args.grammar);
	ast_log(LOG_NOTICE, "%s() grammar: %s\n", synthandrecog_name, args.grammar);

	if ((sar_session.pool = apt_pool_create()) == NULL) {
		ast_log(LOG_ERROR, "Unable to create memory pool for speech channel\n");
		return synthandrecog_exit(chan, NULL, SPEECH_CHANNEL_STATUS_ERROR);
	}

	sar_session.recog_channel = NULL;
	sar_session.synth_channel = NULL;
	sar_session.readformat = NULL;
	sar_session.writeformat = NULL;

	sar_options.recog_hfs = NULL;
	sar_options.synth_hfs = NULL;
	sar_options.flags = 0;
	for (i=0; i<OPT_ARG_ARRAY_SIZE; i++)
		sar_options.params[i] = NULL;

	if (!ast_strlen_zero(args.options)) {
		args.options = normalize_input_string(args.options);
		ast_log(LOG_NOTICE, "%s() options: %s\n", synthandrecog_name, args.options);
		char *options_buf = apr_pstrdup(sar_session.pool, args.options);
		synthandrecog_options_parse(options_buf, &sar_options, sar_session.pool);
	}

	/* Answer if it's not already going. */
	if (ast_channel_state(chan) != AST_STATE_UP)
		ast_answer(chan);

	/* Ensure no streams are currently playing. */
	ast_stopstream(chan);

	ast_format_compat nreadformat;
	ast_format_clear(&nreadformat);
	get_recog_format(chan, &nreadformat);

	recog_name = apr_psprintf(sar_session.pool, "ASR-%lu", (unsigned long int)speech_channel_number);

	/* Create speech channel for recognition. */
	sar_session.recog_channel = speech_channel_create(sar_session.pool, recog_name, SPEECH_CHANNEL_RECOGNIZER, synthandrecog, format_to_str(&nreadformat), samplerate, chan);
	if (sar_session.recog_channel == NULL) {
		return synthandrecog_exit(chan, &sar_session, SPEECH_CHANNEL_STATUS_ERROR);
	}

	const char *recog_profile_option = NULL;
	if ((sar_options.flags & SAR_RECOG_PROFILE) == SAR_RECOG_PROFILE) {
		if (!ast_strlen_zero(sar_options.params[OPT_ARG_RECOG_PROFILE])) {
			recog_profile_option = sar_options.params[OPT_ARG_RECOG_PROFILE];
		}
	}

	/* Get recognition profile. */
	recog_profile = get_recog_profile(recog_profile_option);
	if (!recog_profile) {
		ast_log(LOG_ERROR, "(%s) Can't find profile, %s\n", recog_name, recog_profile_option);
		return synthandrecog_exit(chan, &sar_session, SPEECH_CHANNEL_STATUS_ERROR);
	}

	/* Open recognition channel. */
	if (speech_channel_open(sar_session.recog_channel, recog_profile) != 0) {
		return synthandrecog_exit(chan, &sar_session, SPEECH_CHANNEL_STATUS_ERROR);
	}

	ast_format_compat nwriteformat;
	ast_format_clear(&nwriteformat);
	get_synth_format(chan, &nwriteformat);

	synth_name = apr_psprintf(sar_session.pool, "TTS-%lu", (unsigned long int)speech_channel_number);

	/* Create speech channel for synthesis. */
	sar_session.synth_channel = speech_channel_create(sar_session.pool, synth_name, SPEECH_CHANNEL_SYNTHESIZER, synthandrecog, format_to_str(&nwriteformat), samplerate, chan);
	if (sar_session.synth_channel == NULL) {
		return synthandrecog_exit(chan, &sar_session, SPEECH_CHANNEL_STATUS_ERROR);
	}

	const char *synth_profile_option = NULL;
	if ((sar_options.flags & SAR_SYNTH_PROFILE) == SAR_SYNTH_PROFILE) {
		if (!ast_strlen_zero(sar_options.params[OPT_ARG_SYNTH_PROFILE])) {
			synth_profile_option = sar_options.params[OPT_ARG_SYNTH_PROFILE];
		}
	}

	/* Get synthesis profile. */
	synth_profile = get_synth_profile(synth_profile_option);
	if (!synth_profile) {
		ast_log(LOG_ERROR, "(%s) Can't find profile, %s\n", synth_name, synth_profile_option);
		return synthandrecog_exit(chan, &sar_session, SPEECH_CHANNEL_STATUS_ERROR);
	}

	/* Open synthesis channel. */
	if (speech_channel_open(sar_session.synth_channel, synth_profile) != 0) {
		return synthandrecog_exit(chan, &sar_session, SPEECH_CHANNEL_STATUS_ERROR);
	}

	int bargein = 1;
	/* Check if barge-in is allowed. */
	if ((sar_options.flags & SAR_BARGEIN) == SAR_BARGEIN) {
		if (!ast_strlen_zero(sar_options.params[OPT_ARG_BARGEIN])) {
			bargein = (atoi(sar_options.params[OPT_ARG_BARGEIN]) == 0) ? 0 : 1;
		}
	}

	ast_format_compat oreadformat;
	ast_format_clear(&oreadformat);
	ast_channel_get_readformat(chan, &oreadformat);

	if (ast_channel_set_readformat(chan, &nreadformat) < 0) {
		ast_log(LOG_WARNING, "(%s) Unable to set read format to signed linear\n", synth_name);
		return synthandrecog_exit(chan, &sar_session, SPEECH_CHANNEL_STATUS_ERROR);
	}

	sar_session.readformat = &oreadformat;

	ast_format_compat owriteformat;
	ast_format_clear(&owriteformat);
	ast_channel_get_writeformat(chan, &owriteformat);

	if (ast_channel_set_writeformat(chan, &nwriteformat) < 0) {
		ast_log(LOG_WARNING, "(%s) Unable to set write format to signed linear\n", synth_name);
		return synthandrecog_exit(chan, &sar_session, SPEECH_CHANNEL_STATUS_ERROR);
	}

	sar_session.writeformat = &owriteformat;

	const char *grammar_delimiters = ",";
	/* Get grammar delimiters. */
	if ((sar_options.flags & SAR_GRAMMAR_DELIMITERS) == SAR_GRAMMAR_DELIMITERS) {
		if (!ast_strlen_zero(sar_options.params[OPT_ARG_GRAMMAR_DELIMITERS])) {
			grammar_delimiters = sar_options.params[OPT_ARG_GRAMMAR_DELIMITERS];
			ast_log(LOG_DEBUG, "(%s) Grammar delimiters: %s\n", grammar_delimiters, recog_name);
		}
	}
	/* Parse the grammar argument into a sequence of grammars. */
	char *grammar_arg = apr_pstrdup(sar_session.pool, args.grammar);
	char *last;
	char *grammar_str;
	char grammar_name[32];
	int grammar_id = 0;
	grammar_str = apr_strtok(grammar_arg, grammar_delimiters, &last);
	while (grammar_str) {
		const char *grammar_content = NULL;
		grammar_type_t grammar_type = GRAMMAR_TYPE_UNKNOWN;
		ast_log(LOG_DEBUG, "(%s) Determine grammar type: %s\n", recog_name, grammar_str);
		if (determine_grammar_type(sar_session.recog_channel, grammar_str, &grammar_content, &grammar_type) != 0) {
			ast_log(LOG_WARNING, "(%s) Unable to determine grammar type: %s\n", recog_name, grammar_str);
			return synthandrecog_exit(chan, &sar_session, SPEECH_CHANNEL_STATUS_ERROR);
		}

		apr_snprintf(grammar_name, sizeof(grammar_name) - 1, "grammar-%d", grammar_id++);
		grammar_name[sizeof(grammar_name) - 1] = '\0';
		/* Load grammar. */
		if (recog_channel_load_grammar(sar_session.recog_channel, grammar_name, grammar_type, grammar_content) != 0) {
			ast_log(LOG_ERROR, "(%s) Unable to load grammar\n", recog_name);
			return synthandrecog_exit(chan, &sar_session, SPEECH_CHANNEL_STATUS_ERROR);
		}

		grammar_str = apr_strtok(NULL, grammar_delimiters, &last);
	}

	const char *content = NULL;
	const char *content_type = NULL;
	if (determine_synth_content_type(sar_session.synth_channel, args.prompt, &content, &content_type) != 0) {
		ast_log(LOG_WARNING, "(%s) Unable to determine synthesis content type\n", synth_name);
		return synthandrecog_exit(chan, &sar_session, SPEECH_CHANNEL_STATUS_ERROR);
	}

	/* Start synthesis. */
	if (synth_channel_speak(sar_session.synth_channel, content, content_type, sar_options.synth_hfs) != 0) {
		ast_log(LOG_ERROR, "(%s) Unable to send SPEAK request\n", synth_name);
		return synthandrecog_exit(chan, &sar_session, SPEECH_CHANNEL_STATUS_ERROR);
	}

	if (!bargein) {
		/* if bargein is not allowed, wait for synthesis to complete */
		do {
			int ms = ast_waitfor(chan, 100);
			if (ms < 0) {
				ast_log(LOG_DEBUG, "(%s) Hangup detected\n", recog_name);
				return synthandrecog_exit(chan, &sar_session, SPEECH_CHANNEL_STATUS_INTERRUPTED);
			}

			f = ast_read(chan);
			if (!f) {
				ast_log(LOG_DEBUG, "(%s) Null frame. Hangup detected\n", recog_name);
				return synthandrecog_exit(chan, &sar_session, SPEECH_CHANNEL_STATUS_INTERRUPTED);
			}

			ast_frfree(f);
		}
		while (sar_session.synth_channel->state == SPEECH_CHANNEL_PROCESSING);
	}

	int synth_processing = (sar_session.synth_channel->state == SPEECH_CHANNEL_PROCESSING) ? 1 : 0;
	int start_input_timers = !synth_processing;
	recognizer_data_t *r = sar_session.recog_channel->data;

	ast_log(LOG_NOTICE, "(%s) Recognizing, Start-Input-Timers: %d\n", recog_name, start_input_timers);

	/* Start recognition. */
	if (recog_channel_start(sar_session.recog_channel, recog_name, start_input_timers, sar_options.recog_hfs) != 0) {
		ast_log(LOG_ERROR, "(%s) Unable to start recognition\n", recog_name);
		return synthandrecog_exit(chan, &sar_session, SPEECH_CHANNEL_STATUS_ERROR);
	}

	int waitres;

	/* Continue with recognition. */
	while ((waitres = ast_waitfor(chan, 100)) >= 0) {
		int recog_processing = 1;

		if ((sar_session.recog_channel != NULL) && (sar_session.recog_channel->mutex != NULL)) {
			if (sar_session.recog_channel->mutex != NULL) {
				apr_thread_mutex_lock(sar_session.recog_channel->mutex);
			}

			if (sar_session.recog_channel->state != SPEECH_CHANNEL_PROCESSING) {
				recog_processing = 0;
			}

			if (sar_session.recog_channel->mutex != NULL) {
				apr_thread_mutex_unlock(sar_session.recog_channel->mutex);
			}
		}

		if (recog_processing == 0)
			break;

		if (synth_processing == 1) {
			if (sar_session.synth_channel->state != SPEECH_CHANNEL_PROCESSING) {
				ast_log(LOG_DEBUG, "(%s) Start input timers\n", recog_name);
				recog_channel_start_input_timers(sar_session.recog_channel);
				synth_processing = 0;
			}
			else if (r && r->start_of_input) {
				ast_log(LOG_DEBUG, "(%s) Bargein occurred\n", recog_name);
				synth_channel_bargein_occurred(sar_session.synth_channel);
				synth_processing = 0;
			}
		}

		if (waitres == 0)
			continue;

		f = ast_read(chan);
		if (!f) {
			ast_log(LOG_DEBUG, "(%s) Null frame. Hangup detected\n", recog_name);
			status = SPEECH_CHANNEL_STATUS_INTERRUPTED;
			break;
		}

		if (f->frametype == AST_FRAME_VOICE) {
			len = f->datalen;
			if (speech_channel_write(sar_session.recog_channel, ast_frame_get_data(f), &len) != 0) {
				ast_frfree(f);
				break;
			}
		} else if (f->frametype == AST_FRAME_VIDEO) {
			/* Ignore. */
		} else if (f->frametype == AST_FRAME_DTMF) {
			int dtmfkey = ast_frame_get_dtmfkey(f);
			ast_log(LOG_DEBUG, "(%s) User pressed DTMF key (%d)\n", recog_name, dtmfkey);
			/* Send DTMF frame to ASR engine. */
			if (sar_session.recog_channel->dtmf_generator != NULL) {
				char digits[2];
				digits[0] = (char)dtmfkey;
				digits[1] = '\0';

				ast_log(LOG_NOTICE, "(%s) DTMF digit queued (%s)\n", sar_session.recog_channel->name, digits);
				mpf_dtmf_generator_enqueue(sar_session.recog_channel->dtmf_generator, digits);
			}
		}

		ast_frfree(f);
	}

	const char *completion_cause = NULL;
	const char *result = NULL;
	const char *waveform_uri = NULL;

	if (status == SPEECH_CHANNEL_STATUS_OK) {
		int uri_encoded_results = 0;
		/* Check if the results should be URI-encoded */
		if ((sar_options.flags & SAR_URI_ENCODED_RESULTS) == SAR_URI_ENCODED_RESULTS) {
			if (!ast_strlen_zero(sar_options.params[OPT_ARG_URI_ENCODED_RESULTS])) {
				uri_encoded_results = (atoi(sar_options.params[OPT_ARG_URI_ENCODED_RESULTS]) == 0) ? 0 : 1;
			}
		}

		/* Get recognition result. */
		if (recog_channel_get_results(sar_session.recog_channel, uri_encoded_results, &completion_cause, &result, &waveform_uri) != 0) {
			ast_log(LOG_WARNING, "(%s) Unable to retrieve result\n", recog_name);
			return synthandrecog_exit(chan, &sar_session, SPEECH_CHANNEL_STATUS_ERROR);
		}
	}

	/* Completion cause should always be available at this stage. */
	if (completion_cause)
		pbx_builtin_setvar_helper(chan, "RECOG_COMPLETION_CAUSE", completion_cause);

	/* Result may not be available if recognition completed with nomatch, noinput, or other error cause. */
	pbx_builtin_setvar_helper(chan, "RECOG_RESULT", result ? result : "");

	/* If Waveform URI is available, pass it further to dialplan. */
	if (waveform_uri)
		pbx_builtin_setvar_helper(chan, "RECOG_WAVEFORM_URI", waveform_uri);

	return synthandrecog_exit(chan, &sar_session, status);
}

/* Process messages from UniMRCP for the synthandrecog application. */
static apt_bool_t synthandrecog_message_handler(const mrcp_app_message_t *app_message)
{
	/* Call the appropriate callback in the dispatcher function table based on the app_message received. */
	if (app_message)
		return mrcp_application_message_dispatch(&synthandrecog->dispatcher, app_message);

	ast_log(LOG_ERROR, "(unknown) app_message error!\n");
	return TRUE;
}

/* Load SynthAndRecog application. */
int load_synthandrecog_app()
{
	apr_pool_t *pool = globals.pool;

	if (pool == NULL) {
		ast_log(LOG_ERROR, "Memory pool is NULL\n");
		return -1;
	}

	if(synthandrecog) {
		ast_log(LOG_ERROR, "Application %s is already loaded\n", synthandrecog_name);
		return -1;
	}

	synthandrecog = (ast_mrcp_application_t*) apr_palloc(pool, sizeof(ast_mrcp_application_t));
	synthandrecog->name = synthandrecog_name;
	synthandrecog->exec = app_synthandrecog_exec;
#if !AST_VERSION_AT_LEAST(1,6,2)
	synthandrecog->synopsis = NULL;
	synthandrecog->description = NULL;
#endif

	/* Create the recognizer application and link its callbacks */
	if ((synthandrecog->app = mrcp_application_create(synthandrecog_message_handler, (void *)0, pool)) == NULL) {
		ast_log(LOG_ERROR, "Unable to create MRCP application %s\n", synthandrecog_name);
		synthandrecog = NULL;
		return -1;
	}

	synthandrecog->dispatcher.on_session_update = NULL;
	synthandrecog->dispatcher.on_session_terminate = speech_on_session_terminate;
	synthandrecog->dispatcher.on_channel_add = speech_on_channel_add;
	synthandrecog->dispatcher.on_channel_remove = speech_on_channel_remove;
	synthandrecog->dispatcher.on_message_receive = speech_on_message_receive;
	synthandrecog->audio_stream_vtable.destroy = NULL;
	synthandrecog->audio_stream_vtable.open_rx = recog_stream_open;
	synthandrecog->audio_stream_vtable.close_rx = NULL;
	synthandrecog->audio_stream_vtable.read_frame = recog_stream_read;
	synthandrecog->audio_stream_vtable.open_tx = NULL;
	synthandrecog->audio_stream_vtable.close_tx = NULL;
	synthandrecog->audio_stream_vtable.write_frame = synth_stream_write;
	synthandrecog->audio_stream_vtable.trace = NULL;

	if (!mrcp_client_application_register(globals.mrcp_client, synthandrecog->app, synthandrecog_name)) {
		ast_log(LOG_ERROR, "Unable to register MRCP application %s\n", synthandrecog_name);
		if (!mrcp_application_destroy(synthandrecog->app))
			ast_log(LOG_WARNING, "Unable to destroy MRCP application %s\n", synthandrecog_name);
		synthandrecog = NULL;
		return -1;
	}

	apr_hash_set(globals.apps, synthandrecog_name, APR_HASH_KEY_STRING, synthandrecog);

	return 0;
}

/* Unload SynthAndRecog application. */
int unload_synthandrecog_app()
{
	if(!synthandrecog) {
		ast_log(LOG_ERROR, "Application %s doesn't exist\n", synthandrecog_name);
		return -1;
	}
	
	apr_hash_set(globals.apps, synthandrecog_name, APR_HASH_KEY_STRING, NULL);
	synthandrecog = NULL;

	return 0;
}
