/*
 *   Rocket.Chat plugin for libpurple
 *   Copyright (C) 2016  Eion Robb
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

// Glib
#include <glib.h>

#if !GLIB_CHECK_VERSION(2, 32, 0)
#define g_hash_table_contains(hash_table, key) g_hash_table_lookup_extended(hash_table, key, NULL, NULL)
#endif /* 2.32.0 */

static gboolean
g_str_insensitive_equal(gconstpointer v1, gconstpointer v2)
{
	return (g_ascii_strcasecmp(v1, v2) == 0);
}
static guint
g_str_insensitive_hash(gconstpointer v)
{
	guint hash;
	gchar *lower_str = g_ascii_strdown(v, -1);
	
	hash = g_str_hash(lower_str);
	g_free(lower_str);
	
	return hash;
}


// GNU C libraries
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef __GNUC__
	#include <unistd.h>
#endif
#include <errno.h>

#include <json-glib/json-glib.h>
// Supress overzealous json-glib 'critical errors'
#define json_object_get_int_member(JSON_OBJECT, MEMBER) \
	(json_object_has_member(JSON_OBJECT, MEMBER) ? json_object_get_int_member(JSON_OBJECT, MEMBER) : 0)
#define json_object_get_string_member(JSON_OBJECT, MEMBER) \
	(json_object_has_member(JSON_OBJECT, MEMBER) ? json_object_get_string_member(JSON_OBJECT, MEMBER) : NULL)
#define json_object_get_array_member(JSON_OBJECT, MEMBER) \
	(json_object_has_member(JSON_OBJECT, MEMBER) ? json_object_get_array_member(JSON_OBJECT, MEMBER) : NULL)
#define json_object_get_object_member(JSON_OBJECT, MEMBER) \
	(json_object_has_member(JSON_OBJECT, MEMBER) ? json_object_get_object_member(JSON_OBJECT, MEMBER) : NULL)
#define json_object_get_boolean_member(JSON_OBJECT, MEMBER) \
	(json_object_has_member(JSON_OBJECT, MEMBER) ? json_object_get_boolean_member(JSON_OBJECT, MEMBER) : FALSE)


// static void
// json_array_foreach_element_reverse (JsonArray        *array,
                                    // JsonArrayForeach  func,
                                    // gpointer          data)
// {
	// gint i;

	// g_return_if_fail (array != NULL);
	// g_return_if_fail (func != NULL);

	// for (i = json_array_get_length(array) - 1; i >= 0; i--)
	// {
		// JsonNode *element_node;

		// element_node = json_array_get_element(array, i);

		// (* func) (array, i, element_node, data);
	// }
// }


#include <purple.h>
#if PURPLE_VERSION_CHECK(3, 0, 0)
#include <http.h>
#endif

#ifndef PURPLE_PLUGINS
#	define PURPLE_PLUGINS
#endif

#ifndef _
#	define _(a) (a)
#	define N_(a) (a)
#endif

#define ROCKETCHAT_PLUGIN_ID "prpl-eionrobb-rocketchat"
#ifndef ROCKETCHAT_PLUGIN_VERSION
#define ROCKETCHAT_PLUGIN_VERSION "0.1"
#endif
#define ROCKETCHAT_PLUGIN_WEBSITE "https://github.com/EionRobb/rocketchat-libpurple"

#define ROCKETCHAT_USERAGENT "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36"

#define ROCKETCHAT_BUFFER_DEFAULT_SIZE 40960

#define RC_DEFAULT_SERVER ""
#define RC_SERVER_SPLIT_CHAR '|'


// Purple2 compat functions
#if !PURPLE_VERSION_CHECK(3, 0, 0)

#define purple_connection_error                 purple_connection_error_reason
#define purple_connection_get_protocol          purple_connection_get_prpl
#define PURPLE_CONNECTION_CONNECTING       PURPLE_CONNECTING
#define PURPLE_CONNECTION_CONNECTED        PURPLE_CONNECTED
#define purple_blist_find_group        purple_find_group
#define purple_protocol_get_id  purple_plugin_get_id
#define PurpleProtocolChatEntry  struct proto_chat_entry
#define PurpleChatConversation             PurpleConvChat
#define PurpleIMConversation               PurpleConvIm
#define purple_conversations_find_chat_with_account(id, account) \
		PURPLE_CONV_CHAT(purple_find_conversation_with_account(PURPLE_CONV_TYPE_CHAT, id, account))
#define purple_chat_conversation_has_left     purple_conv_chat_has_left
#define PurpleConversationUpdateType          PurpleConvUpdateType
#define PURPLE_CONVERSATION_UPDATE_UNSEEN     PURPLE_CONV_UPDATE_UNSEEN
#define PURPLE_IS_IM_CONVERSATION(conv)       (purple_conversation_get_type(conv) == PURPLE_CONV_TYPE_IM)
#define PURPLE_IS_CHAT_CONVERSATION(conv)     (purple_conversation_get_type(conv) == PURPLE_CONV_TYPE_CHAT)
#define PURPLE_CONVERSATION(chatorim)         (chatorim == NULL ? NULL : chatorim->conv)
#define PURPLE_IM_CONVERSATION(conv)          PURPLE_CONV_IM(conv)
#define PURPLE_CHAT_CONVERSATION(conv)        PURPLE_CONV_CHAT(conv)
#define purple_serv_got_joined_chat(pc, id, name)  PURPLE_CONV_CHAT(serv_got_joined_chat(pc, id, name))
#define purple_conversations_find_chat(pc, id)  PURPLE_CONV_CHAT(purple_find_chat(pc, id))
#define purple_serv_got_chat_in                    serv_got_chat_in
#define purple_chat_conversation_add_user     purple_conv_chat_add_user
#define purple_chat_conversation_add_users    purple_conv_chat_add_users
#define purple_chat_conversation_remove_user  purple_conv_chat_remove_user
#define purple_chat_conversation_get_topic    purple_conv_chat_get_topic
#define purple_chat_conversation_set_topic    purple_conv_chat_set_topic
#define PurpleChatUserFlags  PurpleConvChatBuddyFlags
#define PURPLE_CHAT_USER_NONE     PURPLE_CBFLAGS_NONE
#define PURPLE_CHAT_USER_OP       PURPLE_CBFLAGS_OP
#define PURPLE_CHAT_USER_FOUNDER  PURPLE_CBFLAGS_FOUNDER
#define PURPLE_CHAT_USER_TYPING   PURPLE_CBFLAGS_TYPING
#define PURPLE_CHAT_USER_AWAY     PURPLE_CBFLAGS_AWAY
#define PURPLE_CHAT_USER_HALFOP   PURPLE_CBFLAGS_HALFOP
#define PURPLE_CHAT_USER_VOICE    PURPLE_CBFLAGS_VOICE
#define PURPLE_CHAT_USER_TYPING   PURPLE_CBFLAGS_TYPING
#define PurpleChatUser  PurpleConvChatBuddy
static inline PurpleChatUser *
purple_chat_conversation_find_user(PurpleChatConversation *chat, const char *name)
{
	PurpleChatUser *cb = purple_conv_chat_cb_find(chat, name);
	
	if (cb != NULL) {
		g_dataset_set_data(cb, "chat", chat);
	}
	
	return cb;
}
#define purple_chat_user_get_flags(cb)     purple_conv_chat_user_get_flags(g_dataset_get_data((cb), "chat"), (cb)->name)
#define purple_chat_user_set_flags(cb, f)  purple_conv_chat_user_set_flags(g_dataset_get_data((cb), "chat"), (cb)->name, (f))
#define purple_chat_user_set_alias(cb, a)  ((cb)->alias = (a))
#define PurpleIMTypingState	PurpleTypingState
#define PURPLE_IM_NOT_TYPING	PURPLE_NOT_TYPING
#define PURPLE_IM_TYPING	PURPLE_TYPING
#define PURPLE_IM_TYPED		PURPLE_TYPED
#define purple_conversation_get_connection      purple_conversation_get_gc
#define purple_chat_conversation_get_id         purple_conv_chat_get_id
#define PURPLE_CMD_FLAG_PROTOCOL_ONLY  PURPLE_CMD_FLAG_PRPL_ONLY
#define PURPLE_IS_BUDDY                PURPLE_BLIST_NODE_IS_BUDDY
#define PURPLE_IS_CHAT                 PURPLE_BLIST_NODE_IS_CHAT
#define purple_chat_get_name_only      purple_chat_get_name
#define purple_blist_find_buddy        purple_find_buddy
#define purple_serv_got_alias                      serv_got_alias
#define purple_account_set_private_alias    purple_account_set_alias
#define purple_account_get_private_alias    purple_account_get_alias
#define purple_protocol_got_user_status		purple_prpl_got_user_status
#define purple_serv_got_im                         serv_got_im
#define purple_serv_got_typing                     serv_got_typing
#define purple_conversations_find_im_with_account(name, account)  \
		PURPLE_CONV_IM(purple_find_conversation_with_account(PURPLE_CONV_TYPE_IM, name, account))
#define purple_im_conversation_new(account, from) PURPLE_CONV_IM(purple_conversation_new(PURPLE_CONV_TYPE_IM, account, from))
#define PurpleMessage  PurpleConvMessage
#define purple_message_set_time(msg, time)  ((msg)->when = (time))
#define purple_conversation_write_message(conv, msg)  purple_conversation_write(conv, msg->who, msg->what, msg->flags, msg->when)
static inline PurpleMessage *
purple_message_new_outgoing(const gchar *who, const gchar *contents, PurpleMessageFlags flags)
{
	PurpleMessage *message = g_new0(PurpleMessage, 1);
	
	message->who = g_strdup(who);
	message->what = g_strdup(contents);
	message->flags = flags;
	message->when = time(NULL);
	
	return message;
}
static inline void
purple_message_destroy(PurpleMessage *message)
{
	g_free(message->who);
	g_free(message->what);
	g_free(message);
}

#define purple_message_get_recipient(message)  (message->who)
#define purple_message_get_contents(message)   (message->what)

#define purple_account_privacy_deny_add     purple_privacy_deny_add
#define purple_account_privacy_deny_remove  purple_privacy_deny_remove
#define PurpleHttpConnection  PurpleUtilFetchUrlData
#define purple_buddy_set_name  purple_blist_rename_buddy

#else
// Purple3 helper functions
#define purple_conversation_set_data(conv, key, value)  g_object_set_data(G_OBJECT(conv), key, value)
#define purple_conversation_get_data(conv, key)         g_object_get_data(G_OBJECT(conv), key)
#define purple_message_destroy          g_object_unref
#endif


typedef struct {
	PurpleAccount *account;
	PurpleConnection *pc;
	
	GHashTable *cookie_table;
	gchar *session_token;
	gchar *channel;
	gchar *self_user;
	
	gint64 last_message_timestamp;
	gint64 last_load_last_message_timestamp;
	
	gchar *username;
	gchar *server;
	
	PurpleSslConnection *websocket;
	gboolean websocket_header_received;
	gboolean sync_complete;
	guchar packet_code;
	gchar *frame;
	guint64 frame_len;
	guint64 frame_len_progress;
	
	gint64 id; //incrementing counter
	
	GHashTable *one_to_ones;      // A store of known room_id's -> username's
	GHashTable *one_to_ones_rev;  // A store of known usernames's -> room_id's
	GHashTable *group_chats;      // A store of known multi-user room_id's -> room name's
	GHashTable *group_chats_rev;  // A store of known multi-user room name's -> room_id's
	GHashTable *sent_message_ids; // A store of message id's that we generated from this instance
	GHashTable *result_callbacks; // Result ID -> Callback function
	GHashTable *usernames_to_ids; // username -> user id
	GHashTable *ids_to_usernames; // user id -> username

	GSList *http_conns; /**< PurpleHttpConnection to be cancelled on logout */
	gint frames_since_reconnect;
	GSList *pending_writes;
} RocketChatAccount;

typedef void (*RocketChatProxyCallbackFunc)(RocketChatAccount *ya, JsonNode *node, gpointer user_data);

typedef struct {
	RocketChatAccount *ya;
	RocketChatProxyCallbackFunc callback;
	gpointer user_data;
} RocketChatProxyConnection;



//#include <mkdio.h>
int mkd_line(char *, int, char **, int);

#define MKD_NOLINKS	0x00000001	/* don't do link processing, block <a> tags  */
#define MKD_NOIMAGE	0x00000002	/* don't do image processing, block <img> */
#define MKD_NOPANTS	0x00000004	/* don't run smartypants() */
#define MKD_NOHTML	0x00000008	/* don't allow raw html through AT ALL */
#define MKD_STRICT	0x00000010	/* disable SUPERSCRIPT, RELAXED_EMPHASIS */
#define MKD_TAGTEXT	0x00000020	/* process text inside an html tag; no
					 * <em>, no <bold>, no html or [] expansion */
#define MKD_NO_EXT	0x00000040	/* don't allow pseudo-protocols */
#define MKD_NOEXT	MKD_NO_EXT	/* ^^^ (aliased for user convenience) */
#define MKD_CDATA	0x00000080	/* generate code for xml ![CDATA[...]] */
#define MKD_NOSUPERSCRIPT 0x00000100	/* no A^B */
#define MKD_NORELAXED	0x00000200	/* emphasis happens /everywhere/ */
#define MKD_NOTABLES	0x00000400	/* disallow tables */
#define MKD_NOSTRIKETHROUGH 0x00000800	/* forbid ~~strikethrough~~ */
#define MKD_TOC		0x00001000	/* do table-of-contents processing */
#define MKD_1_COMPAT	0x00002000	/* compatibility with MarkdownTest_1.0 */
#define MKD_AUTOLINK	0x00004000	/* make http://foo.com link even without <>s */
#define MKD_SAFELINK	0x00008000	/* paranoid check for link protocol */
#define MKD_NOHEADER	0x00010000	/* don't process header blocks */
#define MKD_TABSTOP	0x00020000	/* expand tabs to 4 spaces */
#define MKD_NODIVQUOTE	0x00040000	/* forbid >%class% blocks */
#define MKD_NOALPHALIST	0x00080000	/* forbid alphabetic lists */
#define MKD_NODLIST	0x00100000	/* forbid definition lists */
#define MKD_EXTRA_FOOTNOTE 0x00200000	/* enable markdown extra-style footnotes */
#define MKD_NOSTYLE	0x00400000	/* don't extract <style> blocks */
#define MKD_NODLDISCOUNT 0x00800000	/* disable discount-style definition lists */
#define	MKD_DLEXTRA	0x01000000	/* enable extra-style definition lists */
#define MKD_FENCEDCODE	0x02000000	/* enabled fenced code blocks */
#define MKD_IDANCHOR	0x04000000	/* use id= anchors for TOC links */
#define MKD_GITHUBTAGS	0x08000000	/* allow dash and underscore in element names */
#define MKD_URLENCODEDANCHOR 0x10000000 /* urlencode non-identifier chars instead of replacing with dots */
#define MKD_LATEX	0x40000000	/* handle embedded LaTeX escapes */

#define MKD_EMBED	MKD_NOLINKS|MKD_NOIMAGE|MKD_TAGTEXT

static gchar *
rc_markdown_to_html(const gchar *markdown)
{
	static char *markdown_str = NULL;
	int markdown_len;
	int flags = MKD_NOPANTS | MKD_NOHEADER | MKD_NODIVQUOTE | MKD_NODLIST;
	
	if (markdown_str != NULL) {
		free(markdown_str);
	}
	
	markdown_len = mkd_line((char *)markdown, strlen(markdown), &markdown_str, flags);

	if (markdown_len < 0) {
		return NULL;
	}
	
	return g_strndup(markdown_str, markdown_len);
}


// static gchar *
// purple_base32_encode(const guchar *data, gsize len)
// {
	// static const char base32_alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
	// char *out, *rv;
	// guchar work[5];
	
	// g_return_val_if_fail(data != NULL, NULL);
	// g_return_val_if_fail(len > 0,  NULL);
	
	// rv = out = g_malloc(((len / 5) + 1) * 8 + 1);
	
	// for (; len; len -= MIN(5, len))
	// {
		// memset(work, 0, 5);
		// memcpy(work, data, MIN(5, len));
		
		// *out++ = base32_alphabet[work[0] >> 3];
		// *out++ = base32_alphabet[((work[0] & 0x07) << 2) | (work[1] >> 6)];
		// *out++ = base32_alphabet[(work[1] >> 1) & 0x1f];
		// *out++ = base32_alphabet[((work[1] & 0x01) << 4) | (work[2] >> 4)];
		// *out++ = base32_alphabet[((work[2] & 0x0f) << 1) | (work[3] >> 7)];
		// *out++ = base32_alphabet[(work[3] >> 2) & 0x1f];
		// *out++ = base32_alphabet[((work[3] & 0x03) << 3) | (work[4] >> 5)];
		// *out++ = base32_alphabet[work[4] & 0x1f];
		
		// data += MIN(5, len);
	// }
	
	// *out = '\0';
	
	// return rv;
// }

static const gchar *
rc_get_next_id_str(RocketChatAccount *ya) {
	static gchar *next_id = NULL;
	g_free(next_id);
	
	next_id = g_strdup_printf("%" G_GINT64_FORMAT, ya->id++);
	
	return next_id;
}

static const gchar *
rc_get_next_id_str_callback(RocketChatAccount *ya, RocketChatProxyCallbackFunc callback, gpointer user_data)
{
	const gchar *id = rc_get_next_id_str(ya);
	RocketChatProxyConnection *proxy = g_new0(RocketChatProxyConnection, 1);
	
	proxy->ya = ya;
	proxy->callback = callback;
	proxy->user_data = user_data;
	
	g_hash_table_insert(ya->result_callbacks, g_strdup(id), proxy);
	
	return id;
}

gchar *
rc_string_get_chunk(const gchar *haystack, gsize len, const gchar *start, const gchar *end)
{
	const gchar *chunk_start, *chunk_end;
	g_return_val_if_fail(haystack && start && end, NULL);
	
	if (len > 0) {
		chunk_start = g_strstr_len(haystack, len, start);
	} else {
		chunk_start = strstr(haystack, start);
	}
	g_return_val_if_fail(chunk_start, NULL);
	chunk_start += strlen(start);
	
	if (len > 0) {
		chunk_end = g_strstr_len(chunk_start, len - (chunk_start - haystack), end);
	} else {
		chunk_end = strstr(chunk_start, end);
	}
	g_return_val_if_fail(chunk_end, NULL);
	
	return g_strndup(chunk_start, chunk_end - chunk_start);
}

#if PURPLE_VERSION_CHECK(3, 0, 0)
static void
rc_update_cookies(RocketChatAccount *ya, const GList *cookie_headers)
{
	const gchar *cookie_start;
	const gchar *cookie_end;
	gchar *cookie_name;
	gchar *cookie_value;
	const GList *cur;
	
	for (cur = cookie_headers; cur != NULL; cur = g_list_next(cur))
	{
		cookie_start = cur->data;
		
		cookie_end = strchr(cookie_start, '=');
		cookie_name = g_strndup(cookie_start, cookie_end-cookie_start);
		cookie_start = cookie_end + 1;
		cookie_end = strchr(cookie_start, ';');
		cookie_value= g_strndup(cookie_start, cookie_end-cookie_start);
		cookie_start = cookie_end;

		g_hash_table_replace(ya->cookie_table, cookie_name, cookie_value);
	}
}

#else
static void
rc_update_cookies(RocketChatAccount *ya, const gchar *headers)
{
	const gchar *cookie_start;
	const gchar *cookie_end;
	gchar *cookie_name;
	gchar *cookie_value;
	int header_len;

	g_return_if_fail(headers != NULL);

	header_len = strlen(headers);

	/* look for the next "Set-Cookie: " */
	/* grab the data up until ';' */
	cookie_start = headers;
	while ((cookie_start = strstr(cookie_start, "\r\nSet-Cookie: ")) && (cookie_start - headers) < header_len)
	{
		cookie_start += 14;
		cookie_end = strchr(cookie_start, '=');
		cookie_name = g_strndup(cookie_start, cookie_end-cookie_start);
		cookie_start = cookie_end + 1;
		cookie_end = strchr(cookie_start, ';');
		cookie_value= g_strndup(cookie_start, cookie_end-cookie_start);
		cookie_start = cookie_end;

		g_hash_table_replace(ya->cookie_table, cookie_name, cookie_value);
	}
}
#endif

static void
rc_cookie_foreach_cb(gchar *cookie_name, gchar *cookie_value, GString *str)
{
	g_string_append_printf(str, "%s=%s;", cookie_name, cookie_value);
}

static gchar *
rc_cookies_to_string(RocketChatAccount *ya)
{
	GString *str;

	str = g_string_new(NULL);

	g_hash_table_foreach(ya->cookie_table, (GHFunc)rc_cookie_foreach_cb, str);

	return g_string_free(str, FALSE);
}

static void
rc_response_callback(PurpleHttpConnection *http_conn, 
#if PURPLE_VERSION_CHECK(3, 0, 0)
PurpleHttpResponse *response, gpointer user_data)
{
	gsize len;
	const gchar *url_text = purple_http_response_get_data(response, &len);
#else
gpointer user_data, const gchar *url_text, gsize len, const gchar *error_message)
{
#endif
	const gchar *body;
	gsize body_len;
	RocketChatProxyConnection *conn = user_data;
	JsonParser *parser = json_parser_new();
	
	conn->ya->http_conns = g_slist_remove(conn->ya->http_conns, http_conn);

#if !PURPLE_VERSION_CHECK(3, 0, 0)
	rc_update_cookies(conn->ya, url_text);
	
	body = g_strstr_len(url_text, len, "\r\n\r\n");
	body = body ? body + 4 : body;
	body_len = len - (body - url_text);
#else
	rc_update_cookies(conn->ya, purple_http_response_get_headers_by_name(response, "Set-Cookie"));

	body = url_text;
	body_len = len;
#endif
	
	if (!json_parser_load_from_data(parser, body, body_len, NULL))
	{
		//purple_debug_error("rocketchat", "Error parsing response: %s\n", body);
		if (conn->callback) {
			JsonNode *dummy_node = json_node_new(JSON_NODE_OBJECT);
			JsonObject *dummy_object = json_object_new();
			
			json_node_set_object(dummy_node, dummy_object);
			json_object_set_string_member(dummy_object, "body", body);
			json_object_set_int_member(dummy_object, "len", body_len);
			g_dataset_set_data(dummy_node, "raw_body", (gpointer) body);
			
			conn->callback(conn->ya, dummy_node, conn->user_data);
			
			g_dataset_destroy(dummy_node);
			json_node_free(dummy_node);
			json_object_unref(dummy_object);
		}
	} else {
		JsonNode *root = json_parser_get_root(parser);
		
		purple_debug_misc("rocketchat", "Got response: %s\n", body);
		if (conn->callback) {
			conn->callback(conn->ya, root, conn->user_data);
		}
	}
	
	g_object_unref(parser);
	g_free(conn);
}

static void
rc_fetch_url(RocketChatAccount *ya, const gchar *url, const gchar *postdata, RocketChatProxyCallbackFunc callback, gpointer user_data)
{
	PurpleAccount *account;
	RocketChatProxyConnection *conn;
	gchar *cookies;
	PurpleHttpConnection *http_conn;
	
	account = ya->account;
	if (purple_account_is_disconnected(account)) return;
	
	conn = g_new0(RocketChatProxyConnection, 1);
	conn->ya = ya;
	conn->callback = callback;
	conn->user_data = user_data;
	
	cookies = rc_cookies_to_string(ya);
	
	purple_debug_info("rocketchat", "Fetching url %s\n", url);

#if PURPLE_VERSION_CHECK(3, 0, 0)
	
	PurpleHttpRequest *request = purple_http_request_new(url);
	purple_http_request_header_set(request, "Accept", "*/*");
	purple_http_request_header_set(request, "User-Agent", ROCKETCHAT_USERAGENT);
	purple_http_request_header_set(request, "Cookie", cookies);
	
	if (postdata) {
		purple_debug_info("rocketchat", "With postdata %s\n", postdata);
		
		if (postdata[0] == '{') {
			purple_http_request_header_set(request, "Content-Type", "application/json");
		} else {
			purple_http_request_header_set(request, "Content-Type", "application/x-www-form-urlencoded");
		}
		purple_http_request_set_contents(request, postdata, -1);
	}
	
	http_conn = purple_http_request(ya->pc, request, rc_response_callback, conn);
	purple_http_request_unref(request);

	if (http_conn != NULL)
		ya->http_conns = g_slist_prepend(ya->http_conns, http_conn);

#else
	GString *headers;
	gchar *host = NULL, *path = NULL, *user = NULL, *password = NULL;
	int port;
	purple_url_parse(url, &host, &port, &path, &user, &password);
	
	headers = g_string_new(NULL);
	
	//Use the full 'url' until libpurple can handle path's longer than 256 chars
	g_string_append_printf(headers, "%s /%s HTTP/1.0\r\n", (postdata ? "POST" : "GET"), path);
	//g_string_append_printf(headers, "%s %s HTTP/1.0\r\n", (postdata ? "POST" : "GET"), url);
	g_string_append_printf(headers, "Connection: close\r\n");
	g_string_append_printf(headers, "Host: %s\r\n", host);
	g_string_append_printf(headers, "Accept: */*\r\n");
	g_string_append_printf(headers, "User-Agent: " ROCKETCHAT_USERAGENT "\r\n");
	g_string_append_printf(headers, "Cookie: %s\r\n", cookies);

	if (postdata) {
		purple_debug_info("rocketchat", "With postdata %s\n", postdata);
		
		if (postdata[0] == '{') {
			g_string_append(headers, "Content-Type: application/json\r\n");
		} else {
			g_string_append(headers, "Content-Type: application/x-www-form-urlencoded\r\n");
		}
		g_string_append_printf(headers, "Content-Length: %" G_GSIZE_FORMAT "\r\n", strlen(postdata));
		g_string_append(headers, "\r\n");

		g_string_append(headers, postdata);
	} else {
		g_string_append(headers, "\r\n");
	}

	g_free(host);
	g_free(path);
	g_free(user);
	g_free(password);

	http_conn = purple_util_fetch_url_request_len_with_account(ya->account, url, FALSE, ROCKETCHAT_USERAGENT, TRUE, headers->str, TRUE, 6553500, rc_response_callback, conn);
	
	if (http_conn != NULL)
		ya->http_conns = g_slist_prepend(ya->http_conns, http_conn);

	g_string_free(headers, TRUE);
#endif

	g_free(cookies);
}


static void rc_join_room(RocketChatAccount *ya, const gchar *room_id);
void rc_block_user(PurpleConnection *pc, const char *who);
static void rc_socket_write_json(RocketChatAccount *ya, JsonObject *data);
static GHashTable *rc_chat_info_defaults(PurpleConnection *pc, const char *chatname);
static void rc_mark_room_messages_read(RocketChatAccount *ya, const gchar *room_id);
static void rc_account_connected(RocketChatAccount *ya, JsonNode *node, gpointer user_data);

static void
rc_login_response(RocketChatAccount *ya, JsonNode *node, gpointer user_data)
{
	JsonObject *response;

	if (node == NULL) {
		purple_connection_error(ya->pc, PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED, "Bad username/password");
		return;
	}
	
	if (ya->session_token != NULL && ya->self_user != NULL) {
		// Resubscribe if we're reestablishing a session
		rc_account_connected(ya, NULL, NULL);
	}
	
	response = json_node_get_object(node);
	
	if (json_object_has_member(response, "token")) {
		ya->session_token = g_strdup(json_object_get_string_member(response, "token"));
	}//a["{\"msg\":\"result\",\"id\":\"1\",\"result\":{\"id\":\"hZKg86uJavE6jYLya\",\"token\":\"OvG63dE9x79demZnrmBv4vnYYlGMMB-wRKVWFcTxQbv\",\"tokenExpires\":{\"$date\":1485062242977}}}"]
	//a["{\"msg\":\"result\",\"id\":\"5\",\"error\":{\"error\":403,\"reason\":\"User has no password set\",\"message\":\"User has no password set [403]\",\"errorType\":\"Meteor.Error\"}}"]
}

static void
rc_got_open_rooms(RocketChatAccount *ya, JsonNode *node, gpointer user_data)
{
	//a["{\"msg\":\"result\",\"id\":\"9\",\"result\":{\"update\":[{\"_id\":\"GENERAL\",\"name\":\"general\",\"t\":\"c\",\"topic\":\"Community support in [#support](https://demo.rocket.chat/channel/support).  Developers in [#dev](https://demo.rocket.chat/channel/dev)\",\"muted\":[\"daly\",\"kkloggg\",\"staci.holmes.segarra\"],\"jitsiTimeout\":{\"$date\":1476781304981},\"default\":true},{\"_id\":\"YdpayxcMhWFGKRZb3hZKg86uJavE6jYLya\",\"t\":\"d\"},{\"_id\":\"hZKg86uJavE6jYLyavxiySsLD8gLjgnmnN\",\"t\":\"d\"},{\"_id\":\"2urrp3DyDkLxoMAd3hZKg86uJavE6jYLya\",\"t\":\"d\"},{\"_id\":\"QFhAaDzea7cFK6ChB\",\"name\":\"test-private\",\"t\":\"p\",\"u\":{\"_id\":null,\"username\":null},\"ro\":false},{\"_id\":\"b98BYkRbiD5swDfyY\",\"name\":\"dev\",\"t\":\"c\",\"u\":{\"_id\":\"yhHvK7uhhXh9DqKWH\",\"username\":\"diego.sampaio\"},\"topic\":\"Community and core devs hangout.  Learn code in [#learn](https://demo.rocket.chat/channel/learn).  Get support in [#support](https://demo.rocket.chat/channel/support)\",\"muted\":[\"geektest123\"],\"jitsiTimeout\":{\"$date\":1465876457842}},{\"_id\":\"JoxbibGnXizRb4ef4hZKg86uJavE6jYLya\",\"t\":\"d\"}],\"remove\":[{\"_id\":\"8cXLWPathApTRXHZZ\",\"_deletedAt\":{\"$date\":1477179315230}}]}}"]
	
	JsonObject *result = json_node_get_object(node);
	JsonArray *update = json_object_get_array_member(result, "update");
	gint i, len = json_array_get_length(update);
	
	for(i = 0; i < len; i++) {
		JsonObject *room_info = json_array_get_object_element(update, i);
		const gchar *room_type = json_object_get_string_member(room_info, "t");
		
		if (*room_type != 'd') {
			const gchar *topic = json_object_get_string_member(room_info, "topic");
			const gchar *room_name = json_object_get_string_member(room_info, "name");
			PurpleChatConversation *chatconv = purple_conversations_find_chat_with_account(room_name, ya->account);
			if (chatconv == NULL) {
				const gchar *room_id = json_object_get_string_member(room_info, "_id");
				chatconv = purple_conversations_find_chat_with_account(room_id, ya->account);
			}

			if (chatconv != NULL && topic != NULL) {
				gchar *html_topic = rc_markdown_to_html(topic);
				purple_chat_conversation_set_topic(chatconv, NULL, html_topic);
				g_free(html_topic);
			}
		}
	}
}

static void
rc_account_connected(RocketChatAccount *ya, JsonNode *node, gpointer user_data)
{
	// Subscribe to user presences
	//["{\"msg\":\"sub\",\"id\":\"WMzRMsMY58EKeBcBE\",\"name\":\"activeUsers\",\"params\":[]}"]
	JsonObject *data = json_object_new();
	JsonObject *date;
	JsonArray *params;
	gchar *id;
	
	json_object_set_string_member(data, "msg", "sub");
	
	id = g_strdup_printf("%012XFFFF", g_random_int());
	json_object_set_string_member(data, "id", id);
	g_free(id);
	
	json_object_set_string_member(data, "name", "activeUsers");
	json_object_set_array_member(data, "params", json_array_new());
	
	rc_socket_write_json(ya, data);
	
	// Subscribe to all direct messages rooms
	{
		GList *l, *dm_room_ids = g_hash_table_get_keys(ya->one_to_ones);
		for (l = dm_room_ids; l; l = l->next) {
			rc_join_room(ya, l->data);
		}
		g_list_free(dm_room_ids);
	}
	
	if (ya->self_user) {
		const gchar *subs[] = {"notification", "rooms-changed", "subscriptions-changed", "otr", NULL};
		guint i;
		const gchar *self_id = g_hash_table_lookup(ya->usernames_to_ids, ya->self_user);
		gchar *param_id;
		
	//["{\"msg\":\"sub\",\"id\":\"j3rDKZiswk48oD3xq\",\"name\":\"stream-notify-user\",\"params\":[\"hZKg86uJavE6jYLya/notification\",false]}"]
	//["{\"msg\":\"sub\",\"id\":\"BhQGCDSHbs2K8b6Qo\",\"name\":\"stream-notify-user\",\"params\":[\"oAKZSpTPTQHbp6nBD/rooms-changed\",false]}"]
	//["{\"msg\":\"sub\",\"id\":\"2wA7uGgSRcw67DsqW\",\"name\":\"stream-notify-user\",\"params\":[\"oAKZSpTPTQHbp6nBD/subscriptions-changed\",false]}"]
	//["{\"msg\":\"sub\",\"id\":\"d7R5u6pCkLKPfxFa7\",\"name\":\"stream-notify-user\",\"params\":[\"oAKZSpTPTQHbp6nBD/otr\",false]}"]
	//sign up to notifications
		for (i = 0; subs[i]; i++) {
			data = json_object_new();
			params = json_array_new();
			
			id = g_strdup_printf("%012XFFFF", g_random_int());
			json_object_set_string_member(data, "id", id);
			g_free(id);
			
			json_object_set_string_member(data, "msg", "sub");
			json_object_set_string_member(data, "name", "stream-notify-user");
			
			param_id = g_strdup_printf("%s/%s", self_id, subs[i]);
			json_array_add_string_element(params, param_id);
			g_free(param_id);
			
			json_array_add_boolean_element(params, FALSE);
			
			json_object_set_array_member(data, "params", params);
			
			rc_socket_write_json(ya, data);
		}
	}
	
	// Listen to all incoming direct messages?
	data = json_object_new();
	params = json_array_new();
	
	json_object_set_string_member(data, "msg", "sub");
	
	id = g_strdup_printf("%012XFFFF", g_random_int());
	json_object_set_string_member(data, "id", id);
	g_free(id);
	
	json_array_add_string_element(params, "__my_messages__");
	json_array_add_boolean_element(params, FALSE);
	json_object_set_string_member(data, "name", "stream-room-messages");
	json_object_set_array_member(data, "params", params);
	
	rc_socket_write_json(ya, data);
	
	//Fetch all known rooms
	//["{\"msg\":\"method\",\"method\":\"rooms/get\",\"params\":[{\"$date\":0}],\"id\":\"6\"}"]
	data = json_object_new();
	params = json_array_new();
	
	date = json_object_new();
	json_object_set_int_member(date, "$date", 0);
	json_array_add_object_element(params, date);
	
	json_object_set_string_member(data, "msg", "method");
	json_object_set_string_member(data, "method", "rooms/get");
	json_object_set_array_member(data, "params", params);
	json_object_set_string_member(data, "id", rc_get_next_id_str_callback(ya, rc_got_open_rooms, NULL));
	
	rc_socket_write_json(ya, data);
	
	purple_connection_set_state(ya->pc, PURPLE_CONNECTION_CONNECTED);
}


static gint64 rc_get_room_last_timestamp(RocketChatAccount *ya, const gchar *room_id);
static void rc_set_room_last_timestamp(RocketChatAccount *ya, const gchar *room_id, gint64 last_timestamp);

static gint64
rc_process_room_message(RocketChatAccount *ya, JsonObject *message, JsonObject *roomarg)
{
	JsonObject *ts = json_object_get_object_member(message, "ts");
	JsonObject *u = json_object_get_object_member(message, "u");
	
	const gchar *_id = json_object_get_string_member(message, "_id");
	const gchar *msg_text = json_object_get_string_member(message, "msg");
	const gchar *rid = json_object_get_string_member(message, "rid");
	const gchar *t = json_object_get_string_member(message, "t");
	const gchar *username = json_object_get_string_member(u, "username");
	const gchar *roomType = json_object_get_string_member(roomarg, "roomType");
	const gchar *room_name = g_hash_table_lookup(ya->group_chats, rid);
	gint64 sdate = json_object_get_int_member(ts, "$date");
	gint64 timestamp = sdate / 1000;
	PurpleMessageFlags msg_flags = (purple_strequal(username, ya->self_user) ? PURPLE_MESSAGE_SEND : PURPLE_MESSAGE_RECV);
	
	if (purple_strequal(t, "uj")) {
		PurpleChatConversation *chatconv = purple_conversations_find_chat_with_account(room_name, ya->account);
		if (chatconv == NULL) {
			chatconv = purple_conversations_find_chat_with_account(rid, ya->account);
		}
		
		if (chatconv != NULL) {
			purple_chat_conversation_add_user(chatconv, username, NULL, PURPLE_CHAT_USER_NONE, TRUE);
		}
	} else if (purple_strequal(t, "ul")) {
		PurpleChatConversation *chatconv = purple_conversations_find_chat_with_account(room_name, ya->account);
		if (chatconv == NULL) {
			chatconv = purple_conversations_find_chat_with_account(rid, ya->account);
		}
		
		if (chatconv != NULL) {
			purple_chat_conversation_remove_user(chatconv, username, NULL);
		}
	} else if (purple_strequal(t, "room_changed_topic")) {
		PurpleChatConversation *chatconv = purple_conversations_find_chat_with_account(room_name, ya->account);
		if (chatconv == NULL) {
			chatconv = purple_conversations_find_chat_with_account(rid, ya->account);
		}
		
		if (chatconv != NULL) {
			gchar *html_topic = rc_markdown_to_html(msg_text);
			purple_chat_conversation_set_topic(chatconv, NULL, html_topic);
			g_free(html_topic);
		}
	} else {
		gchar *message = rc_markdown_to_html(msg_text);
		
		// check we didn't send this
		if (msg_flags == PURPLE_MESSAGE_RECV || !g_hash_table_remove(ya->sent_message_ids, _id)) {
			if ((roomType != NULL && *roomType != 'd') || g_hash_table_contains(ya->group_chats, rid)) {
				// Group chat message
				purple_serv_got_chat_in(ya->pc, g_str_hash(rid), username, msg_flags, message, timestamp);
				
				if (purple_conversation_has_focus(PURPLE_CONVERSATION(purple_conversations_find_chat_with_account(room_name ? room_name : rid, ya->account)))) {
					rc_mark_room_messages_read(ya, rid);
				}
				
			} else {
				if (msg_flags == PURPLE_MESSAGE_RECV) {
					purple_serv_got_im(ya->pc, username, message, msg_flags, timestamp);
					
					if (roomType && *roomType == 'd' && !g_hash_table_contains(ya->one_to_ones, rid)) {
						g_hash_table_replace(ya->one_to_ones, g_strdup(rid), g_strdup(username));
						g_hash_table_replace(ya->one_to_ones_rev, g_strdup(username), g_strdup(rid));
					}
					
					if (purple_conversation_has_focus(PURPLE_CONVERSATION(purple_conversations_find_im_with_account(username, ya->account)))) {
						rc_mark_room_messages_read(ya, rid);
					}
					
				} else {
					const gchar *other_user = g_hash_table_lookup(ya->one_to_ones, rid);
					// TODO null check
					PurpleIMConversation *imconv = purple_conversations_find_im_with_account(other_user, ya->account);
					PurpleMessage *pmsg = purple_message_new_outgoing(other_user, message, msg_flags);
					
					if (imconv == NULL) {
						imconv = purple_im_conversation_new(ya->account, other_user);
					}
					purple_message_set_time(pmsg, timestamp);
					purple_conversation_write_message(PURPLE_CONVERSATION(imconv), pmsg);
					purple_message_destroy(pmsg);
				}
			}
		}
		
		g_free(message);
	}
	
	return sdate;
}

void rc_handle_add_new_user(RocketChatAccount *ya, JsonObject *obj);

PurpleGroup* rc_get_or_create_default_group();

static void
rc_process_msg(RocketChatAccount *ya, JsonNode *element_node)
{
	JsonObject *response = NULL;
	JsonObject *obj = json_node_get_object(element_node);

	const gchar *msg = json_object_get_string_member(obj, "msg");
	// gint64 createdTime = json_object_get_int_member(obj, "createdTime");
	// gboolean old_event = !ya->sync_complete;
    rc_get_or_create_default_group();

    if (purple_strequal(msg, "ping")) {
		response = json_object_new();
		json_object_set_string_member(response, "msg", "pong");
	} else if (purple_strequal(msg, "added")) {
        rc_handle_add_new_user(ya, obj);
    } else if (purple_strequal(msg, "changed")) {
		const gchar *collection = json_object_get_string_member(obj, "collection");
		if (purple_strequal(collection, "users")) {
			JsonObject *fields = json_object_get_object_member(obj, "fields");
			const gchar *user_id = json_object_get_string_member(obj, "id");
			const gchar *username = json_object_get_string_member(fields, "username");
			const gchar *status = json_object_get_string_member(fields, "status");
			const gchar *name = json_object_get_string_member(fields, "name");
			
			if (status != NULL) {
				if (username == NULL) {
					username = g_hash_table_lookup(ya->ids_to_usernames, user_id);
				}
				
				purple_protocol_got_user_status(ya->account, username, status, NULL);
			}
			
			//a["{\"msg\":\"changed\",\"collection\":\"users\",\"id\":\"123\",\"fields\":{\"active\":true,\"name\":\"John Doe\",\"type\":\"user\"}}"]
			if (name != NULL) {
				if (username == NULL) {
					username = g_hash_table_lookup(ya->ids_to_usernames, user_id);
				}
				if (username != NULL) {
					purple_serv_got_alias(ya->pc, username, name);
				}
			}
			
		} else if (purple_strequal(collection, "stream-room-messages")) {
			//New incoming message
			//a["{\"msg\":\"changed\",\"collection\":\"stream-room-messages\",\"id\":\"id\",\"fields\":{\"eventName\":\"GENERAL\",\"args\":[{\"_id\":\"000096D065C7FFFF\",\"rid\":\"GENERAL\",\"msg\":\"test from pidgin\",\"ts\":{\"$date\":1477121045178},\"u\":{\"_id\":\"hZKg86uJavE6jYLya\",\"username\":\"eionrobb\"},\"_updatedAt\":{\"$date\":1477121045250}}]}}"]
			//(02:11:28) rocketchat: got frame data: a["{\"msg\":\"changed\",\"collection\":\"stream-room-messages\",\"id\":\"id\",\"fields\":{\"eventName\":\"__my_messages__\",\"args\":[{\"_id\":\"uDnK575PrTpDbf39c\",\"rid\":\"hZKg86uJavE6jYLyaoAKZSpTPTQHbp6nBD\",\"msg\":\"test\",\"ts\":{\"$date\":1477919487366},\"u\":{\"_id\":\"oAKZSpTPTQHbp6nBD\",\"username\":\"eiontest\"},\"_updatedAt\":{\"$date\":1477919487368}},{\"roomParticipant\":true,\"roomType\":\"d\"}]}}"]
			
			JsonObject *fields = json_object_get_object_member(obj, "fields");
			JsonArray *args = json_object_get_array_member(fields, "args");
			JsonObject *arg = json_array_get_object_element(args, 0);
			JsonObject *roomarg = json_array_get_object_element(args, 1);
			const gchar *rid = json_object_get_string_member(arg, "rid");
			gint64 last_message_timestamp;
			
			last_message_timestamp = rc_process_room_message(ya, arg, roomarg);
			
			rc_set_room_last_timestamp(ya, rid, last_message_timestamp);
		} else if (purple_strequal(collection, "stream-notify-room")) {
			//a["{\"msg\":\"changed\",\"collection\":\"stream-notify-room\",\"id\":\"id\",\"fields\":{\"eventName\":\"GENERAL/typing\",\"args\":[\"Neilgle\",true]}}"]
			JsonObject *fields = json_object_get_object_member(obj, "fields");
			const gchar *eventName = json_object_get_string_member(fields, "eventName");
			JsonArray *args = json_object_get_array_member(fields, "args");
			gchar **event_split;
			
			event_split = g_strsplit(eventName, "/", 2);		
			if (purple_strequal(event_split[1], "typing")) {
				const gchar *room_id = event_split[0];
				const gchar *username = json_array_get_string_element(args, 0);
				gboolean is_typing = json_array_get_boolean_element(args, 1);
				
				if (!purple_strequal(username, ya->self_user)) {
					if (g_hash_table_contains(ya->group_chats, room_id)) {
						// This is a group conversation
						PurpleChatConversation *chatconv = purple_conversations_find_chat_with_account(g_hash_table_lookup(ya->group_chats, room_id), ya->account);
						if (chatconv == NULL) {
							chatconv = purple_conversations_find_chat_with_account(room_id, ya->account);
						}
						if (chatconv != NULL) {
							PurpleChatUser *cb = purple_chat_conversation_find_user(chatconv, username);
							PurpleChatUserFlags cbflags;

							if (cb == NULL) {
								// Getting notified about a buddy we dont know about yet
								//TODO add buddy
								return;
							}
							cbflags = purple_chat_user_get_flags(cb);
							
							if (is_typing)
								cbflags |= PURPLE_CHAT_USER_TYPING;
							else
								cbflags &= ~PURPLE_CHAT_USER_TYPING;
							
							purple_chat_user_set_flags(cb, cbflags);
						}
					} else {
						PurpleIMTypingState typing_state;
						
						if (is_typing) {
							typing_state = PURPLE_IM_TYPING;
						} else {
							typing_state = PURPLE_IM_NOT_TYPING;
						}
						purple_serv_got_typing(ya->pc, username, 15, typing_state);
						
					}
				}
			}
			g_strfreev(event_split);
		} else if (purple_strequal(collection, "stream-notify-user")) {
			JsonObject *fields = json_object_get_object_member(obj, "fields");
			const gchar *eventName = json_object_get_string_member(fields, "eventName");
			JsonArray *args = json_object_get_array_member(fields, "args");
			gchar **event_split;
			
			event_split = g_strsplit(eventName, "/", 2);	
			if (purple_strequal(event_split[1], "rooms-changed")) {
				// New chat started
				//a["{\"msg\":\"changed\",\"collection\":\"stream-notify-user\",\"id\":\"id\",\"fields\":{\"eventName\":\"hZKg86uJavE6jYLya/rooms-changed\",\"args\":[\"inserted\",{\"_id\":\"JoxbibGnXizRb4ef4hZKg86uJavE6jYLya\",\"t\":\"d\"}]}}"]
				//a["{\"msg\":\"changed\",\"collection\":\"stream-notify-user\",\"id\":\"id\",\"fields\":{\"eventName\":\"hZKg86uJavE6jYLya/rooms-changed\",\"args\":[\"inserted\",{\"_id\":\"GENERAL\",\"name\":\"general\",\"t\":\"c\",\"topic\":\"Community support in [#support](https://demo.rocket.chat/channel/support).  Developers in [#dev](https://demo.rocket.chat/channel/dev)\",\"muted\":[\"daly\",\"kkloggg\",\"staci.holmes.segarra\"],\"jitsiTimeout\":{\"$date\":1477687206856},\"default\":true}]}}"]
				//a["{\"msg\":\"changed\",\"collection\":\"stream-notify-user\",\"id\":\"id\",\"fields\":{\"eventName\":\"hZKg86uJavE6jYLya/rooms-changed\",\"args\":[\"updated\",{\"_id\":\"ocwXv7EvCJ69d3AdG\",\"name\":\"eiontestchat\",\"t\":\"p\",\"u\":{\"_id\":null,\"username\":null},\"topic\":\"ham salad\",\"ro\":false}]}}"]
			} else if (purple_strequal(event_split[1], "subscriptions-changed")) {
				// Joined a chat			//a["{\"msg\":\"changed\",\"collection\":\"stream-notify-user\",\"id\":\"id\",\"fields\":{\"eventName\":\"oAKZSpTPTQHbp6nBD/subscriptions-changed\",\"args\":[\"inserted\",{\"t\":\"d\",\"ts\":{\"$date\":1477264898460},\"ls\":{\"$date\":1477264898460},\"name\":\"eionrobb\",\"rid\":\"hZKg86uJavE6jYLyaoAKZSpTPTQHbp6nBD\",\"u\":{\"_id\":\"oAKZSpTPTQHbp6nBD\",\"username\":\"eiontest\"},\"open\":true,\"alert\":false,\"unread\":0,\"_updatedAt\":{\"$date\":1477264898482},\"_id\":\"seeiaYbHTmFzbZKPx\"}]}}"]
				//a["{\"msg\":\"changed\",\"collection\":\"stream-notify-user\",\"id\":\"id\",\"fields\":{\"eventName\":\"hZKg86uJavE6jYLya/subscriptions-changed\",\"args\":[\"inserted\",{\"t\":\"c\",\"ts\":{\"$date\":1477913491203},\"name\":\"general\",\"rid\":\"GENERAL\",\"u\":{\"_id\":\"hZKg86uJavE6jYLya\",\"username\":\"eionrobb\"},\"open\":true,\"alert\":true,\"unread\":1,\"_updatedAt\":{\"$date\":1477913492365},\"_id\":\"AakoPQ2mvhXyaFRux\"}]}}"]
				JsonObject *room_info = json_array_get_object_element(args, 1);
				const gchar *name = json_object_get_string_member(room_info, "name");
				const gchar *room_id = json_object_get_string_member(room_info, "rid");
				const gchar *room_type = json_object_get_string_member(room_info, "t");
				gboolean new_room = FALSE;
				
				if (*room_type == 'd') {
					// Direct message
					if (!g_hash_table_contains(ya->one_to_ones, room_id)) {
						g_hash_table_replace(ya->one_to_ones, g_strdup(room_id), g_strdup(name));
						g_hash_table_replace(ya->one_to_ones_rev, g_strdup(name), g_strdup(room_id));
						
						new_room = TRUE;
					}
				} else { //'c' for public chat, 'p' for private chat
					// Group chat
					if (!g_hash_table_contains(ya->group_chats, room_id)) {
						g_hash_table_replace(ya->group_chats, g_strdup(room_id), g_strdup(name));
						g_hash_table_replace(ya->group_chats_rev, g_strdup(name), g_strdup(room_id));
						
						new_room = TRUE;
					}
					
					// chatconv = purple_serv_got_joined_chat(ya->pc, g_str_hash(room_id), room_id);
					// purple_conversation_set_data(PURPLE_CONVERSATION(chatconv), "id", g_strdup(room_id));
				}
				
				if (new_room == TRUE) {
					rc_join_room(ya, room_id);
				}
			}
			g_strfreev(event_split);
			
		}
	} else if (purple_strequal(msg, "removed")) {
		const gchar *collection = json_object_get_string_member(obj, "collection");
		
		if (purple_strequal(collection, "users")) {
			//a["{\"msg\":\"removed\",\"collection\":\"users\",\"id\":\"qYbdBFhcQyiyLx7z9\"}"]
			const gchar *user_id = json_object_get_string_member(obj, "id");
			const gchar *username = g_hash_table_lookup(ya->ids_to_usernames, user_id);
			
			if (username != NULL) {
				purple_protocol_got_user_status(ya->account, username, "offline", NULL);
			}
			
			g_hash_table_remove(ya->usernames_to_ids, username);
			g_hash_table_remove(ya->ids_to_usernames, user_id);
		}
		
	} else if (purple_strequal(msg, "connected")) {
	
		JsonArray *params = json_array_new();
		JsonObject *param = json_object_new();
		JsonObject *user = json_object_new();
		JsonObject *password = json_object_new();
		gchar *digest;
		
		if (ya->session_token) {
			// Continue an existing session
			json_object_set_string_member(param, "resume", ya->session_token);
		} else {
			// Start a brand new login
			if (strchr(ya->username, '@')) {
				json_object_set_string_member(user, "email", ya->username);
			} else {
				json_object_set_string_member(user, "username", ya->username);
			}
			digest = g_compute_checksum_for_string(G_CHECKSUM_SHA256, purple_connection_get_password(ya->pc), -1);
			json_object_set_string_member(password, "digest", digest);
			json_object_set_string_member(password, "algorithm", "sha-256");
			g_free(digest);
			
			json_object_set_object_member(param, "user", user);
			json_object_set_object_member(param, "password", password);
		}
		
		json_array_add_object_element(params, param);
		
		response = json_object_new();
		json_object_set_string_member(response, "msg", "method");
		json_object_set_string_member(response, "method", "login");
		json_object_set_array_member(response, "params", params);
		json_object_set_string_member(response, "id", rc_get_next_id_str_callback(ya, rc_login_response, NULL));
		
		
	} else if (purple_strequal(msg, "result")) {
		JsonNode *result = json_object_get_member(obj, "result");
		const gchar *callback_id = json_object_get_string_member(obj, "id");
		RocketChatProxyConnection *proxy = g_hash_table_lookup(ya->result_callbacks, callback_id);
		
		if (proxy != NULL) {
			if (proxy->callback != NULL) {
				proxy->callback(ya, result, proxy->user_data);
			}
			g_hash_table_remove(ya->result_callbacks, callback_id);
		}
	} else if (purple_strequal(msg, "failed")) {
		purple_connection_error(ya->pc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR, "Failed to connect to server");
	}
	
	if (!json_object_has_member(obj, "msg") && json_object_has_member(obj, "server_id")) {
		JsonArray *support = json_array_new();
		//["{\"msg\":\"connect\",\"version\":\"1\",\"support\":[\"1\",\"pre2\",\"pre1\"]}"]
		
		json_array_add_string_element(support, "1");
		
		response = json_object_new();
		json_object_set_string_member(response, "msg", "connect");
		json_object_set_string_member(response, "version", "1");
		json_object_set_array_member(response, "support", support);
	}
	
	if (response != NULL) {
		rc_socket_write_json(ya, response);
	}
}

PurpleGroup* rc_get_or_create_default_group() {
    PurpleGroup *rc_group = NULL;
    if (rc_group == NULL) {
		rc_group = purple_blist_find_group(_("Rocket.Chat"));
		if (!rc_group)
		{
			rc_group = purple_group_new(_("Rocket.Chat"));
			purple_blist_add_group(rc_group, NULL);
		}
	}
    return rc_group;
}

void rc_handle_add_new_user(RocketChatAccount *ya, JsonObject *obj) {
	PurpleAccount* account = ya->account;
	PurpleGroup *defaultGroup = rc_get_or_create_default_group();
    const gchar *collection = json_object_get_string_member(obj, "collection");

    // a["{\"msg\":\"added\",\"collection\":\"users\",\"id\":\"hZKg86uJavE6jYLya\",\"fields\":{\"emails\":[{\"address\":\"eion@robbmob.com\",\"verified\":true}],\"username\":\"eionrobb\"}}"]

    //a["{\"msg\":\"added\",\"collection\":\"users\",\"id\":\"M6m6odi9ufFJtFzZ3\",\"fields\":{\"status\":\"online\",\"username\":\"ali-14\",\"utcOffset\":3.5}}"]
    if (purple_strequal(collection, "users")) {
		JsonObject *fields = json_object_get_object_member(obj, "fields");
		const gchar *user_id = json_object_get_string_member(obj, "id");
		const gchar *username = json_object_get_string_member(fields, "username");
		const gchar *status = json_object_get_string_member(fields, "status");
		const gchar *name = json_object_get_string_member(fields, "name");

		if (status != NULL) {
			purple_protocol_got_user_status(ya->account, username, status, NULL);
		}

		if (username != NULL) {
			g_hash_table_replace(ya->usernames_to_ids, g_strdup(username), g_strdup(user_id));
			g_hash_table_replace(ya->ids_to_usernames, g_strdup(user_id), g_strdup(username));

			if (!ya->self_user) {
				// The first user added to the collection is us
				ya->self_user = g_strdup(username);

				purple_connection_set_display_name(ya->pc, ya->self_user);
				rc_account_connected(ya, NULL, NULL);
			} else if (purple_account_get_bool(account, "auto-add-buddy", FALSE)) {
				//other user not us
				PurpleBuddy *buddy = purple_blist_find_buddy(account, username);
				if (buddy == NULL) {
					buddy = purple_buddy_new(account, username, name);
					purple_blist_add_buddy(buddy, NULL, defaultGroup, NULL);
				}
			}

			if (name != NULL) {
				purple_serv_got_alias(ya->pc, username, name);
			}
		}
	}
}

static void
rc_roomlist_got_list(RocketChatAccount *ya, JsonNode *node, gpointer user_data)
{
	//a["{\"msg\":\"result\",\"id\":\"13\",\"result\":{\"channels\":[{\"_id\":\"oJmjKQJyixALtty5g\",\"name\":\"commitee\"},{\"_id\":\"jtQDeqzzf2M8oe7Bq\",\"name\":\"enspiral\"},{\"_id\":\"GENERAL\",\"name\":\"general\"},{\"_id\":\"GzxgcmSRcCoSg3tmJ\",\"name\":\"meetupchch\"},{\"_id\":\"EqssvQgYZ9HEFsJ7g\",\"name\":\"technical\"}]}}"]
	PurpleRoomlist *roomlist = user_data;
	JsonObject *result = json_node_get_object(node);
	JsonArray *channels = json_object_get_array_member(result, "channels");
	guint i, len = json_array_get_length(channels);
			
	for (i = 0; i < len; i++) {
		JsonObject *channel = json_array_get_object_element(channels, i);
		const gchar *id = json_object_get_string_member(channel, "_id");
		const gchar *name = json_object_get_string_member(channel, "name");
		const gchar *room_type = json_object_get_string_member(channel, "t");
		PurpleRoomlistRoom *room = purple_roomlist_room_new(PURPLE_ROOMLIST_ROOMTYPE_ROOM, name, NULL);
		
		purple_roomlist_room_add_field(roomlist, room, id);
		purple_roomlist_room_add_field(roomlist, room, name);
		purple_roomlist_room_add_field(roomlist, room, *room_type == 'p' ? _("Private") : "");
		
		purple_roomlist_room_add(roomlist, room);
	}
	
	purple_roomlist_set_in_progress(roomlist, FALSE);
}

static gchar *
rc_roomlist_serialize(PurpleRoomlistRoom *room) {
	GList *fields = purple_roomlist_room_get_fields(room);
	const gchar *id = (const gchar *) fields->data;
	const gchar *name = (const gchar *) fields->next->data;
	
	if (name && *name) {
		return g_strconcat("#", name, NULL);
	} else {
		return g_strdup(id);
	}
}

PurpleRoomlist *
rc_roomlist_get_list(PurpleConnection *pc)
{
	RocketChatAccount *ya = purple_connection_get_protocol_data(pc);
	PurpleRoomlist *roomlist;
	GList *fields = NULL;
	PurpleRoomlistField *f;
	
	roomlist = purple_roomlist_new(ya->account);

	f = purple_roomlist_field_new(PURPLE_ROOMLIST_FIELD_STRING, _("ID"), "id", FALSE);
	fields = g_list_append(fields, f);

	f = purple_roomlist_field_new(PURPLE_ROOMLIST_FIELD_STRING, _("Name"), "name", TRUE);
	fields = g_list_append(fields, f);

	f = purple_roomlist_field_new(PURPLE_ROOMLIST_FIELD_STRING, _("Type"), "t", FALSE);
	fields = g_list_append(fields, f);

	purple_roomlist_set_fields(roomlist, fields);
	purple_roomlist_set_in_progress(roomlist, TRUE);
	
	{
		//["{\"msg\":\"method\",\"method\":\"channelsList\",\"params\":[\"\",50,\"name\"],\"id\":\"13\"}"]
		JsonObject *data = json_object_new();
		JsonArray *params = json_array_new();
		
		json_array_add_string_element(params, ""); // filter
		json_array_add_string_element(params, ""); // channel type  (public, private)
		json_array_add_int_element(params, 500); // limit
		json_array_add_string_element(params, "msgs"); // sort-by (msgs, name)
		
		json_object_set_string_member(data, "msg", "method");
		json_object_set_string_member(data, "method", "channelsList");
		json_object_set_array_member(data, "params", params);
		json_object_set_string_member(data, "id", rc_get_next_id_str_callback(ya, rc_roomlist_got_list, roomlist));
		
		json_object_ref(data);
		rc_socket_write_json(ya, data);
		
		// Send the same request again without the second parameter for older servers
		json_array_remove_element(params, 1);
		rc_socket_write_json(ya, data);
	}
	
	return roomlist;
}


void
rc_set_status(PurpleAccount *account, PurpleStatus *status)
{
	PurpleConnection *pc = purple_account_get_connection(account);
	RocketChatAccount *ya = purple_connection_get_protocol_data(pc);
	
	//["{\"msg\":\"method\",\"method\":\"UserPresence:away\",\"params\":[],\"id\":\"10\"}"]
	JsonObject *data = json_object_new();
	JsonArray *params = json_array_new();
	gchar *method;
	
	json_object_set_string_member(data, "msg", "method");
	
	method = g_strdup_printf("UserPresence:%s", purple_status_get_id(status));
	json_object_set_string_member(data, "method", method);
	g_free(method);
	
	json_object_set_array_member(data, "params", params);
	json_object_set_string_member(data, "id", rc_get_next_id_str(ya));
	
	rc_socket_write_json(ya, data);
}


static void rc_start_socket(RocketChatAccount *ya);

static void
rc_restart_channel(RocketChatAccount *ya)
{
	purple_connection_set_state(ya->pc, PURPLE_CONNECTION_CONNECTING);
	rc_start_socket(ya);
}

static void
rc_build_groups_from_blist(RocketChatAccount *ya)
{
	PurpleBlistNode *node;
	
	for (node = purple_blist_get_root();
	     node != NULL;
		 node = purple_blist_node_next(node, TRUE)) {
		if (PURPLE_IS_CHAT(node)) {
			const gchar *room_id;
			const gchar *name;
			PurpleChat *chat = PURPLE_CHAT(node);
			if (purple_chat_get_account(chat) != ya->account) {
				continue;
			}
			
			name = purple_chat_get_name(chat);
			room_id = purple_blist_node_get_string(node, "room_id");
			if (name == NULL || room_id == NULL || purple_strequal(name, room_id)) {
				GHashTable *components = purple_chat_get_components(chat);
				if (components != NULL) {
					if (room_id == NULL) {
						room_id = g_hash_table_lookup(components, "id");
					}
					if (name == NULL || purple_strequal(name, room_id)) {
						name = g_hash_table_lookup(components, "name");
					}
				}
			}
			if (room_id != NULL) {
				g_hash_table_replace(ya->group_chats, g_strdup(room_id), name ? g_strdup(name) : NULL);
			}
			if (name != NULL) {
				g_hash_table_replace(ya->group_chats_rev, g_strdup(name), room_id ? g_strdup(room_id) : NULL);
			}
		} else if (PURPLE_IS_BUDDY(node)) {
			const gchar *room_id;
			const gchar *name;
			PurpleBuddy *buddy = PURPLE_BUDDY(node);
			if (purple_buddy_get_account(buddy) != ya->account) {
				continue;
			}
			
			name = purple_buddy_get_name(buddy);
			room_id = purple_blist_node_get_string(node, "room_id");
			if (room_id != NULL) {
				g_hash_table_replace(ya->one_to_ones, g_strdup(room_id), g_strdup(name));
				g_hash_table_replace(ya->one_to_ones_rev, g_strdup(name), g_strdup(room_id));
			}
		}
	}
}

static guint rc_conv_send_typing(PurpleConversation *conv, PurpleIMTypingState state, RocketChatAccount *ya);
static gulong chat_conversation_typing_signal = 0;
static void rc_mark_conv_seen(PurpleConversation *conv, PurpleConversationUpdateType type);
static gulong conversation_updated_signal = 0;

void
rc_login(PurpleAccount *account)
{
	RocketChatAccount *ya;
	PurpleConnection *pc = purple_account_get_connection(account);
	gchar **userparts;
	const gchar *username = purple_account_get_username(account);
	gchar *url;
	
	ya = g_new0(RocketChatAccount, 1);
	purple_connection_set_protocol_data(pc, ya);
	ya->account = account;
	ya->pc = pc;
	ya->cookie_table = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	ya->id = 1;
	
	
	ya->last_load_last_message_timestamp = purple_account_get_int(account, "last_message_timestamp_high", 0);
	if (ya->last_load_last_message_timestamp != 0) {
		ya->last_load_last_message_timestamp = (ya->last_load_last_message_timestamp << 32) | ((guint64) purple_account_get_int(account, "last_message_timestamp_low", 0) & 0xFFFFFFFF);
	}
	
	ya->one_to_ones = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	ya->one_to_ones_rev = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	ya->group_chats = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	ya->group_chats_rev = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	ya->sent_message_ids = g_hash_table_new_full(g_str_insensitive_hash, g_str_insensitive_equal, g_free, NULL);
	ya->result_callbacks = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	ya->usernames_to_ids = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	ya->ids_to_usernames = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	
	userparts = g_strsplit(username, (char[2]) {RC_SERVER_SPLIT_CHAR, '\0'}, 2);
	purple_connection_set_display_name(pc, userparts[0]);
	ya->username = g_strdup(userparts[0]);
	ya->server = g_strdup(userparts[1]);
	g_strfreev(userparts);
	
	purple_connection_set_state(pc, PURPLE_CONNECTION_CONNECTING);

	//Build the initial hash tables from the current buddy list
	rc_build_groups_from_blist(ya);
	
	//TODO do something with this callback to make sure it's actually a rocket.chat server
	url = g_strconcat("https://", ya->server, "/api/info", NULL);
	rc_fetch_url(ya, url, NULL, NULL, NULL);
	g_free(url);
	
	rc_start_socket(ya);
	
	
	if (!chat_conversation_typing_signal) {
		chat_conversation_typing_signal = purple_signal_connect(purple_conversations_get_handle(), "chat-conversation-typing", purple_connection_get_protocol(pc), PURPLE_CALLBACK(rc_conv_send_typing), NULL);
	}
	if (!conversation_updated_signal) {
		conversation_updated_signal = purple_signal_connect(purple_conversations_get_handle(), "conversation-updated", purple_connection_get_protocol(pc), PURPLE_CALLBACK(rc_mark_conv_seen), NULL);
	}
}


static void 
rc_close(PurpleConnection *pc)
{
	RocketChatAccount *ya = purple_connection_get_protocol_data(pc);
	// PurpleAccount *account;
	
	g_return_if_fail(ya != NULL);
	
	// account = purple_connection_get_account(pc);
	if (ya->websocket != NULL) purple_ssl_close(ya->websocket);
	
	g_hash_table_remove_all(ya->one_to_ones);
	g_hash_table_unref(ya->one_to_ones);
	g_hash_table_remove_all(ya->one_to_ones_rev);
	g_hash_table_unref(ya->one_to_ones_rev);
	g_hash_table_remove_all(ya->group_chats);
	g_hash_table_unref(ya->group_chats);
	g_hash_table_remove_all(ya->sent_message_ids);
	g_hash_table_unref(ya->sent_message_ids);
	g_hash_table_remove_all(ya->result_callbacks);
	g_hash_table_unref(ya->result_callbacks);
	g_hash_table_remove_all(ya->usernames_to_ids);
	g_hash_table_unref(ya->usernames_to_ids);
	g_hash_table_remove_all(ya->ids_to_usernames);
	g_hash_table_unref(ya->ids_to_usernames);

	while (ya->http_conns) {
#	if !PURPLE_VERSION_CHECK(3, 0, 0)
		purple_util_fetch_url_cancel(ya->http_conns->data);
#	else
		purple_http_conn_cancel(ya->http_conns->data);
#	endif
		ya->http_conns = g_slist_delete_link(ya->http_conns, ya->http_conns);
	}

	while (ya->pending_writes) {
		json_object_unref(ya->pending_writes->data);
		ya->pending_writes = g_slist_delete_link(ya->pending_writes, ya->pending_writes);
	}
	
	g_hash_table_destroy(ya->cookie_table); ya->cookie_table = NULL;
	g_free(ya->frame); ya->frame = NULL;
	g_free(ya->session_token); ya->session_token = NULL;
	g_free(ya->channel); ya->channel = NULL;
	g_free(ya->self_user); ya->self_user = NULL;
	g_free(ya);
}















//static void rc_start_polling(RocketChatAccount *ya);

static gboolean
rc_process_frame(RocketChatAccount *rca, const gchar *frame)
{
	JsonParser *parser = json_parser_new();
	JsonNode *root;
	const gchar frame_type = frame[0];
	
	purple_debug_info("rocketchat", "got frame data: %s\n", frame);

	if (!json_parser_load_from_data(parser, frame + 1, -1, NULL))
	{
		purple_debug_error("rocketchat", "Error parsing response: %s\n", frame);
		return TRUE;
	}
	
	root = json_parser_get_root(parser);
	
	if (root != NULL) {
		purple_debug_error("rocketchat", "fame type is : %c\n", frame_type);
		if (frame_type == 'a') {
			JsonArray *message_array = json_node_get_array(root);
			guint i, len = json_array_get_length(message_array);
			JsonParser *message_parser = json_parser_new();
			
			for (i = 0; i < len; i++) {
				const gchar *message_str = json_array_get_string_element(message_array, i);
				
				if (json_parser_load_from_data(message_parser, message_str, -1, NULL)) {
					rc_process_msg(rca, json_parser_get_root(message_parser));
				}
			}
			g_object_unref(message_parser);
		} else if (frame_type == 'o') {
			//JsonObject *message_object = json_node_get_object(root);
			//TODO not sure
			purple_debug_warning("rocketchat", "object type not handled\n");
		} else if (frame_type == 'c') {
			//JsonObject *message_object = json_node_get_object(root);
			//TODO not sure
			purple_debug_error("rocketchat", "server closed the connection\n");
		} else {
			//TODO is this going to happen?
			purple_debug_error("rocketchat", "unknown frame type '%c'\n", frame_type);
		}
	}
	
	g_object_unref(parser);
	return TRUE;
}

static guchar *
rc_websocket_mask(guchar key[4], const guchar *pload, guint64 psize)
{
	guint64 i;
	guchar *ret = g_new0(guchar, psize);

	for (i = 0; i < psize; i++) {
		ret[i] = pload[i] ^ key[i % 4];
	}

	return ret;
}

static void
rc_socket_write_data(RocketChatAccount *ya, guchar *data, gsize data_len, guchar type)
{
	guchar *full_data;
	guint len_size = 1;
	guchar mkey[4] = { 0x12, 0x34, 0x56, 0x78 };
	
	if (data_len) {
		purple_debug_info("rocketchat", "sending frame: %*s\n", (int)data_len, data);
	}
	
	data = rc_websocket_mask(mkey, data, data_len);
	
	if (data_len > 125) {
		if (data_len <= G_MAXUINT16) {
			len_size += 2;
		} else {
			len_size += 8;
		}
	}
	full_data = g_new0(guchar, 1 + data_len + len_size + 4);
	
	if (type == 0) {
		type = 129;
	}
	full_data[0] = type;
	
	if (data_len <= 125) {
		full_data[1] = data_len | 0x80;
	} else if (data_len <= G_MAXUINT16) {
		guint16 be_len = GUINT16_TO_BE(data_len);
		full_data[1] = 126 | 0x80;
		memmove(full_data + 2, &be_len, 2);
	} else {
		guint64 be_len = GUINT64_TO_BE(data_len);
		full_data[1] = 127 | 0x80;
		memmove(full_data + 2, &be_len, 8);
	}
	
	memmove(full_data + (1 + len_size), &mkey, 4);
	memmove(full_data + (1 + len_size + 4), data, data_len);
	
	purple_ssl_write(ya->websocket, full_data, 1 + data_len + len_size + 4);
	
	g_free(full_data);
	g_free(data);
}

/* takes ownership of data parameter */
static void
rc_socket_write_json(RocketChatAccount *rca, JsonObject *data)
{
	JsonNode *node;
	JsonArray *data_array;
	gchar *str;
	gsize len;
	JsonGenerator *generator;
	
	if (rca->websocket == NULL) {
		if (data != NULL) {
			rca->pending_writes = g_slist_append(rca->pending_writes, data);
		}
		return;
	}
	
	node = json_node_new(JSON_NODE_OBJECT);
	json_node_set_object(node, data);
	
	// a json string ...
	generator = json_generator_new();
	json_generator_set_root(generator, node);
	str = json_generator_to_data(generator, &len);
	g_object_unref(generator);
	json_node_free(node);
	
	// ... bundled in an array ...
	data_array = json_array_new();
	json_array_add_string_element(data_array, str);
	node = json_node_new(JSON_NODE_ARRAY);
	json_node_set_array(node, data_array);
	
	// ... sent as a string
	g_free(str);
	generator = json_generator_new();
	json_generator_set_root(generator, node);
	str = json_generator_to_data(generator, &len);
	g_object_unref(generator);
	
	rc_socket_write_data(rca, (guchar *)str, len, 0);
	
	g_free(str);
	json_node_free(node);
	json_array_unref(data_array);
}

static void
rc_socket_got_data(gpointer userdata, PurpleSslConnection *conn, PurpleInputCondition cond)
{
	RocketChatAccount *ya = userdata;
	guchar length_code;
	int read_len = 0;
	gboolean done_some_reads = FALSE;
	
	
	if (G_UNLIKELY(!ya->websocket_header_received)) {
		gint nlbr_count = 0;
		gchar nextchar;
		
		while(nlbr_count < 4 && purple_ssl_read(conn, &nextchar, 1)) {
			if (nextchar == '\r' || nextchar == '\n') {
				nlbr_count++;
			} else {
				nlbr_count = 0;
			}
		}
		
		ya->websocket_header_received = TRUE;
		done_some_reads = TRUE;

		/* flush stuff that we attempted to send before the websocket was ready */
		while (ya->pending_writes) {
			rc_socket_write_json(ya, ya->pending_writes->data);
			ya->pending_writes = g_slist_delete_link(ya->pending_writes, ya->pending_writes);
		}
	}
	
	while(ya->frame || (read_len = purple_ssl_read(conn, &ya->packet_code, 1)) == 1) {
		if (!ya->frame) {
			if (ya->packet_code != 129) {
				if (ya->packet_code == 136) {
					purple_debug_error("rocketchat", "websocket closed\n");
					
					// Try reconnect
					rc_start_socket(ya);
					
					return;
				} else if (ya->packet_code == 137) {
					// Ping
					gint ping_frame_len;
					length_code = 0;
					purple_ssl_read(conn, &length_code, 1);
					if (length_code <= 125) {
						ping_frame_len = length_code;
					} else if (length_code == 126) {
						guchar len_buf[2];
						purple_ssl_read(conn, len_buf, 2);
						ping_frame_len = (len_buf[0] << 8) + len_buf[1];
					} else if (length_code == 127) {
						purple_ssl_read(conn, &ping_frame_len, 8);
						ping_frame_len = GUINT64_FROM_BE(ping_frame_len);
					}
					if (ping_frame_len) {
						guchar *pong_data = g_new0(guchar, ping_frame_len);
						purple_ssl_read(conn, pong_data, ping_frame_len);

						rc_socket_write_data(ya, pong_data, ping_frame_len, 138);
						g_free(pong_data);
					} else {
						rc_socket_write_data(ya, (guchar *) "", 0, 138);
					}
					return;
				} else if (ya->packet_code == 138) {
					// Pong
					//who cares
					return;
				}
				purple_debug_error("rocketchat", "unknown websocket error %d\n", ya->packet_code);
				return;
			}
			
			length_code = 0;
			purple_ssl_read(conn, &length_code, 1);
			if (length_code <= 125) {
				ya->frame_len = length_code;
			} else if (length_code == 126) {
				guchar len_buf[2];
				purple_ssl_read(conn, len_buf, 2);
				ya->frame_len = (len_buf[0] << 8) + len_buf[1];
			} else if (length_code == 127) {
				purple_ssl_read(conn, &ya->frame_len, 8);
				ya->frame_len = GUINT64_FROM_BE(ya->frame_len);
			}
			//purple_debug_info("rocketchat", "frame_len: %" G_GUINT64_FORMAT "\n", ya->frame_len);
			
			ya->frame = g_new0(gchar, ya->frame_len + 1);
			ya->frame_len_progress = 0;
		}
		
		do {
			read_len = purple_ssl_read(conn, ya->frame + ya->frame_len_progress, ya->frame_len - ya->frame_len_progress);
			if (read_len > 0) {
				ya->frame_len_progress += read_len;
			}
		} while (read_len > 0 && ya->frame_len_progress < ya->frame_len);
		done_some_reads = TRUE;
		
		if (ya->frame_len_progress == ya->frame_len) {
			gboolean success = rc_process_frame(ya, ya->frame);
			g_free(ya->frame); ya->frame = NULL;
			ya->packet_code = 0;
			ya->frame_len = 0;
			
			if (G_UNLIKELY(ya->websocket == NULL || success == FALSE)) {
				return;
			}
		} else {
			return;
		}
	}

	if (done_some_reads == FALSE && read_len <= 0) {
		if (read_len < 0 && errno == EAGAIN) {
			return;
		}

		purple_debug_error("rocketchat", "got errno %d, read_len %d from websocket thread\n", errno, read_len);

		if (ya->frames_since_reconnect < 2) {
			purple_connection_error(ya->pc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR, "Lost connection to server");
		} else {
			// Try reconnect
			rc_start_socket(ya);
		}
	}
}

static void
rc_socket_connected(gpointer userdata, PurpleSslConnection *conn, PurpleInputCondition cond)
{
	RocketChatAccount *ya = userdata;
	gchar *websocket_header;
	gchar *cookies;
	const gchar *websocket_key = "15XF+ptKDhYVERXoGcdHTA=="; //TODO don't be lazy
	GString *url = g_string_new(NULL);
	
	purple_ssl_input_add(ya->websocket, rc_socket_got_data, ya);
	
	g_string_append_printf(url, "/sockjs/%d/pidgin%d/websocket", g_random_int_range(100, 999), g_random_int_range(1, 100));
	cookies = rc_cookies_to_string(ya);
	
	websocket_header = g_strdup_printf("GET %s HTTP/1.1\r\n"
							"Host: %s\r\n"
							"Connection: Upgrade\r\n"
							"Pragma: no-cache\r\n"
							"Cache-Control: no-cache\r\n"
							"Upgrade: websocket\r\n"
							"Sec-WebSocket-Version: 13\r\n"
							"Sec-WebSocket-Key: %s\r\n"
							"User-Agent: " ROCKETCHAT_USERAGENT "\r\n"
							"Cookie: %s\r\n"
							//"Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n"
							"\r\n", url->str, ya->server,
							websocket_key, cookies);
	
	purple_ssl_write(ya->websocket, websocket_header, strlen(websocket_header));
	
	g_free(websocket_header);
	g_string_free(url, TRUE);
	g_free(cookies);
}

static void
rc_socket_failed(PurpleSslConnection *conn, PurpleSslErrorType errortype, gpointer userdata)
{
	RocketChatAccount *ya = userdata;
	
	ya->websocket = NULL;
	ya->websocket_header_received = FALSE;
	
	rc_restart_channel(ya);
}

static void
rc_start_socket(RocketChatAccount *ya)
{
	gchar **server_split;
	gint port = 443;
	
	//Reset all the old stuff
	if (ya->websocket != NULL) {
		purple_ssl_close(ya->websocket);
	}
	
	ya->websocket = NULL;
	ya->websocket_header_received = FALSE;
	g_free(ya->frame); ya->frame = NULL;
	ya->packet_code = 0;
	ya->frame_len = 0;
	ya->frames_since_reconnect = 0;

	server_split = g_strsplit(ya->server, ":", 2);
	if (server_split[1] != NULL) {
		port = atoi(server_split[1]);
	}
	ya->websocket = purple_ssl_connect(ya->account, server_split[0], port, rc_socket_connected, rc_socket_failed, ya);
	
	g_strfreev(server_split);
}




void
rc_block_user(PurpleConnection *pc, const char *who)
{
	// RocketChatAccount *ya = purple_connection_get_protocol_data(pc);
	// JsonObject *data = json_object_new();
	
	// json_object_set_string_member(data, "msg", "SetUserBlocked");
	// json_object_set_string_member(data, "userId", who);
	// json_object_set_int_member(data, "opId", ya->opid++);
	// json_object_set_boolean_member(data, "blocked", TRUE);
	
	// rc_socket_write_json(ya, data);
}

void
rc_unblock_user(PurpleConnection *pc, const char *who)
{
	// RocketChatAccount *ya = purple_connection_get_protocol_data(pc);
	// JsonObject *data = json_object_new();
	
	// json_object_set_string_member(data, "msg", "SetUserBlocked");
	// json_object_set_string_member(data, "userId", who);
	// json_object_set_int_member(data, "opId", ya->opid++);
	// json_object_set_boolean_member(data, "blocked", FALSE);
	
	// rc_socket_write_json(ya, data);
}

static void
rc_chat_leave_by_room_id(PurpleConnection *pc, const gchar *room_id)
{
	// RocketChatAccount *ya;
	// JsonObject *data = json_object_new();
	
	// ya = purple_connection_get_protocol_data(pc);
	
	// json_object_set_string_member(data, "msg", "LeaveGroup");
	// json_object_set_string_member(data, "groupId", groupId);
	// json_object_set_int_member(data, "opId", ya->opid++);
	
	// rc_socket_write_json(ya, data);
}

static void
rc_chat_leave(PurpleConnection *pc, int id)
{
	const gchar *room_id = NULL;
	PurpleChatConversation *chatconv;
	
	chatconv = purple_conversations_find_chat(pc, id);
	room_id = purple_conversation_get_data(PURPLE_CONVERSATION(chatconv), "id");
	if (room_id == NULL) {
		room_id = purple_conversation_get_name(PURPLE_CONVERSATION(chatconv));
	}
	
	rc_chat_leave_by_room_id(pc, room_id);
}

static void
rc_chat_invite(PurpleConnection *pc, int id, const char *message, const char *who)
{
	// RocketChatAccount *ya;
	// const gchar *room_id;
	// PurpleChatConversation *chatconv;
	// JsonObject *data = json_object_new();
	
	// ya = purple_connection_get_protocol_data(pc);
	// chatconv = purple_conversations_find_chat(pc, id);
	// room_id = purple_conversation_get_data(PURPLE_CONVERSATION(chatconv), "id");
	// if (room_id == NULL) {
		// room_id = purple_conversation_get_name(PURPLE_CONVERSATION(chatconv));
	// }
	
	// json_object_set_string_member(data, "msg", "InviteGroupMember");
	// json_object_set_string_member(data, "groupId", groupId);
	// json_object_set_int_member(data, "opId", ya->opid++);
	// json_object_set_string_member(data, "userId", who);
	// json_object_set_string_member(data, "memberId", "00000000000FFFFF");
	// json_object_set_string_member(data, "firstName", "");
	// json_object_set_string_member(data, "lastName", "");
	
	// rc_socket_write_json(ya, data);
}

static GList *
rc_chat_info(PurpleConnection *pc)
{
	GList *m = NULL;
	PurpleProtocolChatEntry *pce;
	
	pce = g_new0(PurpleProtocolChatEntry, 1);
	pce->label = _("Name");
	pce->identifier = "name";
	m = g_list_append(m, pce);

	pce = g_new0(PurpleProtocolChatEntry, 1);
	pce->label = _("Group ID");
	pce->identifier = "id";
	m = g_list_append(m, pce);
	
	return m;
}

static GHashTable *
rc_chat_info_defaults(PurpleConnection *pc, const char *chatname)
{
	GHashTable *defaults = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, g_free);
	
	if (chatname != NULL)
	{
		if (*chatname == '#') {
			g_hash_table_insert(defaults, "name", g_strdup(chatname + 1));
		} else if (strlen(chatname) == 17) {
			g_hash_table_insert(defaults, "id", g_strdup(chatname));
		} else {
			g_hash_table_insert(defaults, "name", g_strdup(chatname));
		}
	}
	
	return defaults;
}

static gchar *
rc_get_chat_name(GHashTable *data)
{
	gchar *temp;

	if (data == NULL) {
		return NULL;
	}
	
	temp = g_hash_table_lookup(data, "name");
	
	if (temp == NULL) {
		temp = g_hash_table_lookup(data, "id");
	}

	if (temp == NULL) {
		return NULL;
	}

	return g_strdup(temp);
}

static void 
rc_got_users_of_room(RocketChatAccount *ya, JsonNode *node, gpointer user_data)
{
	JsonObject *result = json_node_get_object(node);
	gchar *room_id = user_data;
	gchar *room_name = g_hash_table_lookup(ya->group_chats, room_id);
	
	//Text	Sun Oct 23 00:08:23 NZDT 2016	Sun Oct 23 00:08:23 NZDT 2016	a["{\"msg\":\"result\",\"id\":\"15\",\"result\":{\"total\":84776,\"records\":[\"dominico\",\"sri.sri\",\"jacob.brush\",\"sergey-4\",\"joycebabu\",\"vongomben\",\"marina.belobrova\",\"maialen\",\"Guby\",\"kawa.mj\",\"abda\",\"allie.micka\",\"julien.dussart\",\"dkonn\",\"sasaki\",\"hiro-21\",\"cristian.florescu\",\"test1-17\",\"artkill\",\"rocket.cat\",\"gabba\",\"ouaise.abdel.razig\",\"linsk\",\"minh.tri\",\"shabu.ans\",\"daniel.summers\",\"elmor3no\",\"woody.lee\",\"nikoj.ne\",\"mael.lebastard\",\"Solange\",\"ramin\",\"singli\",\"sandra.brown\",\"touqeer.rao-CN\",\"shoukri\",\"lintt\",\"wim.stalmans\",\"john.bowles\",\"jeff.lindesmith\",\"div\",\"timotz\",\"maxime.chauvin\",\"natalia.chalovskaya\",\"mark.webb\",\"demik\",\"nshevate\",\"Team.GrossGerau\",\"eionrobb\",\"danish.soomro\",\"jeremy\",\"testing-33\",\"anwar.hakimi\",\"ldk\",\"stoccafisso\",\"mark.petersen\",\"yang-2\",\"yanis.abib\",\"alan.swan\",\"continuouslee\",\"aj2\",\"rebecca.thomson\",\"yuukan\",\"Snare\",\"kidatti\",\"jader\",\"gkarmas\",\"treym\",\"testDemoS\",\"hubot\",\"rivkah\",\"xenithorb\",\"greg-9\",\"kirby\",\"Olu1\",\"gayle.sabharwal\",\"dale.berger\",\"_\",\"systrace68\",\"amir-3\",\"matyee\",\"any2names\",\"craig.miller\",\"aviner.fishhof\",\"jacobroecker\",\"kevmonzon\",\"john.maharjan\",\"ian-42\",\"nazarov.aleksandr\",\"dave-18\",\"ddd-9\",\"ycq818\",\"ParineyPrinja\",\"mongoose\",\"tenks\",\"thangnc\",\"jamesbaek\",\"BaekWoosok\",\"onlyxool\",\"richardt.steil\",\"FrancescoL\",\"eugene.ferbruarie_Mousten\",\"bill-15\",\"daira\",\"stefana1\",\"jack.terrible\",\"joon626\",\"novy\",\"liyu0013\",\"munzy\",\"chuckbot\",\"hogg\",\"rolanx\",\"lokitoxic\",\"diogenes.alves.oliveira\",\"test.yeah.yeah\",\"Erikxxon\",\"heyrob\",\"mark.yardly\",\"romio.montas\",\"james.thomas\",\"thebelgarion\",\"art-1\",\"ys-1\",\"adry2k\",\"Petersch\",\"johannes57\"]}}"]
	
		
	PurpleChatConversation *chatconv = purple_conversations_find_chat_with_account(room_name, ya->account);
	
	if (chatconv == NULL && room_id != NULL) {
		chatconv = purple_conversations_find_chat_with_account(room_id, ya->account);
	}
	
	if (chatconv == NULL) {
		if (room_name != NULL) {
			chatconv = purple_serv_got_joined_chat(ya->pc, g_str_hash(room_id), room_name);
			purple_conversation_set_data(PURPLE_CONVERSATION(chatconv), "id", g_strdup(room_id));
		}
	}
	
	if (chatconv != NULL) {
		JsonArray *records = json_object_get_array_member(result, "records");
		gint i;
		guint len = json_array_get_length(records);
		GList *users = NULL, *flags = NULL;
	
		for (i = len - 1; i >= 0; i--) {
			const gchar *record = json_array_get_string_element(records, i);
			if (record != NULL) {
				users = g_list_prepend(users, g_strdup(record));
				flags = g_list_prepend(flags, GINT_TO_POINTER(PURPLE_CHAT_USER_NONE));
			}
		}
	
		purple_chat_conversation_add_users(chatconv, users, NULL, flags, FALSE);
		
		while (users != NULL) {
			g_free(users->data);
			users = g_list_delete_link(users, users);
		}
		
		g_list_free(users);
		g_list_free(flags);
	}
	
	g_free(room_id);
}

static void
rc_got_history_of_room(RocketChatAccount *ya, JsonNode *node, gpointer user_data)
{
	JsonObject *result = json_node_get_object(node);
	JsonArray *messages = json_object_get_array_member(result, "messages");
	gchar *room_id = user_data;
	gint i, len = json_array_get_length(messages);
	gint64 last_message = rc_get_room_last_timestamp(ya, room_id);
	gint64 rolling_last_message_timestamp = 0;
	
	//latest are first
	for (i = len - 1; i >= 0; i--) {
		JsonObject *message = json_array_get_object_element(messages, i);
		JsonObject *ts = json_object_get_object_member(message, "ts");
		gint64 sdate = json_object_get_int_member(ts, "$date");
		
		if (last_message > sdate) {
			continue;
		}
		
		rolling_last_message_timestamp = rc_process_room_message(ya, message, NULL);
	}
	
	if (rolling_last_message_timestamp != 0) {
		rc_set_room_last_timestamp(ya, room_id, rolling_last_message_timestamp);
	}
	
	g_free(room_id);
}


	// libpurple can't store a 64bit int on a 32bit machine, so convert to something more usable instead (puke)
	//  also needs to work cross platform, in case the accounts.xml is being shared (double puke)

static gint64
rc_get_room_last_timestamp(RocketChatAccount *ya, const gchar *room_id)
{
	guint64 last_message_timestamp = ya->last_load_last_message_timestamp;
	PurpleBlistNode *blistnode = NULL;
	
	if (g_hash_table_contains(ya->group_chats, room_id)) {
		//twas a group chat
		blistnode = PURPLE_BLIST_NODE(purple_blist_find_chat(ya->account, g_hash_table_lookup(ya->group_chats, room_id)));
		if (blistnode == NULL) {
			blistnode = PURPLE_BLIST_NODE(purple_blist_find_chat(ya->account, room_id));
		}
	} else {
		//is a direct message
		blistnode = PURPLE_BLIST_NODE(purple_blist_find_buddy(ya->account, g_hash_table_lookup(ya->one_to_ones, room_id)));
	}
	if (blistnode != NULL) {
		gint64 last_room_timestamp = purple_blist_node_get_int(blistnode, "last_message_timestamp_high");
		if (last_room_timestamp != 0) {
			last_room_timestamp = (last_room_timestamp << 32) | ((guint64) purple_blist_node_get_int(blistnode, "last_message_timestamp_low") & 0xFFFFFFFF);
			
			ya->last_message_timestamp = MAX(ya->last_message_timestamp, last_room_timestamp);
			return last_room_timestamp;
		}
	}
	
	return last_message_timestamp;
}

static void
rc_set_room_last_timestamp(RocketChatAccount *ya, const gchar *room_id, gint64 last_timestamp)
{
	PurpleBlistNode *blistnode = NULL;
	
	if (last_timestamp <= ya->last_message_timestamp) {
		return;
	}
	
	if (g_hash_table_contains(ya->group_chats, room_id)) {
		//twas a group chat
		blistnode = PURPLE_BLIST_NODE(purple_blist_find_chat(ya->account, g_hash_table_lookup(ya->group_chats, room_id)));
		if (blistnode == NULL) {
			blistnode = PURPLE_BLIST_NODE(purple_blist_find_chat(ya->account, room_id));
		}
	} else {
		//is a direct message
		blistnode = PURPLE_BLIST_NODE(purple_blist_find_buddy(ya->account, g_hash_table_lookup(ya->one_to_ones, room_id)));
	}
	if (blistnode != NULL) {
		purple_blist_node_set_int(blistnode, "last_message_timestamp_high", last_timestamp >> 32);
		purple_blist_node_set_int(blistnode, "last_message_timestamp_low", last_timestamp & 0xFFFFFFFF);
	}
	
	ya->last_message_timestamp = last_timestamp;	
	purple_account_set_int(ya->account, "last_message_timestamp_high", last_timestamp >> 32);
	purple_account_set_int(ya->account, "last_message_timestamp_low", last_timestamp & 0xFFFFFFFF);
	
}

static void
rc_join_room(RocketChatAccount *ya, const gchar *room_id)
{
	//["{\"msg\":\"sub\",\"id\":\"8BZQJLpxqMHNSzPpB\",\"name\":\"stream-room-messages\",\"params\":[\"GENERAL\",false]}"]
	//["{\"msg\":\"sub\",\"id\":\"sZiEjTtC4DhhzqXqv\",\"name\":\"stream-notify-room\",\"params\":[\"GENERAL/deleteMessage\",false]}"]
	//["{\"msg\":\"sub\",\"id\":\"wvf3panWk2qkFyPEk\",\"name\":\"stream-notify-room\",\"params\":[\"GENERAL/typing\",false]}"]
	//["{\"msg\":\"method\",\"method\":\"getRoomRoles\",\"params\":[\"GENERAL\"],\"id\":\"15\"}"]
	//["{\"msg\":\"method\",\"method\":\"getUsersOfRoom\",\"params\":[\"GENERAL\",true],\"id\":\"15\"}"]
	//["{\"msg\":\"method\",\"method\":\"loadHistory\",\"params\":[\"GENERAL\",null,50,{\"$date\":1477203134888}],\"id\":\"5\"}"]
	JsonObject *data = json_object_new();
	JsonArray *params = json_array_new();
	JsonObject *date;
	gchar *id;
	gchar *sub_id;
	
	// Subscribe to typing notifications
	data = json_object_new();
	params = json_array_new();
	json_object_set_string_member(data, "msg", "sub");
	
	id = g_strdup_printf("%012XFFFF", g_random_int());
	json_object_set_string_member(data, "id", id);
	g_free(id);
	
	sub_id = g_strdup_printf("%s/%s", room_id, "typing");
	json_array_add_string_element(params, sub_id);
	g_free(sub_id);
	
	json_array_add_boolean_element(params, FALSE);
	json_object_set_string_member(data, "name", "stream-notify-room");
	json_object_set_array_member(data, "params", params);
	
	rc_socket_write_json(ya, data);
	
	//TODO subscribe to delete message notifications
	
	// Download a list of admins
	data = json_object_new();
	params = json_array_new();
	
	json_array_add_string_element(params, room_id);
	
	json_object_set_string_member(data, "msg", "method");
	json_object_set_string_member(data, "method", "getRoomRoles");
	json_object_set_array_member(data, "params", params);
	json_object_set_string_member(data, "id", rc_get_next_id_str(ya));
	
	rc_socket_write_json(ya, data);
	
	
	// Grab the list of users
	data = json_object_new();
	params = json_array_new();
	
	json_array_add_string_element(params, room_id);
	json_array_add_boolean_element(params, FALSE); // TRUE to get offline users
	
	json_object_set_string_member(data, "msg", "method");
	json_object_set_string_member(data, "method", "getUsersOfRoom");
	json_object_set_array_member(data, "params", params);
	json_object_set_string_member(data, "id", rc_get_next_id_str_callback(ya, rc_got_users_of_room, g_strdup(room_id)));
	
	rc_socket_write_json(ya, data);
	
	if (ya->last_load_last_message_timestamp > 0) {
		// Download old messages
		data = json_object_new();
		params = json_array_new();
		
		json_array_add_string_element(params, room_id);
		json_array_add_null_element(params);
		json_array_add_int_element(params, 50); // Number of messages
		date = json_object_new();
		json_object_set_int_member(date, "$date", rc_get_room_last_timestamp(ya, room_id));
		json_array_add_object_element(params, date);
		
		json_object_set_string_member(data, "msg", "method");
		json_object_set_string_member(data, "method", "loadHistory");
		json_object_set_array_member(data, "params", params);
		json_object_set_string_member(data, "id", rc_get_next_id_str_callback(ya, rc_got_history_of_room, g_strdup(room_id)));
		
		rc_socket_write_json(ya, data);
	}
	
}


static void rc_join_chat(PurpleConnection *pc, GHashTable *chatdata);

static void
rc_got_chat_name_id(RocketChatAccount *ya, JsonNode *node, gpointer user_data)
{
	GHashTable *chatdata = user_data;
	//a["{\"msg\":\"result\",\"id\":\"7\",\"result\":\"b98BYkRbiD5swDfyY\"}"]
	if (node == NULL) {
		return;
	}
	
	g_hash_table_replace(chatdata, "id", g_strdup(json_node_get_string(node)));
	
	rc_join_chat(ya->pc, chatdata);
	g_hash_table_unref(chatdata);
}

static void
rc_join_chat(PurpleConnection *pc, GHashTable *chatdata)
{
	RocketChatAccount *ya = purple_connection_get_protocol_data(pc);
	gchar *id;
	gchar *name;
	PurpleChatConversation *chatconv = NULL;
	
	id = (gchar *) g_hash_table_lookup(chatdata, "id");
	name = (gchar *) g_hash_table_lookup(chatdata, "name");
	
	if (id == NULL && name == NULL) {
		//What do?
		return;
	}
	
	if (id == NULL) {
		id = g_hash_table_lookup(ya->group_chats_rev, name);
	}
	if (name == NULL) {
		name = g_hash_table_lookup(ya->group_chats, id);
	}
	
	//TODO use the api look up name info from the id
	
	if (id == NULL) {
		//["{\"msg\":\"method\",\"method\":\"getRoomIdByNameOrId\",\"params\":[\"general\"],\"id\":\"3\"}"]
		JsonObject *data;
		JsonArray *params;
		
		data = json_object_new();
		params = json_array_new();
		
		json_array_add_string_element(params, name);
		
		json_object_set_string_member(data, "msg", "method");
		json_object_set_string_member(data, "method", "getRoomIdByNameOrId");
		json_object_set_array_member(data, "params", params);
		json_object_set_string_member(data, "id", rc_get_next_id_str_callback(ya, rc_got_chat_name_id, chatdata));
		
		rc_socket_write_json(ya, data);
		
		g_hash_table_ref(chatdata);
		return;
	}
	
	if (name != NULL) {
		chatconv = purple_conversations_find_chat_with_account(name, ya->account);
	}
	if (chatconv == NULL) {
		chatconv = purple_conversations_find_chat_with_account(id, ya->account);
	}
	if (chatconv != NULL && !purple_chat_conversation_has_left(chatconv)) {
		purple_conversation_present(PURPLE_CONVERSATION(chatconv));
		return;
	}
	
	chatconv = purple_serv_got_joined_chat(pc, g_str_hash(id), name ? name : id);
	if (id != NULL) {
		purple_conversation_set_data(PURPLE_CONVERSATION(chatconv), "id", g_strdup(id));
	}
	
	purple_conversation_present(PURPLE_CONVERSATION(chatconv));
	
	g_hash_table_replace(ya->group_chats, g_strdup(id), name ? g_strdup(name) : NULL);
	if (name != NULL) {
		g_hash_table_replace(ya->group_chats_rev, g_strdup(name), id ? g_strdup(id) : NULL);
	}
	
	rc_join_room(ya, id);
}

static void
rc_mark_room_messages_read(RocketChatAccount *ya, const gchar *room_id)
{
	JsonObject *data;
	JsonArray *params;
	
	data = json_object_new();
	params = json_array_new();
	
	json_array_add_string_element(params, room_id);
	
	json_object_set_string_member(data, "msg", "method");
	json_object_set_string_member(data, "method", "readMessages");
	json_object_set_array_member(data, "params", params);
	json_object_set_string_member(data, "id", rc_get_next_id_str(ya));
	
	rc_socket_write_json(ya, data);
}

static void
rc_mark_conv_seen(PurpleConversation *conv, PurpleConversationUpdateType type)
{
	PurpleConnection *pc;
	RocketChatAccount *ya;
	const gchar *room_id;
	
	if (type != PURPLE_CONVERSATION_UPDATE_UNSEEN)
		return;
	
	pc = purple_conversation_get_connection(conv);
	if (!PURPLE_CONNECTION_IS_CONNECTED(pc))
		return;
	
	if (g_strcmp0(purple_protocol_get_id(purple_connection_get_protocol(pc)), ROCKETCHAT_PLUGIN_ID))
		return;
	
	ya = purple_connection_get_protocol_data(pc);
	
	room_id = purple_conversation_get_data(conv, "id");
	if (room_id == NULL) {
		if (PURPLE_IS_IM_CONVERSATION(conv)) {
			room_id = g_hash_table_lookup(ya->one_to_ones_rev, purple_conversation_get_name(conv));
		} else {
			room_id = purple_conversation_get_name(conv);
			if (g_hash_table_lookup(ya->group_chats_rev, room_id)) {
				// Convert friendly name into id
				room_id = g_hash_table_lookup(ya->group_chats_rev, room_id);
			}
		}
	}
	g_return_if_fail(room_id != NULL);
	
	rc_mark_room_messages_read(ya, room_id);
}

static guint
rc_conv_send_typing(PurpleConversation *conv, PurpleIMTypingState state, RocketChatAccount *ya)
{
	PurpleConnection *pc;
	const gchar *room_id;
	gchar *typing_id;
	JsonObject *data;
	JsonArray *params;
	
	pc = ya ? ya->pc : purple_conversation_get_connection(conv);
	
	if (!PURPLE_CONNECTION_IS_CONNECTED(pc))
		return 0;
	
	if (g_strcmp0(purple_protocol_get_id(purple_connection_get_protocol(pc)), ROCKETCHAT_PLUGIN_ID))
		return 0;
	
	if (ya == NULL) {
		ya = purple_connection_get_protocol_data(pc);
	}
	
	room_id = purple_conversation_get_data(conv, "id");
	if (room_id == NULL) {
		if (PURPLE_IS_IM_CONVERSATION(conv)) {
			room_id = g_hash_table_lookup(ya->one_to_ones_rev, purple_conversation_get_name(conv));
		} else {
			room_id = purple_conversation_get_name(conv);
			if (g_hash_table_lookup(ya->group_chats_rev, room_id)) {
				// Convert friendly name into id
				room_id = g_hash_table_lookup(ya->group_chats_rev, room_id);
			}
		}
	}
	g_return_val_if_fail(room_id, -1); //TODO create new conversation for this new person
	
	
	//["{\"msg\":\"method\",\"method\":\"stream-notify-room\",\"params\":[\"eZqA2i4r76MHt4Y2nednpTpbaBg6qwjgR6/typing\",\"eionrobb\",true],\"id\":\"6\"}"]
	data = json_object_new();
	params = json_array_new();
	
	typing_id = g_strdup_printf("%s/typing", room_id);
	json_array_add_string_element(params, typing_id);
	g_free(typing_id);
	
	json_array_add_string_element(params, ya->self_user);
	if (state == PURPLE_IM_TYPING) {
		json_array_add_boolean_element(params, TRUE);
	} else {
		json_array_add_boolean_element(params, FALSE);
	}
	
	json_object_set_string_member(data, "msg", "method");
	json_object_set_string_member(data, "method", "stream-notify-room");
	json_object_set_array_member(data, "params", params);
	json_object_set_string_member(data, "id", rc_get_next_id_str(ya));
	
	rc_socket_write_json(ya, data);
	
	return 10;
}

static guint
rc_send_typing(PurpleConnection *pc, const gchar *who, PurpleIMTypingState state)
{
	PurpleConversation *conv;
	
	conv = PURPLE_CONVERSATION(purple_conversations_find_im_with_account(who, purple_connection_get_account(pc)));
	g_return_val_if_fail(conv, -1);
	
	return rc_conv_send_typing(conv, state, NULL);
}

static gint
rc_conversation_send_message(RocketChatAccount *ya, const gchar *rid, const gchar *message)
{
	//["{\"msg\":\"method\",\"method\":\"sendMessage\",\"params\":[{\"_id\":\"KrR3aWKh4MeMk38jS\",\"rid\":\"GENERAL\",\"msg\":\".\"}],\"id\":\"19\"}"]
	
	JsonObject *data = json_object_new();
	JsonArray *params = json_array_new();
	JsonObject *param = json_object_new();
	gchar *stripped;
	gchar *_id;
	
	_id = g_strdup_printf("%012XFFFF", g_random_int());
	json_object_set_string_member(param, "_id", _id);
	g_hash_table_insert(ya->sent_message_ids, _id, _id);
	
	json_object_set_string_member(param, "rid", rid);
	
	stripped = g_strstrip(purple_markup_strip_html(message));
	json_object_set_string_member(param, "msg", stripped);
	g_free(stripped);
	
	json_array_add_object_element(params, param);
	
	json_object_set_string_member(data, "msg", "method");
	json_object_set_string_member(data, "method", "sendMessage");
	json_object_set_array_member(data, "params", params);
	json_object_set_string_member(data, "id", rc_get_next_id_str(ya));
	
	rc_socket_write_json(ya, data);
	
	return 1;
}

static gint
rc_chat_send(PurpleConnection *pc, gint id, 
#if PURPLE_VERSION_CHECK(3, 0, 0)
PurpleMessage *msg)
{
	const gchar *message = purple_message_get_contents(msg);
#else
const gchar *message, PurpleMessageFlags flags)
{
#endif
	
	RocketChatAccount *ya;
	const gchar *room_id;
	PurpleChatConversation *chatconv;
	gint ret;
	
	ya = purple_connection_get_protocol_data(pc);
	chatconv = purple_conversations_find_chat(pc, id);
	room_id = purple_conversation_get_data(PURPLE_CONVERSATION(chatconv), "id");
	if (!room_id) {
		// Fix for a race condition around the chat data and serv_got_joined_chat()
		room_id = purple_conversation_get_name(PURPLE_CONVERSATION(chatconv));
		if (g_hash_table_lookup(ya->group_chats_rev, room_id)) {
			// Convert friendly name into id
			room_id = g_hash_table_lookup(ya->group_chats_rev, room_id);
		}
		g_return_val_if_fail(room_id, -1);
	}
	g_return_val_if_fail(g_hash_table_contains(ya->group_chats, room_id), -1); //TODO rejoin room?
	
	ret = rc_conversation_send_message(ya, room_id, message);
	if (ret > 0) {
		purple_serv_got_chat_in(pc, g_str_hash(room_id), ya->self_user, PURPLE_MESSAGE_SEND, message, time(NULL));
	}
	return ret;
}

static void
rc_created_direct_message(RocketChatAccount *ya, JsonNode *node, gpointer user_data)
{
	JsonObject *result = json_node_get_object(node);
	const gchar *room_id = json_object_get_string_member(result, "rid");
	PurpleBuddy *buddy = user_data;
	
	if (buddy != NULL) {
		const gchar *who = purple_buddy_get_name(buddy);
		
		g_hash_table_replace(ya->one_to_ones, g_strdup(room_id), g_strdup(who));
		g_hash_table_replace(ya->one_to_ones_rev, g_strdup(who), g_strdup(room_id));
	
		purple_blist_node_set_string(PURPLE_BLIST_NODE(buddy), "room_id", room_id);
	}
	
	rc_join_room(ya, room_id);
}

static void
rc_created_direct_message_send(RocketChatAccount *ya, JsonNode *node, gpointer user_data)
{
	PurpleMessage *msg = user_data;
	JsonObject *result;
	const gchar *who;
	const gchar *message;
	const gchar *room_id;
	PurpleBuddy *buddy;
	
	if (node == NULL) {
		//todo display error
		return;
	}
	
	result = json_node_get_object(node);
	who = purple_message_get_recipient(msg);
	message = purple_message_get_contents(msg);
	room_id = json_object_get_string_member(result, "rid");
	buddy = purple_blist_find_buddy(ya->account, who);
	
	if (room_id != NULL && who != NULL) {
		g_hash_table_replace(ya->one_to_ones, g_strdup(room_id), g_strdup(who));
		g_hash_table_replace(ya->one_to_ones_rev, g_strdup(who), g_strdup(room_id));
	}
	
	if (buddy != NULL) {
		purple_blist_node_set_string(PURPLE_BLIST_NODE(buddy), "room_id", room_id);
	}
	
	rc_join_room(ya, room_id);
	
	rc_conversation_send_message(ya, room_id, message);
}

static int
rc_send_im(PurpleConnection *pc, 
#if PURPLE_VERSION_CHECK(3, 0, 0)
PurpleMessage *msg)
{
	const gchar *who = purple_message_get_recipient(msg);
	const gchar *message = purple_message_get_contents(msg);
#else
const gchar *who, const gchar *message, PurpleMessageFlags flags)
{
#endif

	RocketChatAccount *ya = purple_connection_get_protocol_data(pc);
	gchar *room_id = g_hash_table_lookup(ya->one_to_ones_rev, who);
	
	if (room_id == NULL) {
		//["{\"msg\":\"method\",\"method\":\"createDirectMessage\",\"params\":[\"hubot\"],\"id\":\"28\"}"]
		JsonObject *data;
		JsonArray *params;
#if !PURPLE_VERSION_CHECK(3, 0, 0)
		PurpleMessage *msg = purple_message_new_outgoing(who, message, flags);
#endif
		
		data = json_object_new();
		params = json_array_new();
		
		json_array_add_string_element(params, who);
		
		json_object_set_string_member(data, "msg", "method");
		json_object_set_string_member(data, "method", "createDirectMessage");
		json_object_set_array_member(data, "params", params);
		json_object_set_string_member(data, "id", rc_get_next_id_str_callback(ya, rc_created_direct_message_send, msg));
	
		rc_socket_write_json(ya, data);
		return 1;
	}
	
	return rc_conversation_send_message(ya, room_id, message);
}

// static const gchar *
// rc_normalise_buddy(const PurpleAccount *account, const gchar *str)
// {
	// static gchar buf[26 + 1];
	// gchar *tmp1, *tmp2;

	// g_return_val_if_fail(str != NULL, NULL);

	// tmp1 = g_ascii_strup(str, -1);
	// use g_ascii_isalnum on each char
	// g_snprintf(buf, sizeof(buf), "%26s", tmp1 ? tmp1 : "");
	// g_free(tmp1);

	// return buf;
// }

// static gchar *
// rc_make_base32guid(guint64 id)
// {
	// guchar guid[16];
	// guint64 be_id = GUINT64_TO_BE(id);
	// gchar *base32guid;
	
	// memset(guid, 0, 16);
	// memmove(guid + 8, &be_id, 8);
	
	// base32guid = purple_base32_encode(guid, 16);
	// base32guid[26] = 0; // Strip off trailing padding
	
	// return base32guid;
// }

static void
rc_chat_set_topic(PurpleConnection *pc, int id, const char *topic)
{
	RocketChatAccount *ya;
	const gchar *room_id;
	PurpleChatConversation *chatconv;
	JsonObject *data;
	JsonArray *params;
	
	ya = purple_connection_get_protocol_data(pc);
	chatconv = purple_conversations_find_chat(pc, id);
	room_id = purple_conversation_get_data(PURPLE_CONVERSATION(chatconv), "id");
	if (!room_id) {
		// Fix for a race condition around the chat data and serv_got_joined_chat()
		room_id = purple_conversation_get_name(PURPLE_CONVERSATION(chatconv));
		if (g_hash_table_lookup(ya->group_chats_rev, room_id)) {
			// Convert friendly name into id
			room_id = g_hash_table_lookup(ya->group_chats_rev, room_id);
		}
		g_return_if_fail(room_id);
	}
	g_return_if_fail(g_hash_table_contains(ya->group_chats, room_id)); //TODO rejoin room?
	
	//["{\"msg\":\"method\",\"method\":\"saveRoomSettings\",\"params\":[\"ocwXv7EvCJ69d3AdG\",\"roomTopic\",\"set topic here plzkthxbai\"],\"id\":\"16\"}"]
	data = json_object_new();
	params = json_array_new();
	
	json_array_add_string_element(params, room_id);
	json_array_add_string_element(params, "roomTopic");
	json_array_add_string_element(params, topic);
	
	json_object_set_string_member(data, "msg", "method");
	json_object_set_string_member(data, "method", "saveRoomSettings");
	json_object_set_array_member(data, "params", params);
	json_object_set_string_member(data, "id", rc_get_next_id_str(ya));
	
	rc_socket_write_json(ya, data);
}

static void
rc_got_avatar(RocketChatAccount *ya, JsonNode *node, gpointer user_data)
{
	JsonObject *response = json_node_get_object(node);
	PurpleBuddy *buddy = user_data;
	const gchar *response_str;
	gsize response_len;
	gpointer response_dup;
	
	response_str = g_dataset_get_data(node, "raw_body");
	response_len = json_object_get_int_member(response, "len");
	response_dup = g_memdup(response_str, response_len);
	
	purple_buddy_icons_set_for_user(ya->account, purple_buddy_get_name(buddy), response_dup, response_len, NULL);
}

static void
rc_add_buddy(PurpleConnection *pc, PurpleBuddy *buddy, PurpleGroup *group
#if PURPLE_VERSION_CHECK(3, 0, 0)
, const char *message
#endif
)
{
	RocketChatAccount *ya = purple_connection_get_protocol_data(pc);
	JsonObject *data;
	JsonArray *params;
	const gchar *buddy_name = purple_buddy_get_name(buddy);
	gchar *avatar_url;
	
	//["{\"msg\":\"method\",\"method\":\"createDirectMessage\",\"params\":[\"1test\"],\"id\":\"28\"}"]
	
	//a["{\"msg\":\"result\",\"id\":\"28\",\"result\":{\"rid\":\"hZKg86uJavE6jYLyavxiySsLD8gLjgnmnN\"}}"]
	
	data = json_object_new();
	params = json_array_new();
	
	json_array_add_string_element(params, buddy_name);
	
	json_object_set_string_member(data, "msg", "method");
	json_object_set_string_member(data, "method", "createDirectMessage");
	json_object_set_array_member(data, "params", params);
	json_object_set_string_member(data, "id", rc_get_next_id_str_callback(ya, rc_created_direct_message, buddy));
	
	rc_socket_write_json(ya, data);
	
	// Grab all the user data
	//["{\"msg\":\"sub\",\"id\":\"rr9T9NEee3JubKWGi\",\"name\":\"fullUserData\",\"params\":[\"eionrobb\",1]}"]
	data = json_object_new();
	params = json_array_new();
	
	json_array_add_string_element(params, buddy_name);
	json_array_add_int_element(params, 1);
	
	json_object_set_string_member(data, "msg", "sub");
	json_object_set_string_member(data, "id", rc_get_next_id_str(ya));
	json_object_set_string_member(data, "name", "fullUserData");
	json_object_set_array_member(data, "params", params);
	
	rc_socket_write_json(ya, data);
	
	
	//avatar at https://{server}/avatar/{username}.jpg?_dc=0
	avatar_url = g_strdup_printf("https://%s/avatar/%s.jpg?_dc=0", ya->server, purple_url_encode(buddy_name));
	rc_fetch_url(ya, avatar_url, NULL, rc_got_avatar, buddy);
	g_free(avatar_url);
	
	return;
}


static const char *
rc_list_icon(PurpleAccount *account, PurpleBuddy *buddy)
{
	return "rocketchat";
}

static GList *
rc_status_types(PurpleAccount *account)
{
	GList *types = NULL;
	PurpleStatusType *status;

	status = purple_status_type_new_full(PURPLE_STATUS_AVAILABLE, "online", "Online", TRUE, TRUE, FALSE);
	types = g_list_append(types, status);

	status = purple_status_type_new_full(PURPLE_STATUS_AWAY, "away", "Away", TRUE, TRUE, FALSE);
	types = g_list_append(types, status);

	status = purple_status_type_new_full(PURPLE_STATUS_UNAVAILABLE, "busy", "Busy", TRUE, TRUE, FALSE);
	types = g_list_append(types, status);
	
	status = purple_status_type_new_full(PURPLE_STATUS_OFFLINE, NULL, "Offline", TRUE, TRUE, FALSE);
	types = g_list_append(types, status);
	
	return types;
}

static GHashTable *
rc_get_account_text_table(PurpleAccount *unused)
{
	GHashTable *table;

	table = g_hash_table_new(g_str_hash, g_str_equal);

	g_hash_table_insert(table, "login_label", (gpointer)_("Email or Username..."));

	return table;
}

static GList *
rc_add_account_options(GList *account_options)
{
	PurpleAccountOption *option;
	
	option = purple_account_option_bool_new(N_("Auto-add buddies to the buddy list"), "auto-add-buddy", FALSE);
	account_options = g_list_append(account_options, option);
	
	return account_options;
}

static PurpleCmdRet
rc_cmd_leave(PurpleConversation *conv, const gchar *cmd, gchar **args, gchar **error, void *data)
{
	PurpleConnection *pc = NULL;
	int id = -1;
	
	pc = purple_conversation_get_connection(conv);
	id = purple_chat_conversation_get_id(PURPLE_CHAT_CONVERSATION(conv));
	
	if (pc == NULL || id == -1)
		return PURPLE_CMD_RET_FAILED;
	
	rc_chat_leave(pc, id);
	
	return PURPLE_CMD_RET_OK;
}

static gboolean
plugin_load(PurplePlugin *plugin, GError **error)
{
	//["{\"msg\":\"method\",\"method\":\"slashCommand\",\"params\":[{\"cmd\":\"join\",\"params\":\"#general \",\"msg\":{\"_id\":\"FLpX4en75muW3raxH\",\"rid\":\"hZKg86uJavE6jYLyaoAKZSpTPTQHbp6nBD\",\"msg\":\"/join #general \"}}],\"id\":\"19\"}"]
	
	purple_cmd_register("leave", "", PURPLE_CMD_P_PLUGIN, PURPLE_CMD_FLAG_CHAT |
						PURPLE_CMD_FLAG_PROTOCOL_ONLY | PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS,
						ROCKETCHAT_PLUGIN_ID, rc_cmd_leave,
						_("leave:  Leave the group chat"), NULL);
	
	return TRUE;
}

static gboolean
plugin_unload(PurplePlugin *plugin, GError **error)
{
	purple_signals_disconnect_by_handle(plugin);
	
	return TRUE;
}

// Purple2 Plugin Load Functions
#if !PURPLE_VERSION_CHECK(3, 0, 0)
static gboolean
libpurple2_plugin_load(PurplePlugin *plugin)
{
	return plugin_load(plugin, NULL);
}

static gboolean
libpurple2_plugin_unload(PurplePlugin *plugin)
{
	return plugin_unload(plugin, NULL);
}

static void
plugin_init(PurplePlugin *plugin)
{
	// PurpleAccountOption *option;
	// PurplePluginInfo *info = plugin->info;
	// PurplePluginProtocolInfo *prpl_info = info->extra_info;
	//purple_signal_connect(purple_get_core(), "uri-handler", plugin, PURPLE_CALLBACK(rc_uri_handler), NULL);
	
	PurpleAccountUserSplit *split;
	PurplePluginInfo *info;
	PurplePluginProtocolInfo *prpl_info = g_new0(PurplePluginProtocolInfo, 1);
	
	split = purple_account_user_split_new(_("Server"), RC_DEFAULT_SERVER, RC_SERVER_SPLIT_CHAR);
	prpl_info->user_splits = g_list_append(prpl_info->user_splits, split);
	
	info = plugin->info;
	if (info == NULL) {
		plugin->info = info = g_new0(PurplePluginInfo, 1);
	}
	info->extra_info = prpl_info;
	#if PURPLE_MINOR_VERSION >= 5
		prpl_info->struct_size = sizeof(PurplePluginProtocolInfo);
	#endif
	#if PURPLE_MINOR_VERSION >= 8
		//prpl_info->add_buddy_with_invite = rc_add_buddy_with_invite;
	#endif
	
	prpl_info->options = OPT_PROTO_CHAT_TOPIC | OPT_PROTO_SLASH_COMMANDS_NATIVE;
	prpl_info->protocol_options = rc_add_account_options(prpl_info->protocol_options);
	prpl_info->icon_spec.format = "png,gif,jpeg";
	prpl_info->icon_spec.min_width = 0;
	prpl_info->icon_spec.min_height = 0;
	prpl_info->icon_spec.max_width = 96;
	prpl_info->icon_spec.max_height = 96;
	prpl_info->icon_spec.max_filesize = 0;
	prpl_info->icon_spec.scale_rules = PURPLE_ICON_SCALE_DISPLAY;
	
	prpl_info->get_account_text_table = rc_get_account_text_table;
	prpl_info->list_icon = rc_list_icon;
	prpl_info->set_status = rc_set_status;
	prpl_info->status_types = rc_status_types;
	prpl_info->chat_info = rc_chat_info;
	prpl_info->chat_info_defaults = rc_chat_info_defaults;
	prpl_info->login = rc_login;
	prpl_info->close = rc_close;
	prpl_info->send_im = rc_send_im;
	prpl_info->send_typing = rc_send_typing;
	// prpl_info->add_deny = rc_block_user;
	// prpl_info->rem_deny = rc_unblock_user;
	prpl_info->join_chat = rc_join_chat;
	prpl_info->get_chat_name = rc_get_chat_name;
	prpl_info->chat_invite = rc_chat_invite;
	prpl_info->chat_send = rc_chat_send;
	prpl_info->set_chat_topic = rc_chat_set_topic;
	prpl_info->add_buddy = rc_add_buddy;
	
	prpl_info->roomlist_get_list = rc_roomlist_get_list;
	prpl_info->roomlist_room_serialize = rc_roomlist_serialize;
}

static PurplePluginInfo info = {
	PURPLE_PLUGIN_MAGIC,
/*	PURPLE_MAJOR_VERSION,
	PURPLE_MINOR_VERSION,
*/
	2, 1,
	PURPLE_PLUGIN_PROTOCOL, /* type */
	NULL, /* ui_requirement */
	0, /* flags */
	NULL, /* dependencies */
	PURPLE_PRIORITY_DEFAULT, /* priority */
	ROCKETCHAT_PLUGIN_ID, /* id */
	"Rocket.Chat", /* name */
	ROCKETCHAT_PLUGIN_VERSION, /* version */
	"", /* summary */
	"", /* description */
	"Eion Robb <eion@robbmob.com>", /* author */
	ROCKETCHAT_PLUGIN_WEBSITE, /* homepage */
	libpurple2_plugin_load, /* load */
	libpurple2_plugin_unload, /* unload */
	NULL, /* destroy */
	NULL, /* ui_info */
	NULL, /* extra_info */
	NULL, /* prefs_info */
	NULL/*plugin_actions*/, /* actions */
	NULL, /* padding */
	NULL,
	NULL,
	NULL
};

PURPLE_INIT_PLUGIN(rocketchat, plugin_init, info);

#else
//Purple 3 plugin load functions


G_MODULE_EXPORT GType rc_protocol_get_type(void);
#define ROCKETCHAT_TYPE_PROTOCOL			(rc_protocol_get_type())
#define ROCKETCHAT_PROTOCOL(obj)			(G_TYPE_CHECK_INSTANCE_CAST((obj), ROCKETCHAT_TYPE_PROTOCOL, RocketChatProtocol))
#define ROCKETCHAT_PROTOCOL_CLASS(klass)	(G_TYPE_CHECK_CLASS_CAST((klass), ROCKETCHAT_TYPE_PROTOCOL, RocketChatProtocolClass))
#define ROCKETCHAT_IS_PROTOCOL(obj)			(G_TYPE_CHECK_INSTANCE_TYPE((obj), ROCKETCHAT_TYPE_PROTOCOL))
#define ROCKETCHAT_IS_PROTOCOL_CLASS(klass)	(G_TYPE_CHECK_CLASS_TYPE((klass), ROCKETCHAT_TYPE_PROTOCOL))
#define ROCKETCHAT_PROTOCOL_GET_CLASS(obj)	(G_TYPE_INSTANCE_GET_CLASS((obj), ROCKETCHAT_TYPE_PROTOCOL, RocketChatProtocolClass))

typedef struct _RocketChatProtocol
{
	PurpleProtocol parent;
} RocketChatProtocol;

typedef struct _RocketChatProtocolClass
{
	PurpleProtocolClass parent_class;
} RocketChatProtocolClass;

static void
rc_protocol_init(PurpleProtocol *prpl_info)
{
	PurpleProtocol *info = prpl_info;
	PurpleAccountUserSplit *split;

	info->id = ROCKETCHAT_PLUGIN_ID;
	info->name = "Rocket.Chat";
	info->options = OPT_PROTO_CHAT_TOPIC | OPT_PROTO_SLASH_COMMANDS_NATIVE;
	info->account_options = rc_add_account_options(info->account_options);
	
	split = purple_account_user_split_new(_("Server"), RC_DEFAULT_SERVER, RC_SERVER_SPLIT_CHAR);
	info->user_splits = g_list_append(info->user_splits, split);
}

static void
rc_protocol_class_init(PurpleProtocolClass *prpl_info)
{
	prpl_info->login = rc_login;
	prpl_info->close = rc_close;
	prpl_info->status_types = rc_status_types;
	prpl_info->list_icon = rc_list_icon;
}

static void
rc_protocol_privacy_iface_init(PurpleProtocolPrivacyIface *prpl_info)
{
	prpl_info->add_deny = rc_block_user;
	prpl_info->rem_deny = rc_unblock_user;
}

static void 
rc_protocol_im_iface_init(PurpleProtocolIMIface *prpl_info)
{
	prpl_info->send = rc_send_im;
	prpl_info->send_typing = rc_send_typing;
}

static void 
rc_protocol_chat_iface_init(PurpleProtocolChatIface *prpl_info)
{
	prpl_info->send = rc_chat_send;
	prpl_info->info = rc_chat_info;
	prpl_info->info_defaults = rc_chat_info_defaults;
	prpl_info->join = rc_join_chat;
	prpl_info->get_name = rc_get_chat_name;
	prpl_info->invite = rc_chat_invite;
	prpl_info->set_topic = rc_chat_set_topic;
}

static void 
rc_protocol_server_iface_init(PurpleProtocolServerIface *prpl_info)
{
	prpl_info->add_buddy = rc_add_buddy;
	prpl_info->set_status = rc_set_status;
}

static void 
rc_protocol_client_iface_init(PurpleProtocolClientIface *prpl_info)
{
	prpl_info->get_account_text_table = rc_get_account_text_table;
}

static void 
rc_protocol_roomlist_iface_init(PurpleProtocolRoomlistIface *prpl_info)
{
	prpl_info->get_list = rc_roomlist_get_list;
	prpl_info->room_serialize = rc_roomlist_serialize;
}

static PurpleProtocol *rc_protocol;

PURPLE_DEFINE_TYPE_EXTENDED(
	RocketChatProtocol, rc_protocol, PURPLE_TYPE_PROTOCOL, 0,

	PURPLE_IMPLEMENT_INTERFACE_STATIC(PURPLE_TYPE_PROTOCOL_IM_IFACE,
	                                  rc_protocol_im_iface_init)

	PURPLE_IMPLEMENT_INTERFACE_STATIC(PURPLE_TYPE_PROTOCOL_CHAT_IFACE,
	                                  rc_protocol_chat_iface_init)

	PURPLE_IMPLEMENT_INTERFACE_STATIC(PURPLE_TYPE_PROTOCOL_PRIVACY_IFACE,
	                                  rc_protocol_privacy_iface_init)

	PURPLE_IMPLEMENT_INTERFACE_STATIC(PURPLE_TYPE_PROTOCOL_SERVER_IFACE,
	                                  rc_protocol_server_iface_init)

	PURPLE_IMPLEMENT_INTERFACE_STATIC(PURPLE_TYPE_PROTOCOL_CLIENT_IFACE,
	                                  rc_protocol_client_iface_init)

	PURPLE_IMPLEMENT_INTERFACE_STATIC(PURPLE_TYPE_PROTOCOL_ROOMLIST_IFACE,
	                                  rc_protocol_roomlist_iface_init)

);

static gboolean
libpurple3_plugin_load(PurplePlugin *plugin, GError **error)
{
	rc_protocol_register_type(plugin);
	rc_protocol = purple_protocols_add(ROCKETCHAT_TYPE_PROTOCOL, error);
	if (!rc_protocol)
		return FALSE;

	return plugin_load(plugin, error);
}

static gboolean
libpurple3_plugin_unload(PurplePlugin *plugin, GError **error)
{
	if (!plugin_unload(plugin, error))
		return FALSE;

	if (!purple_protocols_remove(rc_protocol, error))
		return FALSE;

	return TRUE;
}

static PurplePluginInfo *
plugin_query(GError **error)
{
	return purple_plugin_info_new(
		"id",          ROCKETCHAT_PLUGIN_ID,
		"name",        "Rocket.Chat",
		"version",     ROCKETCHAT_PLUGIN_VERSION,
		"category",    N_("Protocol"),
		"summary",     N_("Rocket.Chat Protocol Plugins."),
		"description", N_("Adds Rocket.Chat protocol support to libpurple."),
		"website",     ROCKETCHAT_PLUGIN_WEBSITE,
		"abi-version", PURPLE_ABI_VERSION,
		"flags",       PURPLE_PLUGIN_INFO_FLAGS_INTERNAL |
		               PURPLE_PLUGIN_INFO_FLAGS_AUTO_LOAD,
		NULL
	);
}

PURPLE_PLUGIN_INIT(rocketchat, plugin_query, libpurple3_plugin_load, libpurple3_plugin_unload);

#endif
