
// Compile:
// gcc -Wall -std=gnu99 -fPIC -shared -Wall -I/usr/include/dovecot -DHAVE_CONFIG_H applepush-plugin.c -o applepush_plugin.so

/* Copyright (c) 2007-2015 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "llist.h"
#include "str.h"
#include "str-sanitize.h"
#include "imap-util.h"
#include "mail-user.h"
#include "mail-storage-private.h"
#include "notify-plugin.h"

//#include "applepush-plugin.h"

#if 0

//#include "config.h"
#if (DOVECOT_VERSION_MAJOR >= 2u) && (DOVECOT_VERSION_MINOR >= 2u)
#include "net.h"
#else
#include "network.h"
#endif

#include "strescape.h"
#include "imap-common.h"
#include "imap-commands.h"
#include "mail-namespace.h"
#include "mailbox-list-private.h"

#include <stdlib.h>

#endif






int system(const char *command);

#define MAILBOX_NAME_LOG_LEN 64
#define HEADER_LOG_LEN 80

#define APPLEPUSH_USER_CONTEXT(obj) \
	MODULE_CONTEXT(obj, applepush_user_module)

enum applepush_field {
	APPLEPUSH_FIELD_UID	= 0x01,
	APPLEPUSH_FIELD_BOX	= 0x02,
	APPLEPUSH_FIELD_MSGID	= 0x04,
	APPLEPUSH_FIELD_PSIZE	= 0x08,
	APPLEPUSH_FIELD_VSIZE	= 0x10,
	APPLEPUSH_FIELD_FLAGS	= 0x20,
	APPLEPUSH_FIELD_FROM	= 0x40,
	APPLEPUSH_FIELD_SUBJECT	= 0x80,
	APPLEPUSH_FIELD_USER	= 0x100
};
#define APPLEPUSH_DEFAULT_FIELDS \
	(APPLEPUSH_FIELD_UID | APPLEPUSH_FIELD_BOX | \
	 APPLEPUSH_FIELD_MSGID | APPLEPUSH_FIELD_PSIZE)

enum applepush_event {
	APPLEPUSH_EVENT_DELETE		= 0x01,
	APPLEPUSH_EVENT_UNDELETE		= 0x02,
	APPLEPUSH_EVENT_EXPUNGE		= 0x04,
	APPLEPUSH_EVENT_SAVE		= 0x08,
	APPLEPUSH_EVENT_COPY		= 0x10,
	APPLEPUSH_EVENT_MAILBOX_CREATE	= 0x20,
	APPLEPUSH_EVENT_MAILBOX_DELETE	= 0x40,
	APPLEPUSH_EVENT_MAILBOX_RENAME	= 0x80,
	APPLEPUSH_EVENT_FLAG_CHANGE	= 0x100
};
#define APPLEPUSH_DEFAULT_EVENTS \
	(APPLEPUSH_EVENT_DELETE | APPLEPUSH_EVENT_UNDELETE | \
	 APPLEPUSH_EVENT_EXPUNGE | APPLEPUSH_EVENT_SAVE | APPLEPUSH_EVENT_COPY | \
	 APPLEPUSH_EVENT_MAILBOX_DELETE | APPLEPUSH_EVENT_MAILBOX_RENAME)

static const char *field_names[] = {
	"uid",
	"box",
	"msgid",
	"size",
	"vsize",
	"flags",
	"from",
	"subject",
	"user",
	NULL
};

static const char *event_names[] = {
	"delete",
	"undelete",
	"expunge",
	"save",
	"copy",
	"mailbox_create",
	"mailbox_delete",
	"mailbox_rename",
	"flag_change",
	NULL
};

struct applepush_user {
	union mail_user_module_context module_ctx;

	enum applepush_field fields;
	enum applepush_event events;

//	char aps_id[96];
//	char aps_token[32];
};

struct applepush_message {
	struct applepush_message *prev, *next;

	enum applepush_event event;
	bool ignore;
	const char *pretext, *text;
//	const char *username;
	struct mail_user *mu;
};

struct applepush_mail_txn_context {
	pool_t pool;
	struct applepush_message *messages, *messages_tail;
};

static MODULE_CONTEXT_DEFINE_INIT(applepush_user_module,
				  &mail_user_module_register);

static enum applepush_field applepush_field_find(const char *name)
{
	unsigned int i;

	for (i = 0; field_names[i] != NULL; i++) {
		if (strcmp(name, field_names[i]) == 0)
			return 1 << i;
	}
	return 0;
}

static enum applepush_event applepush_event_find(const char *name)
{
	unsigned int i;

	if (strcmp(name, "append") == 0) {
		/* v1.x backwards compatibility */
		name = "save";
	}
	for (i = 0; event_names[i] != NULL; i++) {
		if (strcmp(name, event_names[i]) == 0)
			return 1 << i;
	}
	return 0;
}

static enum applepush_field applepush_parse_fields(const char *str)
{
	const char *const *tmp;
	static enum applepush_field field, fields = 0;

	for (tmp = t_strsplit_spaces(str, ", "); *tmp != NULL; tmp++) {
		field = applepush_field_find(*tmp);
		if (field == 0)
			i_fatal("Unknown field in applepush_fields: '%s'", *tmp);
		fields |= field;
	}
	return fields;
}

static enum applepush_event applepush_parse_events(const char *str)
{
	const char *const *tmp;
	static enum applepush_event event, events = 0;

	for (tmp = t_strsplit_spaces(str, ", "); *tmp != NULL; tmp++) {
		event = applepush_event_find(*tmp);
		if (event == 0)
			i_fatal("Unknown event in applepush_events: '%s'", *tmp);
		events |= event;
	}
	return events;
}

static void applepush_mail_user_created(struct mail_user *user)
{
	struct applepush_user *muser;
	const char *str;

	muser = p_new(user->pool, struct applepush_user, 1);
	MODULE_CONTEXT_SET(user, applepush_user_module, muser);

	str = mail_user_plugin_getenv(user, "applepush_fields");
	muser->fields = str == NULL ? APPLEPUSH_DEFAULT_FIELDS :
		applepush_parse_fields(str);

	str = mail_user_plugin_getenv(user, "applepush_events");
	muser->events = str == NULL ? APPLEPUSH_DEFAULT_EVENTS :
		applepush_parse_events(str);
}

static void applepush_append_mailbox_name(string_t *str, struct mail *mail)
{
	const char *mailbox_str;

	mailbox_str = mailbox_get_vname(mail->box);
	str_printfa(str, "box=%s",
		    str_sanitize(mailbox_str, MAILBOX_NAME_LOG_LEN));
}

static struct mail_user* applepush_get_mailbox_user(struct mail *mail){
	if(!mail) return NULL;
	if(!mail->box) return NULL;
	struct mail_storage *stor=mailbox_get_storage(mail->box);
	if(!stor) return NULL;
	return mail_storage_get_user(stor);
}

static void applepush_append_mailbox_user(string_t *str, struct mail_user *mu)
{
	const char *mailbox_str;

	if(mu){
	    mailbox_str = mu->username;
	    str_printfa(str, "user=%s",
		    str_sanitize(mailbox_str, MAILBOX_NAME_LOG_LEN));
	}
}



static void
applepush_append_mail_header(string_t *str, struct mail *mail,
			    const char *name, const char *header)
{
	const char *value;

	if (mail_get_first_header(mail, header, &value) <= 0)
		value = "";
	str_printfa(str, "%s=%s", name, str_sanitize(value, HEADER_LOG_LEN));
}

static void
applepush_append_uid(struct applepush_mail_txn_context *ctx,
		    struct applepush_message *msg, string_t *str, uint32_t uid)
{
	if (uid != 0)
		str_printfa(str, "uid=%u", uid);
	else {
		/* we don't know the uid yet, assign it later */
		str_printfa(str, "uid=");
		msg->pretext = p_strdup(ctx->pool, str_c(str));
		str_truncate(str, 0);
	}
}

static void
applepush_update_wanted_fields(struct mail *mail, enum applepush_field fields)
{
	enum mail_fetch_field wanted_fields = 0;
	struct mailbox_header_lookup_ctx *wanted_headers = NULL;
	const char *headers[4];
	unsigned int hdr_idx = 0;

	if ((fields & APPLEPUSH_FIELD_MSGID) != 0)
		headers[hdr_idx++] = "Message-ID";
	if ((fields & APPLEPUSH_FIELD_FROM) != 0)
		headers[hdr_idx++] = "From";
	if ((fields & APPLEPUSH_FIELD_SUBJECT) != 0)
		headers[hdr_idx++] = "Subject";
	if (hdr_idx > 0) {
		i_assert(hdr_idx < N_ELEMENTS(headers));
		headers[hdr_idx] = NULL;
		wanted_headers = mailbox_header_lookup_init(mail->box, headers);
	}

	if ((fields & APPLEPUSH_FIELD_PSIZE) != 0)
		wanted_fields |= MAIL_FETCH_PHYSICAL_SIZE;
	if ((fields & APPLEPUSH_FIELD_VSIZE) != 0)
		wanted_fields |= MAIL_FETCH_VIRTUAL_SIZE;

	mail_add_temp_wanted_fields(mail, wanted_fields, wanted_headers);
	if (wanted_headers != NULL)
		mailbox_header_lookup_unref(&wanted_headers);
}

static void
applepush_append_mail_message_real(struct applepush_mail_txn_context *ctx,
				  struct mail *mail, enum applepush_event event,
				  const char *desc)
{
	struct applepush_user *muser =
		APPLEPUSH_USER_CONTEXT(mail->box->storage->user);
	struct applepush_message *msg;
	string_t *text;
	uoff_t size;

	msg = p_new(ctx->pool, struct applepush_message, 1);

	/* avoid parsing through the message multiple times */
	applepush_update_wanted_fields(mail, muser->fields);

	text = t_str_new(128);
	str_append(text, desc);
	str_append(text, ": ");
	if ((muser->fields & APPLEPUSH_FIELD_BOX) != 0) {
		applepush_append_mailbox_name(text, mail);
		str_append(text, ", ");
	}
	if ((muser->fields & APPLEPUSH_FIELD_UID) != 0) {
		if (event != APPLEPUSH_EVENT_SAVE &&
		    event != APPLEPUSH_EVENT_COPY)
			applepush_append_uid(ctx, msg, text, mail->uid);
		else {
			/* with mbox mail->uid contains the uid, but handle
			   this consistently with all mailbox formats */
			applepush_append_uid(ctx, msg, text, 0);
		}
		str_append(text, ", ");
	}
	if ((muser->fields & APPLEPUSH_FIELD_MSGID) != 0) {
		applepush_append_mail_header(text, mail, "msgid", "Message-ID");
		str_append(text, ", ");
	}
	if ((muser->fields & APPLEPUSH_FIELD_PSIZE) != 0) {
		if (mail_get_physical_size(mail, &size) == 0)
			str_printfa(text, "size=%"PRIuUOFF_T, size);
		else
			str_printfa(text, "size=error");
		str_append(text, ", ");
	}
	if ((muser->fields & APPLEPUSH_FIELD_VSIZE) != 0) {
		if (mail_get_virtual_size(mail, &size) == 0)
			str_printfa(text, "vsize=%"PRIuUOFF_T, size);
		else
			str_printfa(text, "vsize=error");
		str_append(text, ", ");
	}
	if ((muser->fields & APPLEPUSH_FIELD_FROM) != 0) {
		applepush_append_mail_header(text, mail, "from", "From");
		str_append(text, ", ");
	}
	if ((muser->fields & APPLEPUSH_FIELD_SUBJECT) != 0) {
		applepush_append_mail_header(text, mail, "subject", "Subject");
		str_append(text, ", ");
	}

	msg->mu=applepush_get_mailbox_user(mail);
	if ((muser->fields & APPLEPUSH_FIELD_USER) != 0) {
		applepush_append_mailbox_user(text, msg->mu);
		str_append(text, ", ");
	}
	if(msg->mu) i_info("XXX username=%s mu=%p",msg->mu->username,msg->mu);

	if ((muser->fields & APPLEPUSH_FIELD_FLAGS) != 0) {
		str_printfa(text, "flags=(");
		imap_write_flags(text, mail_get_flags(mail),
				 mail_get_keywords(mail));
		str_append(text, "), ");
	}
	str_truncate(text, str_len(text)-2);

	msg->event = event;
	msg->text = p_strdup(ctx->pool, str_c(text));
	DLLIST2_APPEND(&ctx->messages, &ctx->messages_tail, msg);
}

static void applepush_add_dummy_msg(struct applepush_mail_txn_context *ctx,
				   enum applepush_event event)
{
	struct applepush_message *msg;

	msg = p_new(ctx->pool, struct applepush_message, 1);
	msg->event = event;
	msg->ignore = TRUE;
	DLLIST2_APPEND(&ctx->messages, &ctx->messages_tail, msg);
}

static void
applepush_append_mail_message(struct applepush_mail_txn_context *ctx,
			     struct mail *mail, enum applepush_event event,
			     const char *desc)
{
	struct applepush_user *muser =
		APPLEPUSH_USER_CONTEXT(mail->box->storage->user);

	if ((muser->events & event) == 0) {
		if (event == APPLEPUSH_EVENT_SAVE ||
		    event == APPLEPUSH_EVENT_COPY)
			applepush_add_dummy_msg(ctx, event);
		return;
	}

	T_BEGIN {
		applepush_append_mail_message_real(ctx, mail, event, desc);
	} T_END;
}

static void *
applepush_mail_transaction_begin(struct mailbox_transaction_context *t ATTR_UNUSED)
{
	pool_t pool;
	struct applepush_mail_txn_context *ctx;

	pool = pool_alloconly_create("applepush", 2048);
	ctx = p_new(pool, struct applepush_mail_txn_context, 1);
	ctx->pool = pool;
//	i_info("trans begin!");
	return ctx;
}

static void applepush_mail_save(void *txn, struct mail *mail)
{
	struct applepush_mail_txn_context *ctx =
		(struct applepush_mail_txn_context *)txn;

	applepush_append_mail_message(ctx, mail, APPLEPUSH_EVENT_SAVE, "save");
}

static void applepush_mail_copy(void *txn, struct mail *src, struct mail *dst)
{
	struct applepush_mail_txn_context *ctx =
		(struct applepush_mail_txn_context *)txn;
	struct mail_private *src_pmail = (struct mail_private *)src;
	struct mailbox *src_box = src->box;
	const char *desc;

	i_info("MAIL_COPY!!!");

	if (src_pmail->vmail != NULL) {
		/* copying a mail from virtual storage. src points to the
		   backend mail, but we want to log the virtual mailbox name. */
		src_box = src_pmail->vmail->box;
	}
//Dec  5 22:11:35 webmail dovecot: lda(camera): copy from stdin: box=INBOX, uid=192379, msgid=<1112960713.10169.1449349893856.JavaMail.unifi-video@telek>, size=94092
	desc = t_strdup_printf("copy from %s",
			       str_sanitize(mailbox_get_vname(src_box),
					    MAILBOX_NAME_LOG_LEN));
	applepush_append_mail_message(ctx, dst,
				     APPLEPUSH_EVENT_COPY, desc);
}

static void applepush_mail_expunge(void *txn, struct mail *mail)
{
	struct applepush_mail_txn_context *ctx =
		(struct applepush_mail_txn_context *)txn;
	
	applepush_append_mail_message(ctx, mail, APPLEPUSH_EVENT_EXPUNGE,
				     "expunge");
}

static void applepush_mail_update_flags(void *txn, struct mail *mail,
				       enum mail_flags old_flags)
{
	struct applepush_mail_txn_context *ctx =
		(struct applepush_mail_txn_context *)txn;
	enum mail_flags new_flags = mail_get_flags(mail);

	if (((old_flags ^ new_flags) & MAIL_DELETED) == 0) {
		applepush_append_mail_message(ctx, mail,
					     APPLEPUSH_EVENT_FLAG_CHANGE,
					     "flag_change");
	} else if ((old_flags & MAIL_DELETED) == 0) {
		applepush_append_mail_message(ctx, mail, APPLEPUSH_EVENT_DELETE,
					     "delete");
	} else {
		applepush_append_mail_message(ctx, mail, APPLEPUSH_EVENT_UNDELETE,
					     "undelete");
	}
}

static void
applepush_mail_update_keywords(void *txn, struct mail *mail, 
			      const char *const *old_keywords ATTR_UNUSED)
{
	struct applepush_mail_txn_context *ctx =
		(struct applepush_mail_txn_context *)txn;

	applepush_append_mail_message(ctx, mail, APPLEPUSH_EVENT_FLAG_CHANGE,
				     "flag_change");
}

static void applepush_save(const struct applepush_message *msg, uint32_t uid)
{


	if (msg->ignore) {
		/* not logging this save/copy */
	} else if (msg->pretext == NULL)
		i_info("%s", msg->text);
	else if (uid != 0)
		i_info("%s%u%s", msg->pretext, uid, msg->text);
	else
		i_info("%serror%s", msg->pretext, msg->text);
}

static void
applepush_mail_transaction_commit(void *txn,
				 struct mail_transaction_commit_changes *changes)
{
	struct applepush_mail_txn_context *ctx =
		(struct applepush_mail_txn_context *)txn;
	struct applepush_message *msg;
	struct seq_range_iter iter;
	unsigned int n = 0;
	struct mail_user *mu=NULL;
//	const char* username=NULL;
	uint32_t uid;
	char cmd[100];

	seq_range_array_iter_init(&iter, &changes->saved_uids);
	for (msg = ctx->messages; msg != NULL; msg = msg->next) {
		if(msg->mu){
		    if(mu!=msg->mu && mu)
			i_info("multi_usernames: %s -> %s", mu->username,msg->mu->username);
		    mu=msg->mu;
		}
		if (msg->event == APPLEPUSH_EVENT_SAVE ||
		    msg->event == APPLEPUSH_EVENT_COPY) {
			if (!seq_range_array_iter_nth(&iter, n++, &uid))
				uid = 0;
			applepush_save(msg, uid);
		} else {
			i_assert(msg->pretext == NULL);
			i_info("%s", msg->text);
		}
	}
	i_assert(!seq_range_array_iter_nth(&iter, n, &uid));

        if(mu){
//		i_info("push_notify: mu=%p", mu);
//	        struct applepush_user *muser = APPLEPUSH_USER_CONTEXT(mu);
//		i_info("push_notify: muser=%p", muser);
		//sleep(10);
		strcpy(cmd,"/etc/xapsd/notify.sh ");
		strcat(cmd,mu->username);
		i_info("push_notify: user=%s cmd='%s'", mu->username,cmd);
		system(cmd); // EXEC!!!!!!!!!!!
	}

	pool_unref(&ctx->pool);
}

static void applepush_mail_transaction_rollback(void *txn)
{
	struct applepush_mail_txn_context *ctx =
		(struct applepush_mail_txn_context *)txn;

	pool_unref(&ctx->pool);
}

static void
applepush_mailbox_create(struct mailbox *box)
{
	struct applepush_user *muser = APPLEPUSH_USER_CONTEXT(box->storage->user);

	if ((muser->events & APPLEPUSH_EVENT_MAILBOX_CREATE) == 0)
		return;

	i_info("Mailbox created: %s",
	       str_sanitize(mailbox_get_vname(box), MAILBOX_NAME_LOG_LEN));
}

static void
applepush_mailbox_delete_commit(void *txn ATTR_UNUSED, struct mailbox *box)
{
	struct applepush_user *muser = APPLEPUSH_USER_CONTEXT(box->storage->user);

	if ((muser->events & APPLEPUSH_EVENT_MAILBOX_DELETE) == 0)
		return;

	i_info("Mailbox deleted: %s",
	       str_sanitize(mailbox_get_vname(box), MAILBOX_NAME_LOG_LEN));
}

static void
applepush_mailbox_rename(struct mailbox *src, struct mailbox *dest)
{
	struct applepush_user *muser = APPLEPUSH_USER_CONTEXT(src->storage->user);

	if ((muser->events & APPLEPUSH_EVENT_MAILBOX_RENAME) == 0)
		return;

	i_info("Mailbox renamed: %s -> %s",
	       str_sanitize(mailbox_get_vname(src), MAILBOX_NAME_LOG_LEN),
	       str_sanitize(mailbox_get_vname(dest), MAILBOX_NAME_LOG_LEN));
}

static const struct notify_vfuncs applepush_vfuncs = {
	.mail_transaction_begin = applepush_mail_transaction_begin,
	.mail_save = applepush_mail_save,
	.mail_copy = applepush_mail_copy,
	.mail_expunge = applepush_mail_expunge,
	.mail_update_flags = applepush_mail_update_flags,
	.mail_update_keywords = applepush_mail_update_keywords,
	.mail_transaction_commit = applepush_mail_transaction_commit,
	.mail_transaction_rollback = applepush_mail_transaction_rollback,
	.mailbox_create = applepush_mailbox_create,
	.mailbox_delete_commit = applepush_mailbox_delete_commit,
	.mailbox_rename = applepush_mailbox_rename
};

static struct notify_context *applepush_ctx;

static struct mail_storage_hooks applepush_mail_storage_hooks = {
	.mail_user_created = applepush_mail_user_created
};



#if 0

/**
 * Command handler for the XAPPLEPUSHSERVICE command. The command is
 * used by iOS clients to register for push notifications.
 *
 * We receive a list of key value pairs from the client, with the
 * following keys:
 *
 *  aps-version      - always set to "2"
 *  aps-account-id   - a unique id the iOS device has associated with this account
 *  api-device-token - the APS device token
 *  api-subtopic     - always set to "com.apple.mobilemail"
 *  mailboxes        - list of mailboxes to send notifications for
 *
 * For example:
 *
 *  XAPPLEPUSHSERVICE aps-version 2 aps-account-id 0715A26B-CA09-4730-A419-793000CA982E
 *    aps-device-token 2918390218931890821908309283098109381029309829018310983092892829
 *    aps-subtopic com.apple.mobilemail mailboxes (INBOX Notes)
 *
 * To minimize the work that needs to be done inside the IMAP client,
 * we only parse and validate the parameters and then simply push all
 * of this to the supporting daemon that will record the mapping
 * between the account and the iOS client.
 */

static bool cmd_xapplepushservice(struct client_command_context *cmd)
{
  /*
   * Parse arguments. We expect four key value pairs. We only take
   * those that we understand for version 2 of this extension.
   *
   * TODO: We are ignoring the mailboxes parameter for now and just
   * default to INBOX always.
   */

  const struct imap_arg *args;
  const char *arg_key, *arg_val;
  const char *aps_version = NULL, *aps_account_id = NULL, *aps_device_token = NULL, *aps_subtopic = NULL;

  if (!client_read_args(cmd, 0, 0, &args)) {
    client_send_command_error(cmd, "Invalid arguments.");
    return FALSE;
  }

  for (int i = 0; i < 4; i++) {
    if (!imap_arg_get_astring(&args[i*2+0], &arg_key)) {
      client_send_command_error(cmd, "Invalid arguments.");
      return FALSE;
    }

    if (!imap_arg_get_astring(&args[i*2+1], &arg_val)) {
      client_send_command_error(cmd, "Invalid arguments.");
      return FALSE;
    }

    if (strcasecmp(arg_key, "aps-version") == 0) {
      aps_version = arg_val;
    } else if (strcasecmp(arg_key, "aps-account-id") == 0) {
      aps_account_id = arg_val;
    } else if (strcasecmp(arg_key, "aps-device-token") == 0) {
      aps_device_token = arg_val;
    } else if (strcasecmp(arg_key, "aps-subtopic") == 0) {
      aps_subtopic = arg_val;
    }
  }

  /*
   * Check if this is a version we expect
   */

  if (!aps_version || (strcmp(aps_version, "1") != 0 && strcmp(aps_version, "2") != 0)) {
    client_send_command_error(cmd, "Unknown aps-version.");
    return FALSE;
  }

  /*
   * If this is version 2 then also need to grab the mailboxes, which
   * is a list of mailbox names.
   */

  const struct imap_arg *mailboxes = NULL;

  if (strcmp(aps_version, "2") == 0) {
    if (!imap_arg_get_astring(&args[8], &arg_key)) {
      client_send_command_error(cmd, "Invalid arguments.");
      return FALSE;
    }

    if (strcmp(arg_key, "mailboxes") != 0) {
      client_send_command_error(cmd, "Invalid arguments. (Expected mailboxes)");
      return FALSE;
    }

    if (!imap_arg_get_list(&args[9], &mailboxes)) {
      client_send_command_error(cmd, "Invalid arguments.");
      return FALSE;
    }
  }

  /*
   * Check if all of the parameters are there.
   */

  if (!aps_account_id || strlen(aps_account_id) == 0) {
    client_send_command_error(cmd, "Incomplete or empty aps-account-id parameter.");
    return FALSE;
  }

  if (!aps_device_token || strlen(aps_device_token) == 0) {
    client_send_command_error(cmd, "Incomplete or empty aps-device-token parameter.");
    return FALSE;
  }

  if (!aps_subtopic || strlen(aps_subtopic) == 0) {
    client_send_command_error(cmd, "Incomplete or empty aps-subtopic parameter.");
    return FALSE;
  }

  /*
   * Forward to the helper daemon. The helper will return the
   * aps-topic, which in reality is the subject of the certificate. I
   * think it is only used to make sure that the binding between the
   * client and the APS server and the IMAP server stays current.
   */

  struct client *client = cmd->client;
  struct mail_user *user = client->user;

  struct applepush_user *muser = APPLEPUSH_USER_CONTEXT(user);
  strcpy(muser->aps_id,aps_account_id);

  i_info("XAPPLEPUSH!!! mu=%p muser=%p fields=0x%02X user=%s id=%s token=%s",user,muser,muser->fields,user->username,muser->aps_id,aps_device_token);

  int i;
  for(i=0;i<64;i++){
     int c=aps_device_token[i]; if(!c) break;
     if(c>'9') c-='A'; else c-='0';
     c&=15;
     if(i&1) muser->aps_token[i>>1]|=c; else muser->aps_token[i>>1]=c<<4;
  }

//  string_t *aps_topic = t_str_new(0);
//  if (xaps_register(socket_path, aps_account_id, aps_device_token, aps_subtopic, user->username, mailboxes, aps_topic) != 0) {
//    client_send_command_error(cmd, "Registration failed.");
//    return FALSE;
//  }

  /*
   * Return success. We assume that aps_version and aps_topic do not
   * contain anything that needs to be escaped.
   */

  client_send_line(cmd->client,
    t_strdup_printf("* XAPPLEPUSHSERVICE aps-version \"%s\" aps-topic \"%s\"", aps_version,
	 "com.apple.mail.XServer.a5c53cf6-9cda-4e40-93a2-fc0e5fadd640"));
  client_send_tagline(cmd, "OK XAPPLEPUSHSERVICE Registration successful.");

  return TRUE;
}

#endif










void applepush_plugin_init(struct module *module)
{
	applepush_ctx = notify_register(&applepush_vfuncs);
	mail_storage_hooks_add(module, &applepush_mail_storage_hooks);
//  command_register("XAPPLEPUSHSERVICE", cmd_xapplepushservice, 0);
}

void applepush_plugin_deinit(void)
{
	mail_storage_hooks_remove(&applepush_mail_storage_hooks);
	notify_unregister(applepush_ctx);
//  command_unregister("XAPPLEPUSHSERVICE");
}

const char *applepush_plugin_dependencies[] = { "notify", NULL };


