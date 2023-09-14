/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014 Stefan Arentz <stefan@arentz.ca>
 * Copyright (c) 2017 Frederik Schwan <frederik dot schwan at linux dot com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <config.h>
#include <lib.h>
#include <net.h>
#if (DOVECOT_VERSION_MAJOR > 2u || (DOVECOT_VERSION_MAJOR == 2u && DOVECOT_VERSION_MINOR >= 3u))
#include <ostream-unix.h>
#include <ostream.h>
#endif
#include <unistd.h>
#include <push-notification-drivers.h>
#include <imap-arg.h>
#include <strescape.h>
#include <mail-storage-private.h>
#include <push-notification-txn-msg.h>

#include "xaps-daemon.h"

#include <stdio.h>

/**
 * Quote and escape a string. Not sure if this deals correctly with
 * unicode in mailbox names.
 */

static void xaps_str_append_quoted(string_t *dest, const char *str) {
    str_append_c(dest, '"');
    str_append(dest, str_escape(str));
    str_append_c(dest, '"');
}


int xaps_notify(const char *socket_path, const char *username, struct mail_user *mailuser , struct mailbox *mailbox, struct push_notification_txn_msg *msg) {
    struct push_notification_txn_event *const *event;
    /*
     * Construct the request.
     */
    string_t *req = t_str_new(1024);
    str_append(req, "NOTIFY");
    str_append(req, " dovecot-username=");
    xaps_str_append_quoted(req, username);
    str_append(req, "\tdovecot-mailbox=");
    xaps_str_append_quoted(req, mailbox->name);
    if (array_is_created(&msg->eventdata)) {
        str_append(req, "\tevents=(");
        int count = 0;
        array_foreach(&msg->eventdata, event) {
            if (count) {
                str_append(req, ",");
            }
            str_append(req, "\"");
            str_append(req, (*event)->event->event->name);
            str_append(req, "\"");
            count++;
        }
        str_append(req, ")");

    }

    i_error("notify='%.*s'",(int)(str_len(req)), str_data(req));
//    str_append(req, "\r\n");
//    push_notification_driver_debug(XAPS_LOG_LABEL, mailuser, "about to send: %p", req);

    // call external program to send the push trigger:
    if(username){
        char tmp[1024];
        sprintf(tmp,"/etc/xapsd/sendpush '%s'",username);
        system(tmp);
    }

    return 0; //send_to_daemon(socket_path, req, NULL);
}

int xaps_register(const char *socket_path, struct xaps_attr *xaps_attr) {

    string_t *req = t_str_new(1024);
    str_append(req, "REGISTER");
    str_append(req, " aps-account-id=");
    xaps_str_append_quoted(req, xaps_attr->aps_account_id);
    str_append(req, "\taps-device-token=");
    xaps_str_append_quoted(req, xaps_attr->aps_device_token);
    str_append(req, "\taps-subtopic=");
    xaps_str_append_quoted(req, xaps_attr->aps_subtopic);
    str_append(req, "\tdovecot-username=");
    xaps_str_append_quoted(req, xaps_attr->dovecot_username);
    str_append(req, "");

    if (xaps_attr->mailboxes == NULL) {
        str_append(req, "\tdovecot-mailboxes=(\"INBOX\")");
    } else {
        str_append(req, "\tdovecot-mailboxes=(");
        int next = 0;
        for (; !IMAP_ARG_IS_EOL(xaps_attr->mailboxes); xaps_attr->mailboxes++) {
            const char *mailbox;
            if (!imap_arg_get_astring(&(xaps_attr->mailboxes[0]), &mailbox)) {
                return -1;
            }
            if (next) {
                str_append(req, ",");
            }
            xaps_str_append_quoted(req, mailbox);
            next = 1;
        }
        str_append(req, ")");
    }

    i_error("register='%.*s'",(int)(str_len(req)), str_data(req));

    str_append(req, "\r\n");

//FIXME, read/copy UID from cert.pem:
//subject=UID = com.apple.mail.XServer.a5c53cf6-9cda-4e40-93a2-fc0e5fadd640, CN = APSP:a5c53cf6-9cda-4e40-93a2-fc0e5fadd640, C = HU
//issuer=CN = Apple Application Integration 2 Certification Authority, OU = Apple Certification Authority, O = Apple Inc., C = US
    str_append(xaps_attr->aps_topic, "com.apple.mail.XServer.a5c53cf6-9cda-4e40-93a2-fc0e5fadd640");

    // append registration data (username, account id & token) to file (path/name set in xaps.conf file 'xaps_socket' parameter - yes it's ugly :))
    int fd = open(socket_path, O_RDWR | O_APPEND);
    if(fd>0){
        char tmp[1024];
        int len=sprintf(tmp,"%s:%s:%s:%s\n",xaps_attr->dovecot_username,xaps_attr->aps_account_id,xaps_attr->aps_device_token,xaps_attr->aps_subtopic);
        write(fd,tmp,len);
        close(fd);
    }

    return 0;
}
