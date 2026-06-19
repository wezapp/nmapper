#!/bin/sh

smtp_banner() {
    printf "220 mail.corp.local ESMTP Postfix (Ubuntu)\r\n"
}

imap_banner() {
    printf "* OK [CAPABILITY IMAP4rev1 LITERAL+ SASL-IR LOGIN-REFERRALS ID ENABLE IDLE AUTH=PLAIN] Dovecot ready.\r\n"
}

pop3_banner() {
    printf "+OK Dovecot ready.\r\n"
}

# SMTP (25)
while true; do
    socat TCP4-LISTEN:25,reuseaddr EXEC:'printf "220 mail.corp.local ESMTP Postfix\r\n"' 2>/dev/null || true
done &

# SMTPS (465)
while true; do
    socat TCP4-LISTEN:465,reuseaddr EXEC:'printf "220 mail.corp.local ESMTP Postfix (TLS)\r\n"' 2>/dev/null || true
done &

# Submission (587)
while true; do
    socat TCP4-LISTEN:587,reuseaddr EXEC:'printf "220 mail.corp.local ESMTP Postfix\r\n"' 2>/dev/null || true
done &

# IMAP (143)
while true; do
    socat TCP4-LISTEN:143,reuseaddr EXEC:'printf "* OK Dovecot IMAP4rev1 ready\r\n"' 2>/dev/null || true
done &

# IMAPS (993)
while true; do
    socat TCP4-LISTEN:993,reuseaddr EXEC:'printf "* OK Dovecot IMAP4rev1 ready\r\n"' 2>/dev/null || true
done &

# POP3 (110)
while true; do
    socat TCP4-LISTEN:110,reuseaddr EXEC:'printf "+OK Dovecot ready\r\n"' 2>/dev/null || true
done &

# POP3S (995)
while true; do
    socat TCP4-LISTEN:995,reuseaddr EXEC:'printf "+OK Dovecot ready\r\n"' 2>/dev/null || true
done &

echo "Mail server started — SMTP:25/465/587, IMAP:143/993, POP3:110/995"
wait
