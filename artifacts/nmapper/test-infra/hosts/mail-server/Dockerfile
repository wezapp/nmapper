FROM alpine:3.19

RUN apk add --no-cache socat bash

COPY start.sh /start.sh
RUN chmod +x /start.sh

# SMTP, SMTPS, Submission, IMAP, IMAPS, POP3, POP3S
EXPOSE 25 465 587 143 993 110 995

CMD ["/start.sh"]
