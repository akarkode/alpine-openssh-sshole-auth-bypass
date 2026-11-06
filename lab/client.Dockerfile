FROM alpine:3.21

RUN apk add --no-cache openssh-client

COPY exploit.sh /exploit.sh
RUN chmod +x /exploit.sh

ENTRYPOINT ["/exploit.sh"]
