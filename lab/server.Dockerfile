FROM alpine:3.21

# Default = last VULNERABLE Alpine package. Build with
#   --build-arg OPENSSH_VER=9.9_p2-r1
# to get the fixed package for an A/B comparison.
# openssh-server is built WITHOUT PAM -> the affected configuration.
ARG OPENSSH_VER=9.9_p2-r0

RUN apk add --no-cache curl \
 && mkdir -p /tmp/apks \
 && for p in openssh-server-common openssh-keygen openssh-server ; do \
        f="$p-$OPENSSH_VER.apk" ; \
        curl -fsSL --retry 5 --retry-delay 2 \
          -o "/tmp/apks/$f" \
          "https://dl-cdn.alpinelinux.org/alpine/v3.21/main/x86_64/$f" ; \
    done \
 && apk add --no-cache /tmp/apks/*.apk \
 && apk del curl \
 && rm -rf /tmp/apks /var/cache/apk/*

COPY sshd.conf /etc/ssh/sshd_config
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22
CMD ["/entrypoint.sh"]
