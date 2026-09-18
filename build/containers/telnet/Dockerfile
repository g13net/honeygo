FROM docker.io/library/alpine:latest

RUN apk add busybox-extras && \
    echo "root:honeygo" | chpasswd && \
    adduser -D admin && \
    echo "admin:password" | chpasswd

# Run telnetd in foreground
ENTRYPOINT ["busybox-extras", "telnetd", "-F", "-p", "23"]
