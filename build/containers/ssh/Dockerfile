FROM docker.io/library/alpine:latest

RUN apk add openssh-server && \
    ssh-keygen -A && \
    echo "root:honeygo" | chpasswd && \
    adduser -D admin && \
    echo "admin:password" | chpasswd && \
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config

ENTRYPOINT ["/usr/sbin/sshd", "-D", "-p", "22", "-e"]
