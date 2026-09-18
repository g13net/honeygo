FROM docker.io/library/alpine:latest

# No need for telnetd/sshd if we use docker exec handoff
RUN apk add --no-cache busybox-extras bash socat

# Create a dummy user environment
RUN adduser -D user && \
    mkdir -p /home/user && \
    echo "Welcome to the sandbox!" > /home/user/MOTD

# Stay alive so we can exec into it
ENTRYPOINT ["tail", "-f", "/dev/null"]
