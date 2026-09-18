FROM ubuntu:22.04

# Avoid prompts
ENV DEBIAN_FRONTEND=noninteractive

# Install Xvfb, x11vnc, and a lightweight window manager
RUN apt-get update && apt-get install -y \
    xvfb \
    x11vnc \
    openbox \
    xterm \
    socat \
    && rm -rf /var/lib/apt/lists/*

# Set display
ENV DISPLAY=:1

# Expose VNC port
EXPOSE 5900

# Startup script
# 1. Start Xvfb (Virtual Frame Buffer)
# 2. Start Openbox (Window Manager)
# 3. Start a terminal for immediate interaction
# 4. Start x11vnc (VNC Server) in the foreground to keep container alive
CMD Xvfb :1 -screen 0 1024x768x24 & \
    openbox-session & \
    xterm -geometry 80x24+10+10 -ls -title "Honeygo Virtual Desktop" & \
    x11vnc -display :1 -forever -shared -nopw -rfbport 5900
