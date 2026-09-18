ENGINE ?= $(shell which podman 2>/dev/null || which docker 2>/dev/null)

# Rootless Podman requires cgroupfs (not systemd) to run RUN steps without D-Bus permission errors.
# These flags are a no-op when using plain Docker.
PODMAN_FLAGS ?= $(shell $(ENGINE) --version 2>/dev/null | grep -q podman && echo "--cgroup-manager=cgroupfs --format=docker" || echo "")

.PHONY: images base-image ssh-image telnet-image vnc-image modbus-image s7comm-image

images: base-image ssh-image telnet-image vnc-image modbus-image s7comm-image

base-image:
	$(ENGINE) build $(PODMAN_FLAGS) -t honeygo-base -f build/containers/base/Dockerfile .

ssh-image:
	$(ENGINE) build $(PODMAN_FLAGS) -t honeygo-ssh -f build/containers/ssh/Dockerfile .

telnet-image:
	$(ENGINE) build $(PODMAN_FLAGS) -t honeygo-telnet -f build/containers/telnet/Dockerfile .

vnc-image:
	$(ENGINE) build $(PODMAN_FLAGS) -t honeygo-vnc -f build/containers/vnc/Dockerfile .

modbus-image:
	$(ENGINE) build $(PODMAN_FLAGS) -t honeygo-modbus -f build/containers/modbus/Dockerfile .

s7comm-image:
	$(ENGINE) build $(PODMAN_FLAGS) -t honeygo-s7comm -f build/containers/s7comm/Dockerfile .
