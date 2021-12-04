CONTAINER_NAME=blockchain-messenger-builder

RUNNING = $(shell docker ps --format '{{.Names}}' | grep -w $(CONTAINER_NAME) -m1)
EXISTS = $(shell docker ps -a --format '{{.Names}}' | grep -w $(CONTAINER_NAME) -m1)

start-env:
ifneq ($(RUNNING), $(CONTAINER_NAME))
	docker build -t $(CONTAINER_NAME) .
	docker run --name $(CONTAINER_NAME) --volume $(PWD):/usr/src/app --detach $(CONTAINER_NAME)
endif

build: start-env
	docker exec -it $(CONTAINER_NAME) /bin/bash -c \
		"RUSTFLAGS='-C linker=x86_64-pc-windows-gnu' cargo build --target x86_64-pc-windows-gnu --release"

stop-env:
ifeq ($(RUNNING), $(CONTAINER_NAME))
	docker stop $(CONTAINER_NAME) && docker rm $(CONTAINER_NAME)
endif

clean: stop-env
ifeq ($(EXISTS), $(CONTAINER_NAME))
	docker rm $(CONTAINER_NAME)
endif