CARGO=cargo
CARGO_FLAGS=

ifeq ($(APP_ENVIRONMENT),prod)
	CARGO_FLAGS+=--release
endif

.DEFAULT_GOAL := build

build:
	$(CARGO) build $(CARGO_FLAGS)
.PHONY: build
