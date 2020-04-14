NAME?=mitm

PROJECT_DIR=$(shell echo `pwd`)
BUILD_DIR=$(PROJECT_DIR)/build

all:
	@$(CHANGE_VERSION)
	go build -ldflags "-s -w"  -o $(BUILD_DIR)/$(NAME) $(PROJECT_DIR)/src/*.go

debug:
	@$(SET_ENV)
	go build -o $(BUILD_DIR)/$(NAME) $(PROJECT_DIR)/src/*.go

.PHONY: clean
clean:
	rm -fr $(BUILD_DIR)/$(NAME)
