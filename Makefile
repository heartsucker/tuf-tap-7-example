.PHONY: all clean help init run update venv
.DEFAULT_GOAL := run 

clean: ## Remove temp resources
	@rm -rf venv vectors

help: ## Show this message
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%16s\033[0m : %s\n", $$1, $$2}' $(MAKEFILE_LIST)

init: venv ## Initialize the environment
	@. venv/bin/activate && \
		pip install -Ur requirements.txt

run: init ## Run the server
	@. venv/bin/activate && \
		./server.py -t tuf

update: ## Update the requirements and virtualenv
	@pip-compile requirements.in && \
		$(MAKE) init

venv: ## Create the virtualenv
	@if [ ! -d venv ]; then virtualenv -p `which python3` venv; fi
