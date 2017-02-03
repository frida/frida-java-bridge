all:
	@echo "Nothing to build. To run the test-suite: make check"

check: node_modules
	$(MAKE) -C test deploy
	$(MAKE) -C test run

check-gdb: node_modules
	$(MAKE) -C test deploy
	$(MAKE) -C test debug

develop: node_modules
	$(MAKE) -C test deploy
	$(MAKE) -C test watch

node_modules: package.json
	npm install

.PHONY: all check
