all:
	@echo "Nothing to build. To run the test-suite: make check"

check: node_modules
	$(MAKE) -C test deploy
	$(MAKE) -C test run

node_modules: package.json
	npm install

.PHONY: all check
