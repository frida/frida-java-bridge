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

clean:
	rm -rf node_modules
	$(MAKE) -C test clean

.PHONY: all check check-gdb develop clean
