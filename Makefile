.DEFAULT_GOAL := test

EXCLUDE_LINT := should be.*UI

Coding/bin/Makefile.base:
	git clone https://github.com/dedis/Coding
include Coding/bin/Makefile.base

# You can use `test_playground` to run any test or part of cothority
# for more than once in Travis. Change `make test` in .travis.yml
# to `make test_playground`.
test_playground:
	cd byzcoin; \
	for a in $$( seq 100 ); do \
		if DEBUG_TIME=true go test -v -race > log.txt 2>&1; then \
			echo Successfully ran \#$$a at $$(date); \
		else \
			echo Failed at $$(date); \
			cat log.txt; \
			exit 1; \
		fi; \
	done;

proto:
	./proto.sh
	make -C external

docker:
	cd conode/; make docker_dev
	cd external/docker/; make docker_test

docker_test_run: docker
	docker run -ti -p7770-7777:7770-7777 dedis/conode-test

test_java: docker
	cd external/java; mvn test

test_proto:
	@./proto.sh > /dev/null; \
	if [ "$$( git diff )" ]; then \
		echo "Please update proto-files with 'make proto'"; \
		exit 1; \
	fi
