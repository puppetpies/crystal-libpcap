all: test

test:
	crystal build --release test.cr -o bin/test

clean:
	rm -f test
	rm -Rf .crystal
