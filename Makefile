all: test

test:
	crystal compile --release test.cr -o bin/test

clean:
	rm -f test
	rm -Rf .crystal
