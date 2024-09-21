all: alloc

alloc: alloc.cpp
	clang++ -g -w -fsanitize=address -o alloc alloc.cpp

alloc_d: alloc.cpp
	clang++ -g -w -fsanitize=address -o alloc_d alloc.cpp -DDEBUG

debug: alloc_d
	./alloc_d 5 ./testcases/block3.i output.txt

run: alloc
	./alloc 5 ./testcases/block3.i output.txt

test: alloc
	./alloc 52 ./testcases/block1.i output.txt
	./sim -i 1024 1 1 < ./testcases/block1.i
	./sim -i 1024 1 1 < output.txt

clean:
	rm -f alloc
