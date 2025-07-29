all:
	g++ DES.cpp -o des

run: all
	./des

clean:
	rm -f des
