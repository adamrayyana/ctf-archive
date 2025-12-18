# compile with all protections on
compile:
	gcc -o main main.c -fstack-protector-strong -Wl,-z,relro,-z,now
clean:
	rm -f main libc ld ld-linux-x86-64.so.2 main_patched
patch:
	/opt/pwninit.py/pwninit.py
all: clean compile patch