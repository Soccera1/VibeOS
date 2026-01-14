cmd_applets/built-in.o :=  gcc -m32 -nostdlib -nostdlib -nostdlib -T ../user.ld ../user/start.o ../libc.o -r -o applets/built-in.o applets/applets.o
