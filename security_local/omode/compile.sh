gcc -o compressedBroadcast -g -Wall $(pkg-config rohc --cflags) compressedBroadcast.c $(pkg-config rohc --libs )
