gcc -o CompressorSend -g -Wall $(pkg-config rohc --cflags) CompressorSend.c $(pkg-config rohc --libs )
