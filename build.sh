set -x
gcc -O3 -o main \
  main.c \
  baile/baile.c \
  blake3/blake3.c \
  blake3/blake3_portable.c \
  blake3/blake3_dispatch.c \
  blake3/blake3_avx512_x86-64_unix.S \
  blake3/blake3_sse41_x86-64_unix.S \
  blake3/blake3_avx2_x86-64_unix.S \
  blake3/blake3_sse2_x86-64_unix.S \
  -Ibaile \
  -Iblake3 

