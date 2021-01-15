// Copyright: Renzo Carbonara, 2021. 
//
// This work is released into the public domain with CC0 1.0. 
//
// Alternatively, it is licensed under the Apache License 2.0. 

#include <baile.h>
#include <blake3.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/*****************************************************************************
 * General tools *************************************************************/

// XOR the little-endian encoding of `x` into `dst`.
static void xor64le(void *dst, uint64_t x);
static inline void xor64le(void *dst, uint64_t x) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  *(uint64_t *)dst ^= x;
#else
  ((uint8_t *)dst)[0] ^= x;
  ((uint8_t *)dst)[1] ^= x >> 8;
  ((uint8_t *)dst)[2] ^= x >> 16;
  ((uint8_t *)dst)[3] ^= x >> 24;
  ((uint8_t *)dst)[4] ^= x >> 32;
  ((uint8_t *)dst)[5] ^= x >> 40;
  ((uint8_t *)dst)[6] ^= x >> 48;
  ((uint8_t *)dst)[7] ^= x >> 56;
#endif
}

// Fill `dst` with `n` zeros. Returns `dst`.
//
// TODO: make faster and prevent it from being optimized away.
static void * memzero(void *dst, size_t n);
static inline void * memzero(void *dst, size_t n) {
  memset(dst, 0, n);
  return dst;
}

// XOR `n` bytes in `a` and `b` into `dst`. Returns `dst`.
//
// If `dst` and `a` or `b` are the same, XORing happens in-place.
//
// TODO: make faster.
static void * memxor(void *dst, const void *a, const void *b, size_t n);
static inline void * memxor(void *dst, const void *a, const void *b, size_t n) {
  uint8_t * p = dst;
  while (n--) { *(p++) = *((uint8_t*)a++) ^ *((uint8_t*)b++); }
  return dst;
}

// How much padding is necessary to add to `x` so that it aligns 
// to a multiple of 64?
//
// align64(0)  = 0
// align64(1)  = 63
// align64(63) = 1
// align64(64) = 0
// align64(65) = 63
static size_t align64(size_t x);
static inline size_t align64(size_t x) { 
  return (x & 63) ? (64 - (x & 63)) : 0;
}

/*****************************************************************************
 * Things that belong in BLAKE3 proper ***************************************/

// XOR `len` bytes starting at `src` with the BLAKE3 stream, write the result
// in `dst`. If `src` and `dst` are the same, XORing happens in-place.
static void blake3_hasher_finalize_xor(
  blake3_hasher *h, uint8_t *dst, const uint8_t *src, size_t len);
static inline void blake3_hasher_finalize_xor(
  blake3_hasher *h, uint8_t *dst, const uint8_t *src, size_t len)
{
  if (len == 0) return;

  uint8_t buf[64]; 
  size_t off = 0;  

  // Entire 64 byte blocks, if any.
  while (len - off >= 64) {
    blake3_hasher_finalize_seek(h, off, buf, 64);
    memxor(dst + off, src + off, buf, 64);
    off += 64;
  }
  
  // Up to 63 trailing bytes, if any.
  if (len - off) {
    blake3_hasher_finalize_seek(h, off, buf, len - off);
    memxor(dst + off, src + off, buf, len - off);
  }
  
  memzero(buf, sizeof(buf));
}


/*****************************************************************************
 * Baile *********************************************************************/

static const uint8_t zeros[64] = { 0 };

// INTERNAL. Feeds into `h` all the input necessary to obtain the `tag`.
static void baile_tag_input(
  blake3_hasher * h, 
  const uint8_t * ad,
  size_t ad_len,
  const uint8_t * text,
  size_t text_len,
  const uint8_t * key);
static inline void baile_tag_input(
  blake3_hasher * h, 
  const uint8_t * ad,
  size_t ad_len,
  const uint8_t * text,
  size_t text_len,
  const uint8_t * key)
{
  uint8_t key2[32];
  uint8_t tmp[8];

  // Hash key: key (little-endian) with its least significant bit negated, its
  // lowest bytes 8 through 15 XORed with ad_len (little-endian), and its
  // lowest bytes 16 through 23 XORed with text_len (little-endian).
  //
  // Example: [n_______ aaaaaaaa tttttttt ________] 
  //           0        8        16       24       32
  //   n: negate least significant bit, a: xor ad_len, t: xor text_len
  memcpy(key2, key, 32); 
  key2[0] ^= 0b1;               // n
  xor64le(key2 + 8,  ad_len);   // a 
  xor64le(key2 + 16, text_len); // t
  blake3_hasher_init_keyed(h, key2);
  memzero(key2, 32);
  
  // Hash message: Associated data.
  blake3_hasher_update(h, ad, ad_len);
  // Hash message: Text.
  blake3_hasher_update(h, text, text_len);
  // Hash message: Pad with zeros until message length is multitple of 64.
  blake3_hasher_update(h, zeros, align64(ad_len + text_len));
}

int baile_encrypt(
  uint8_t * ctext,
  uint8_t * tag,
  size_t tag_len,
  const uint8_t * ad,
  size_t ad_len,
  const uint8_t * text,
  size_t text_len,
  const uint8_t * key)
{
  if (!key) return -1;
  if (!(!tag_len || (tag && tag_len <= 64))) return -2;
  if (!(!ad_len || ad)) return -3;
  if (!(!text_len || (ctext && text))) return -4;
  // ad_len and text_len can't add up to more than 2^64-1.
  if ((uint64_t)ad_len + (uint64_t)text_len < (uint64_t)ad_len) return -5;

  blake3_hasher h;
  
  // tag[0..tag_len-1] = see baile_tag_input()
  if (tag_len) {
    baile_tag_input(&h, ad, ad_len, text, text_len, key);
    blake3_hasher_finalize(&h, tag, tag_len);
  }

  // stream[0..text_len] = BLAKE3(key, tag)
  blake3_hasher_init_keyed(&h, key); 
  blake3_hasher_update(&h, tag, tag_len);

  // ctext[0..text_len] = XOR(stream, ctext)
  blake3_hasher_finalize_xor(&h, ctext, text, text_len);

  memzero(&h, sizeof(h));
  return 0;
}

int baile_decrypt(
  uint8_t * text,
  const uint8_t * tag,
  size_t tag_len,
  const uint8_t * ad,
  size_t ad_len,
  const uint8_t * ctext,
  size_t text_len,
  const uint8_t * key)
{
  if (!key) return -1;
  if (!(!tag_len || (tag && tag_len <= 64))) return -2;
  if (!(!ad_len || ad)) return -3;
  if (!(!text_len || (ctext && text))) return -4;
  // ad_len and text_len can't add up to more than 2^64-1.
  if ((uint64_t)ad_len + (uint64_t)text_len < (uint64_t)ad_len) return -5;

  int ret = 0;
  uint8_t tmp[64];
  blake3_hasher h;

  // stream[0..text_len] = BLAKE3(key, tag)
  blake3_hasher_init_keyed(&h, key); 
  blake3_hasher_update(&h, tag, tag_len);

  // text[0..text_len] = XOR(stream, ctext)
  blake3_hasher_finalize_xor(&h, text, ctext, text_len);

  // tag[0..tag_len-1] = see baile_tag_input()
  if (tag_len) {
    baile_tag_input(&h, ad, ad_len, text, text_len, key);
    blake3_hasher_finalize(&h, tmp, tag_len);
  }

  if (memcmp(tmp, tag, tag_len)) ret = -6;  

  memzero(&h, sizeof(h));
  memzero(&tmp, sizeof(tmp));
  return ret;
}
