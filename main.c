#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <blake3.h>
#include <baile.h>

/*****************************************************************************
 * Debugging tools ***********************************************************/

static int to_base16(uint8_t *base16, size_t base16_len, const uint8_t *bin) {
  if (base16_len & 1) return -1;

  size_t bin_len = base16_len / 2;
  unsigned int x;
  int b;
  int c;

  for (size_t i = 0; i < bin_len; i++) {
    c = bin[i] & 0xf;
    b = bin[i] >> 4;
    x = (uint8_t)(87U + c + (((c - 10U) >> 8) & ~38U)) << 8 |
        (uint8_t)(87U + b + (((b - 10U) >> 8) & ~38U));
    base16[i * 2U] = (uint8_t)x;
    base16[i * 2U + 1U] = (uint8_t)(x >> 8);
  }
  return 0;
}

static void debug_base16(char * prefix, const uint8_t *bin, size_t bin_len) {
  uint8_t * base16 = malloc(bin_len * 2);
  fprintf(stderr, "%s[%zd]: ", prefix, bin_len);
  if (!base16) {
    fprintf(stderr, "ERROR!\n"); // meh
    return;
  }
  to_base16(base16, bin_len * 2, bin);
  fwrite(base16, 1, bin_len * 2, stderr);
  fprintf(stderr, "\n");
  free(base16);
}

static void debug_str(char * str) {
  fprintf(stderr, "%s\n", str);
}


int main(int argc, char *argv[]) {
   int ret = 0;
   uint8_t tag[64];
   size_t tag_len;
   const size_t key_len = 32;
   uint8_t key[key_len];
   uint8_t * ad = 0;
   uint8_t * text = 0;
   uint8_t * ctext = 0;

   if (argc != 5) {
      fprintf(stderr, "Usage: %s SEED TAG-SIZE AD-SIZE TEXT-SIZE\n", argv[0]);
      ret = 1; goto out; 
   }

   const char * seed = argv[1];
   size_t seed_len = strlen(seed);

   if (!sscanf(argv[2], "%zu", &tag_len)) { ret = 2; goto out; }
   if (tag_len > 64) { ret = 3; goto out; }

   size_t ad_len;
   if (!sscanf(argv[3], "%zu", &ad_len)) { ret = 4; goto out; }
   ad = malloc(ad_len);
   if (!ad) { ret = 5; goto out; }

   size_t text_len;
   if (!sscanf(argv[4], "%zu", &text_len)) { ret = 6; goto out; }
   text = malloc(text_len);
   if (!text) { ret = 6; goto out; }

   blake3_hasher h;
   blake3_hasher_init(&h);
   blake3_hasher_update(&h, seed, seed_len);
   blake3_hasher_finalize_seek(&h, 0, key, key_len);
   blake3_hasher_finalize_seek(&h, key_len, ad, ad_len);
   blake3_hasher_finalize_seek(&h, key_len + ad_len, text, text_len);

   debug_base16("key", key, key_len);
   debug_base16("ad", ad, ad_len);
   debug_base16("text", text, text_len);

   if (ret = baile_encrypt(text, tag, tag_len, ad, ad_len, text, text_len, key)) {
     debug_str("baile_encrypt failed");
     ret = 7; goto out;
   }
   debug_str("baile_encrypt ok");
   debug_base16("tag", tag, tag_len);
   debug_base16("ctext", text, text_len);

   if (baile_decrypt(text, tag, tag_len, ad, ad_len, text, text_len, key)) {
     debug_str("baile_decrypt failed");
     ret = 8; goto out; 
   }
   debug_str("baile_decrypt ok");

out:
   if (ad) free(ad);
   if (text) free(text);
   return ret;
}


