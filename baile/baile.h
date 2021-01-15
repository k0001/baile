#pragma once

// Copyright: Renzo Carbonara, 2021. 
//
// This work is released into the public domain with CC0 1.0. 
//
// Alternatively, it is licensed under the Apache License 2.0. 

#include <stddef.h>
#include <stdint.h>

#define BAILE_KEY_LEN 32
#define BAILE_TAG_MIN 0
#define BAILE_TAG_MAX 64

/* Baile encrypt. 
 *
 * Return codes:
 *
 * 0: OK.
 * -1: `key` is NULL.
 * -2: Incompatible `tag` and `tag_len`, or `tag_len` too long.
 * -3: Incompatible `ad` and `ad_len`.
 * -4: Incompatible `text`, `ctext` and `text_len`.
 * -5: `ad_len` and `text_len` too long.
 * -6: Message could not be authenticated. Unauthenticated `text` is available.
 */
int baile_encrypt(
  uint8_t * ctext,
  uint8_t * tag,
  size_t tag_len,
  const uint8_t * text,
  size_t text_len,
  const uint8_t * ad,
  size_t ad_len,
  const uint8_t * key);

/* Baile decrypt. 
 *
 * Return codes:
 *
 * 0: OK.
 * -1: `key` is NULL.
 * -2: Incompatible `tag` and `tag_len`, or `tag_len` too long. 
 * -3: Incompatible `ad` and `ad_len`.
 * -4: Incompatible `text`, `ctext` and `text_len`.
 * -5: `ad_len` and `text_len` too long.
 * -6: Message could not be authenticated. Unauthenticated `text` is available.
 */
int baile_decrypt(
  uint8_t * text,
  const uint8_t * tag,
  size_t tag_len,
  const uint8_t * ctext,
  size_t text_len,
  const uint8_t * ad,
  size_t ad_len,
  const uint8_t * key);

