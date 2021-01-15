# Baile

A fast nonce-misuse resistant AEAD construction on top of BLAKE3.

**WARNING** This is an experiment. Don't use this.


## Encryption

-  Inputs:
    - Key: 32 bytes secret key.
    - Length(Tag): Desired authentication tag length (maximum 64 bytes).
    - Ad: Associated data to authenticate.
    - Text: Arbitrary length text to encrypt and authenticate.
  
    Note: Length(Ad) + Length(Text) must 2^64-1 at most.
  
-  Algorithm:

   ```
   Tag <- BLAKE3(msg: Ad ++ Text ++ PadWithZerosUntilMsgLengthIsMultipleOf64,
                 key: XOR(LittleEndian32Bytes(Key),
                          LittleEndian32Bytes(1),
                          ShiftRightBy8(LittleEndian32Bytes(Length(Ad))),
                          ShiftRightBy16(LittleEndian32Bytes(Length(Text)))))
   CipherText <- XOR(Text, BLAKE3(msg: Tag, key: Key))
   ```
  
-  Outputs:
    - Tag: Authentication tag of the requested Length(Tag).
    - CipherText: Encrypted version of Text.



## Decryption

- Inputs:
    - Key: Same key used during encryption.
    - Tag: Authentication tag obtained during encryption.
    - Ad: Same associated data used during encryption.
    - CipherText: Encrypted text.
  
- Algorithm:
  ```
  Text <- XOR(CipherText, BLAKE3(msg: Tag, key: Key))
  Tag2 <- BLAKE3(msg: Ad ++ Text ++ PadWithZerosUntilMsgLengthIsMultipleOf64,
                 key: XOR(LittleEndian32Bytes(Key),
                          LittleEndian32Bytes(1),
                          ShiftRightBy8(LittleEndian32Bytes(Length(Ad))),
                          ShiftRightBy16(LittleEndian32Bytes(Length(Text)))))
  ```
  
- Outputs:
    - Success: Whether the calculated Tag2 is equal to the expected Tag.
    - Text: Decrypted CipherText.



## Security

- Security level is 128 bits, same as BLAKE3.

- Key length is 32 bytes, same as BLAKE3.

- Recommended Tag length is 32 bytes, the same as BLAKE3's default hash output 
  length.

- The Tag is deterministically obtained from the Key, the Ad and the Text.

- The Tag and Key are used to generate the secret encryption stream for
  encrypting and decrypting Text, and to verify Ad and Text integrity 
  after decryption.

- Each Key and Tag combination produce a different BLAKE3 secret encryption
  stream. There are potentially up to 2^64 different encryption streams per 
  Key, limited by the chosen Tag length.

- Having access to two CipherTexts produced by the same Key and Tag
  reveals as many bytes of the secret encryption stream as the shortest of the 
  two CipherTexts. This secret encryption stream chunk can be used to decrypt 
  as many bytes of other CipherTexts produced by the same Key and 
  Tag combination.

- Knowing the secret encryption stream produced by one particular Key and Tag
  combination, without previous knowledge of said Key, but having knowledge 
  of the Tag, does not reveal the Key. If only the stream is known, then 
  neither the Tag nor the Key can be determined from it.

- The Tag length can be adjusted up or down according to the expected number 
  of collisions from hashing Ad and Text together with BLAKE3. It is often 
  safe to decrease the Tag length if necessary, particularly when the Ad 
  length and Text length add up to less than 32 bytes. The maximum Tag length 
  is 64.  Minimum is 0. Don't use a short Tag unless you really know what you 
  are doing. Certainly don't use one of length 0. 



## Performance

- The total number of BLAKE3 compressions necessary to encrypt or 
  decrypt grows lineary with the length of the Ad and the Text, and can
  be determined with this formula:

  ```
  1 + Ceiling((Length(Ad) + Length(Text)) / 64)
  ```

- Notably, Ads and Texts whose lengths add up to 64 bytes at most require 
  only two BLAKE3 compressions in total.

## Legal

Copyright: Renzo Carbonara, 2021. 

This work is released into the public domain with CC0 1.0. 

Alternatively, it is licensed under the Apache License 2.0. 
