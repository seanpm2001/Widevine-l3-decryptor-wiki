
This write-up describes the process that was done reversing [Widevine](https://en.wikipedia.org/wiki/Widevine)'s *old* Windows CDM (`widevinecdm.dll` 4.10.1610.0) to bypass its protection and extract its RSA private key. Knowing the private key could eventually lead to the decryption of media content keys for L3. 

Everything is for educational purposes only, and most of the techniques described here will <ins>**NOT**</ins> work against newer versions of the CDM anyway since it had gone through a major refactoring (obfuscation techniques & algorithms were changed). If all you care about is ripping videos, please look elsewhere.

Before talking about the private key extraction, we'll see why it's needed.

## Background
When websites want to play DRM-protected content, they will usually use the Encrypted Media Extensions (EME) API to choose a DRM system, set a service certificate for authentication/privacy, and use a license server to **obtain a license** for the specific media that will be played. It looks roughly like this in the case of Widevine:
```javascript
var keySystemAccess = await navigator.requestMediaKeySystemAccess("com.widevine.alpha", options);
var mediaKeys = await keySystemAccess.createMediaKeys();
mediaKeys.setServerCertificate(someCertificateBlob);
var mediaKeySession = mediaKeys.createSession("temporary");

// Now parse the MP4 and get the PSSH box that contains a key ID...
// then
mediaKeySession.generateRequest("cenc", psshBox);
mediaKeySession.addEventListener("message", function(message)
{
    if (message.messageType == "license-request")
    {
        // We got a license request, now send it to a license server...
        var licenseResponseBlob = send(new Uint8Array(message.message));
        // and update the CDM about its response
        mediaKeySession.update(licenseResponseBlob)
    }
});

```
Behind the scense Chrome will create a CDM instance from the CDM DLL and call its `CreateSessionAndGenerateRequest` and `UpdateSession` methods to generate and update the proprietary protobuf license requests and respones (the same blobs that the javascript code above sees). This is just part of the interface defined in [content_decryption_module.h](https://chromium.googlesource.com/chromium/cdm/+/bc262e26cd2dca812f05bdad3b37398839e63007/content_decryption_module.h#653).

Now, It is well-known that in such a DRM scheme the actual keys needed to decrypt the media are usually embedded in the license response, encrypted in some way or another.

## The license response and the device RSA keypair

So the first question to ask ourselfs when we want to get content keys, is of course where and how the content key(s) can be extracted from Widevine's license response. When dumping a licnese response we got from an EME session using [protbuf-inspector](https://github.com/mildsunrise/protobuf-inspector), we can see it looks roughly like this:
```
root:
    1 <varint> = 2  # Type
    2 <chunk> = message:    # Msg
        1 <chunk> = message:    # Id
            1 <chunk> = bytes (16)  # RequestId
                0000   49 C5 22 ...
            2 <chunk> = bytes (8)   # SessionId
                0000   19 54 ...
            4 <varint> = 1  (STREAMING) # Type
            5 <varint> = 0  # Version
        2 <chunk> = message:    # Policy
            1 <varint> = 1
            ...
        3 <chunk> = message:    # Keys
            1 <chunk> = bytes (16)  # Id
                0000   9A A8 F8 43 ...
            2 <chunk> = bytes (16):    # Iv
                0000   B1 D3 15 88 ...
            3 <chunk> = bytes (32)  # Key
                0000   8E 1B 1B AB ...
            4 <varint> = 2  # Type
            ...
        4 <varint> = 1585928174 # LicenseStartTime
        ...
    3 <chunk> = bytes (32)  # Signature (HMAC-SHA256)
        0000   B8 FA 8D ...
    4 <chunk> = bytes (256) # SessionKey
        0000   92 16 0C ...
```
You can see that it contains an array of keys, while each one contains a type (`CONTENT`/`SIGNING`), a KID, the key data itself (encrypted), and an IV used to decrypt the data.

Now from various documentaion files and code found online (and later, by debugging the code), we can see that to decrypt the content key, the CDM basically needs to:
1. Decrypt the `session_key`, using a **device private key** that correlates to a device public key that's sent out in the license request (in an encrypted form)
2. Calculate some buffer from the license request and compute CMAC on it to get an encryption key
3. Use this encryption key to decrypt each content key in the list of keys we got

We can verify that we got the above steps right by finding and isolating the function in `widevinecdm.dll` that's responsible for decrypting things using the device's private key and calling it from outside the DLL in C++. This will not be shown here, since it'll be pretty easy to understand once we'll talk about the decryption process.

So the only component that's missing is the device RSA key pair. Let's get it.

## Getting the device's public key
Before reversing the private key out of the CDM, it is a good idea to first extract its relevant public key and its public modulus `N`, which can help later in the analysis. The device public key is sent in the license request as part of the certificate chain that's inside the encrypted `encrypted_client_id`.

The license request looks like this:
```
root:
    1 <varint> = 1      # Type
    2 <chunk> = message:    # Msg
        2 <chunk> = message:    # ContentId
            1 <chunk> = message:    # CencId
                1 <chunk> = message:    # Pssh
                    1 <varint> = 1  # algorithm (AESCTR)
                    2 <chunk> = bytes (16) # key_id
                        0000   9A ...                          
                    3 <chunk> = "..."   # provider
                    4 <chunk> = bytes (20)  # content_id
                        0000   9A A8 ....             
                2 <varint> = 1 # LicenseType
                3 <chunk> = bytes (16)  # RequestId
                    0000   49 C5 22 0E ...                          
        3 <varint> = 1 # Type
        4 <varint> = 1585928174 # RequestTime
        6 <varint> = 21 # ProtocolVersion
        8 <chunk> = message:    # EncryptedClientId
            1 <chunk> = "spotify.com"   # ServiceId
            2 <chunk> = bytes (16)  # ServiceCertificateSerialNumber
                0000   4F 2D 27 ...                         
            3 <chunk> = bytes (3632)    # EncryptedClientId
                0000   72 9C 97 ....                                                
            4 <chunk> = bytes (16) # EncryptedClientIdIv
                0000   F1 75 24 CF ...                          
            5 <chunk> = bytes (256) # EncryptedPrivacyKey
                0000   79 06 E9 61 8....
    3 <chunk> = bytes (256) # Signature (RSA-SSA-PSS)
        0000   9E E....                        
```
The `encrypted_client_id` is AES-encrypted using a so-called privacy key which is encrypted itself (`encrypted_privacy_key`), together with an IV from `encrypted_client_id_iv`.

Luckily, the code that does this privacy encryption is not considered sensative at all, and it's not even obfuscated. In fact, it's easy to see it is done from the CDM's `crypto/encryptor.cc` source file, and we can extract the key by finding and hooking [OpenSSL's aes_init_key function](https://github.com/openssl/openssl/blob/d9c29baf1a23d2be17b9b4ab8f7b4fe43dd74454/crypto/evp/e_aes.c#L2301) (which is called from `EVP_CipherInit_ex`).

After decrypting the client indentification buffer we can just see the public key in the `device_certificate` encoded in ASN.1 DER:
```
root:
    1 <varint> = 1  # type (DEVICE_CERTIFICATE)
    2 <chunk> = message:    # token
        1 <chunk> = message:    # device_certificate
            1 <varint> = 2  # type (USER_DEVICE)
            2 <chunk> = bytes (17)  # serial_number
                0000   EA 2E 69 8D ...
            3 <varint> = 1557514008 # creation_time_seconds
            4 <chunk> = bytes (270) # public_key (PKCS#1 ASN.1 DER)
                0000   30 82 01 0A ...
            5 <varint> = 13701  # system_id
        2 <chunk> = bytes (256) # signature (RSASSA-PSS)
            0000   97 E6 1C 5F 44 70 ...
        3 <chunk> = message:    # signer
            1 <chunk> = message:    # device_certificate
                1 <varint> = 1  # type  (INTERMEDIATE)
                ...
            2 <chunk> = bytes (384) # signature (RSASSA-PSS)
                0000   5D 79 96 17 DB ...
    3 <chunk> = message:    # client_info (repeated)
        1 <chunk> = "architecture_name"
        2 <chunk> = "x86-64"

        ...
    ...
```

So let's put aside our RSA's modulus `N` out of the public key. This will help us later in the private key extraction.

## Hunting for the private key
Okay, having the device's public key in hand, it is time to start taking a deeper look into the CDM process to find an anchor point to the private key.
The private key is **never exposed plain in memory**, however, and the CDM process won't like attempts to debug it as well.

### Some Anti-Debugging tricks
When we'll try to attach a debugger during decryption (playback), we will immetiately encounter various anti-debugging tricks, usually resulting in the process crashed. 

Here's an example of the [int 2D trick](https://reverseengineering.stackexchange.com/questions/1541/int-2d-anti-forensic-method):
```
000007fe`d31a9f18 48890424             mov     qword ptr [rsp], rax
000007fe`d31a9f1c 488d4520             lea     rax, [rbp+20h]
000007fe`d31a9f20 cd2d                 int     2Dh
000007fe`d31a9f22 e9125bfeff           jmp     widevinecdm!VerifyCdmHost_0+0x436449 (000007fe`d318fa39)
```
At other times our debugger will stop at execption-related functions
```
(3158.1d3c): Invalid handle - code c0000008 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
ntdll!KiRaiseUserExceptionDispatcher+0x3a:
00000000`7782b5ba 8b8424c0000000  mov     eax,dword ptr [rsp+0C0h] 
``` 
or just crash later at non-executable addresses:
```
(4058.3430): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
000007ff`54afe670 ??              ???
```
Even when trying kernel debugging, the CDM process appears to not even start decrypting in this mode, to prevent such attempts.

However, we don't really need to fiddle with these tricks directly to bypass them, since there are a bunch of stealthier ways to fiddle with and debug the process. These include, among others, DLL injection of custom hooking code, DynamoRIO, Hypervisor-assisted-debugging, TTD, Frida, and probably more. 

It is worth noting, though, that for some DLL injection techniques to work, we may need to launch Chrome with a `--no-sandbox` flag, as the CDM process is sandbox and could fail mapping the DLL from disk (due to low privileges).

So from now on we'll simply assume the process can be debugged and jump to the more interesting stuff.

### Finding the RSA decryption function

Knowing that we want to discover the RSA key that's used to decrypt the `session_key`, the next question to ask is this: Where is this `session_key` getting decrypted, or alternatively, is there another place, perhaps easier to reverse one, where we can find it?

Well, the license request's `signature` field (in `SignedMesage`) is an RSA-SSA-PSS signature on the `msg` field using the *same private key* that's used to decrypt the `session_key` - the device key. 
```
root:
    1 <varint> = 1      # Type
    2 <chunk> = message:    # Msg
        ...
    3 <chunk> = bytes (256) # Signature (RSA-SSA-PSS)
        0000   9E E....                        
```
In the signing process we perform the same methematical operation as in the decryption process - raising to the power of `d` mod `N`. So it does not really matter which of these operations we choose to reverse.

But there is a good reason to prefer reversing the signing: we do see both the `msg` field and the `signature` field in memory (in the resulting license request). This means, in the signing, we *know* what the source and the result of the decryption process should be. That's in contrary to the situation when we deal with the decryption of `session_key`, in which case we don't know the expected output (so it could involve obfuscated post results).

So, to reverse the signing, we'll follow the memory accesses to the `signature`/`msg` buffers in memory and quickly land in the function that actually starts to process the `msg` buffer, in preparation for signing. 

Using [RSA-SSA-PSS](https://tools.ietf.org/html/rfc3447#section-8.1.1) (with SHA1 as a hash function) as a signing algorithm means that the padding operation that generates a number out of `msg` is called [EMSA-PSS-ENCODE](https://tools.ietf.org/html/rfc3447#section-9.1.1) in the RFC. This function essentially creates a suitable number for exponentiation using a series of computations. It starts by computing something like `MGF(sha1(zeroes || sha1(msg) || random))`, and eventually ends by concatenating `0xBC` to the result.

So we'll keep on following the data flow in code, passing through the SHA1 function a few times ([MGF1](https://en.wikipedia.org/wiki/Mask_generation_function#MGF1), etc.), until we reach a point where we have a buffer in memory that looks exactly like an expected result of applying `EMSA-PSS-ENCODE` to the `msg`:

```
00000000`0097c920  0f ... .... cc 5d bc  .4%.d.......Y.].
```
It's easy to tell that `EMSA-PSS-ENCODE` was completed beacuse the buffer ends with `0xBC`, the last component that needs to be concatenated by the RFC, as noted earlier.

At this point we have a 2048-bit number that was generated from the input buffer and is ready for exponentiation using the private key's secret exponent.

## Diving into the RSA implementation
It's time to dig in and reverse the actual whitebox RSA algorithm.

In case you're not familiar with modern implementations of RSA, what we're expecting to see here in the end is a modular exponentiation of our giant number using a [square-and-multiply algorithm](https://en.wikipedia.org/wiki/Exponentiation_by_squaring). This is not going to be an ordinary algortihm though, because a whitebox algorithm means we're expecting a twist (probably involving tables) which makes figuring out the key harder.

### Doing math with big numbers and the montgomery method
So again, at the point where we have passed through the `EMSA_PSS_ENCODE` step and we have the 2048-bit base number that is going to get raised to some power, we can again simply set an access breakpoint on the buffer where the number is stored to see what is getting done next.

The first operation that we encounter that uses the base buffer is inside a loop that's part of a function `R_mul_bignum_mont` that looks like this, after decompilation and cleaning:
```c
signed __int64 __fastcall R_mul_bignum_mont(_DWORD *ret, _DWORD *num_1, _DWORD *num_2, _RSA_INFO *info)
{
  ...

  for ( i = 0; i < info->size_of_bignum_in_dwords; ++i ) {

    // multiply the numbers
    prev = 0;
    for ( j = 0; j < info->size_of_bignum_in_dwords; ++j ) {
      mul_result = result[j] + prev + num_2[i] * num_1[j];
      result[j] = mul_result;
      prev = HIDWORD(mul_result);
    }
    
    v18 = prev + prev_thing;
    prev_thinga = prev + prev_thing;

    // add (product * N * R^-1) to the product
    multiplier = (unsigned int)info->montgomery_multiplication_factor * *result;
    ...
    for ( k = 1; k < info->size_of_bignum_in_dwords; ++k ) {
      mul_result = preva + result[k] + (info->modulus[k] * multiplier)
      result[k - 1] = mul_result;
      preva = HIDWORD(mul_result);
    }
    ...
  }

  // if (N < result_bignum)
  if (R_compare_bignums(info->modulus, result, info->size_of_bignum_in_dwords) <= 0 || ...) {
    
    // substruct N from the result
    v17 = 0;
    for ( l = 0; l <  info->size_of_bignum_in_dwords; ++l ) {
      v7 = result[l] - (unsigned int)info->modulus[l] - v17;
      ...
      v17 = -HIDWORD(v7);
    }
  }
  return some_size;
}
```
 After some guessing and experiments we can see that the purpose of the above function is to perform modular multiplication of big numbers using the [Montgomery method](https://en.wikipedia.org/wiki/Montgomery_modular_multiplication) - pretty common in RSA implementations. 
 
 If you never heard about montgomery multiplication, we're basically talking about a fast way to multiply a series of numbers with modulo applied. All computations are done in the so-called *Montgomery domain*, and in the end the result is converted back to the regular domain.
 
 The signature of the above function also doesn't look too different from [OpenSSL's BN_mod_mul_montgomery](https://github.com/openssl/openssl/blob/master/crypto/bn/bn_mont.c#L26), and the steps taken are similar:

1. Compute the regular product `num1 * num2`, dword-by-dword
3. Simultaneously divide the product by `R`, the montogomery coefficient, and reduce by `N`, dword-by-dword. This is done in part by multiplying with the [modular inverse](https://en.wikipedia.org/wiki/Modular_multiplicative_inverse) of `R`. Here `info->montgomery_multiplication_factor` is the same as [OpenSSL's mont->n0](https://github.com/openssl/openssl/blob/13a574d8bb2523181f8150de49bc041c9841f59d/crypto/bn/bn_local.h#L237).
4. Finally finish reducing the result by substrcting `N` if needed, resulting in a number below `N`

It's not important to fully understand the steps, we just need to know that this is a montgomery multiplication function, and we can easily reproduce it in another language. A good code example of doing math on numbers using this technique can be found [here](https://www.nayuki.io/page/montgomery-reduction-algorithm) (written in Python).
 
In addition, it's easy to discover in the binary other similar functions that perform more operations (add, substruct) on numbers in montgomery form. For example, here is the addition function:

```c
signed __int64 __fastcall R_add_bignum_mont(_DWORD *ret, _DWORD *num_1, _DWORD *num_2, _RSA_INFO *info)
{
  ...

  // do the actual addition
  for ( i = 0; i < info->size_of_bignum_in_dwords; ++i )
  {
    addition_result = prev + *(num_2 + i) + *(num_1 + i);
    ...
  }

  // substruct N if needed
  if (R_compare_bignums(ret, info->modulus, info->size_of_bignum_in_dwords) >=0 || ... )
  {
    ...
  }
  return result;
}
```

Now **all the math operations in the RSA modular exponentiation are going to use these two functions**, which is good for us.

### The RSA information structure

Note that both `R_mul_bignum_mont` and `R_add_bignum_mont` take as the last parameter (`info`) a struct which we'll call the **RSA struct** , since it's easy to see that it begins with these numbers:

```c
struct RSA_INFO
{
    uint32 size_of_bignum_in_dwords;

    byte montgomery_RR_mod_N[size_of_bignum_in_dwords * 4]; // used to convert to montgomery form
    byte modulus[size_of_bignum_in_dwords * 4];      // the public key's N
    byte montgomery_R[size_of_bignum_in_dwords * 4]; // the montgomery coefficient chosen
    byte modulusMinusTwo[size_of_bignum_in_dwords * 4];
    byte nulledNumber[size_of_bignum_in_dwords * 4];
    uint32 montgomery_multiplication_factor;       // used to multiply montgomery numbers, N` = ((R^-1 mod N)*R - 1) / N

    ...

    // more fields
}
```

At first look, the above information appears to show us that this struct just contains various pre-computed numbers derived from the modulus (N), but in fact it also contains other fields and pointers that will be important later for the private key.

Actually, when we look at the calls to both functions mentioned above (`R_mul_bignum_mont` and `R_add_bignum_mont`) and examine the contents and sources of `num_1` and `num_2` buffers, we can see that at least some values **also** come from the rest of the *RSA struct*. That's important since we want to understand what and where the input to this algorithm comes from.

As you can see, inside this big struct there are a lot big number that are occupying 256 bytes each. Let's define then
```c
struct bigNumber {
    byte data[size_of_bignum_in_dwords * 4]; // 256 bytes
};
```
And now, if we'll look at the offsets at which data is accessed in the struct at run-time, we could build the layout of the rest of the fields:

```c
struct RSA_INFO
{
    uint32 size_of_bignum_in_dwords;
    // ... more known fields (see above)

    byte _[0x119];
    byte padding1[3];

    // fields that appear to be used in the initialization of the algorithm
    bigNumber field1;
    byte __block1Related[60];
    bigNumber field3;
    byte _[144];

    // fields that appear to be used in more advanced stages
    uint32 coreIterationsCount;
    bigNumber field5;
    bigNumber field6;
    bigNumber montgomery_one;
    byte indexPerIteration[coreIterationsCount];

    // a field that appears to be used in the end of the algorithm
    byte unknown;
    byte padding2[2];
    bigNumber purposeDependentNumber;
    byte padding3[4]; 

    // pointers to additional, important, data blocks
    struct
    {
        Block1 *pointer1; // pointer to block 1
        byte __[0x90];
        Block2 *pointer2; // pointer to block 2
        void *emptyPointer;
        byte __block1Related2[460];
    } pointersStruct;
}
```
Not all fields are used or important to understand, but note that the struct contains two *pointers* to **two additional data blocks**. 

The first block is made up of 3 tables with each having 32 big numbers (2048-bit each):

```c
struct Block1
{
    Block1Table subBlock0; // polynomial sum multiplier
    Block1Table subBlock1; // a pre multiplier
    Block1Table subBlock2; // a post multiplier
};

struct Block1Table {
    bigNumber numbers[32];
};
```
And the second block is made up of 32 tables with each having 34 big numbers:
```c
struct Block2
{
    Block2Table tables[32]; // coefficient tables
};

struct Block2Table
{
    bigNumber x_powered_coefficient;
    bigNumber coefficients[33];
};
```
These two data blocks will be used and are important, especially the second block.

### Where do all of these numbers come from?

At this point, you may want to know where do the numbers and the data in that RSA info struct come from, and whether they were calculated dynamically (since they appear to be quite important). 

By tracing writes to the relevant buffer in memory, we discover the data is written to by what appears to be a deserializaiton function that just extracts it from a serialized buffer. Now, that serizlied buffer comes from what can be easily detected as [zlib's inflate() function](https://github.com/madler/zlib/blob/master/inflate.c#L622).

Finally, the compressed input to `inflate()` comes from... a harcoded buffer in the data section.

<img src="https://user-images.githubusercontent.com/11458759/112755060-b7df1580-8fe7-11eb-9dd8-46c3f8ae88ac.PNG" >

So we now know that the RSA struct is (mostly) static which stregths the assumption that this struct actually *correlates to the private key*.

We'll see how fields from the RSA info struct are used later, but first, we should have a better view on the context from which all of these `R_mul_bignum_mont` callls are made.

### Zooming out to the algorithm

Let's look at the calls to `R_mul_bignum_mont` and `R_add_bignum_mont` over time and at the context from which they are called. 

To do this, we'll build a log of calls to `R_mul_bignum_mont` and `R_add_bignum_mont`. The log contains 3,644 calls to `R_mul_bignum_mont` and some more adding (obviously there are many loops):

```
	mul(, m, info->montgomery_RR_mod_N, ) -> 58 cc 34 ... 
	mul(, info->field1, 58 cc 34 ..., ) -> 50 bd d7 ... 
	add(, 50 bd d7 ..., info->field3, ) -> 26 e3 3b ...
	mul(, info->field5, 26 e3 3b ..., ) -> e0 83 80 ...
	mul(, 50 bd d7 ..., 50 bd d7 ..., ) -> c6 24 a0 ...
	mul(, c6 24 a0 ..., c6 24 a0 ..., ) -> 35 18 74 ...
	mul(, e0 83 80 ..., e0 83 80 ..., ) -> a4 fe 9b ...
	mul(, a4 fe 9b ..., e0 83 80 ..., ) -> 8f 2d fb ...
	mul(, 8f 2d fb ..., e0 83 80 ..., ) -> 9b 6c 68 ...
	mul(, 9b 6c 68 ..., e0 83 80 ..., ) -> 35 fc a ...
	...
	mul(, 91 b3 ...,  e0 83 80 ..., ) -> b5 61 b7 ...
    ...
    
    ...
```

The first call to `R_mul_bignum_mont` is done from the function `R_BN_to_montgomery` which, unsurprisingly, really just converts our big number from regular form to montgomery form by multiplying it with `info->montgomery_RR_mod_N` (aka `R^2 (mod N)`), in a similar way to [how OpenSSL stores it](https://github.com/google/boringssl/blob/b117a3a0b7bd11fe6ebd503ec6b45d6b910b41a1/include/openssl/bn.h#L987):

<img src="https://user-images.githubusercontent.com/11458759/112755057-b7467f00-8fe7-11eb-9c00-71198f02d37a.PNG">

But starting from the second call to `R_mul_bignum_mont` we can see that this is done from a differnt function and context.

So far this is less or more what you'd expect to find if you were to look inside a standard RSA implementation. Unfortunately, this is where things get a little more complicated.

## Some code obfuscation
When we try to x-ref or go back to the point where some calls to `R_mul_bignum_mont` were made, we will usually see weird control flows similar to this:

<img src="https://user-images.githubusercontent.com/11458759/112755058-b7467f00-8fe7-11eb-98ca-c17b396468bf.PNG" >

When looking at the basic blocks above, what we immediately see is that our function was broken into many unrealted-looking basic blocks, with no apparent connections between them.

What's actually happening here is that:
1. Basic blocks are splitted randomly by inserting `jmp`s between them (like the third basic block in the above image). 
2. Many times conditional and unconditional jumps are taken **indirectly**, such as in the first block in the above image (`cmovnz`) and in the second block in the above image (`jmp     [rsp+var_8]`). 
3. There are some games with the stack pointer, `rsp`, which mess up some variables accesses a little bit. This obfuscation is, apparently, not annoying enough to be worth bypassing.

So basically as we said this technique results in splitting every function that has it applied into many blocks that appear unrealted and generally make understanding contexts pretty annoying.

To overcome this, it's possible to write an IDAPython script that patches the indirect jumps with direct jumps instead. Basically, the script starts by finding nodes without a successor, than disassambles the last instructions to figure out what case of control flow obfuscation it is, and act according to the case:

* A condition with two potential indirect jump targets (with a `cmovnz` like instruction) - like the first block in the imge above

    In this case the script would scan the previous lines to find the `loc_` and `sub_` targets, than assemble & patch a `jnz`/`jz`/`jg`/`jge`/etc instead.
* Indirect jump - like the second block in the image above
    
    In this case the script would scan the previous assembly lines, find the real jump target, and patch the line with a regular `jmp` instruction.
* Just a jump - like the third block in the image above
    
    In this case the script would just tell IDA to `MakeCode` the target address so that the node will have a successor.

After the sciprt reveals more and more nodes, it runs again and again until there are no longer nodes without a successor or we encouter a `ret` instruction.

## Algorithm Preparations

So, running the IDAPython script on the function where the second `R_mul_bignum_mont` call was made from (we can find its start address from the call stack) reveals the general function graph of what we call `R_do_rsa_preparations`:

<img src="https://user-images.githubusercontent.com/11458759/112755054-b6155200-8fe7-11eb-85b2-f9c6e24dcd83.PNG">

Now, what you're looking at is not the core yet (exponentiation by square-and-multiply), it's just some preparations. And the preparations obviously do all kinds of multiplications and additions to our number with other numbers. 

Looking at the log we generated earlier and at the flow graph, the whole function starts by doing this:

```
	mul(, m, info->montgomery_RR_mod_N, ) -> 58 cc 34 ... // convert input to montgomery form
	mul(, info->field1, 58 cc 34 ..., ) -> 50 bd d7 ... // computing x = number * field1

	// computing y = (x + field3) * field5
	add(, 50 bd d7 ..., info->field3, ) -> 26 e3 3b ...
	mul(, info->field5, 26 e3 3b ..., ) -> e0 83 80 ...

	// some squaring (x = x^4)
	mul(, 50 bd d7 ..., 50 bd d7 ..., ) -> c6 24 a0 ...
	mul(, c6 24 a0 ..., c6 24 a0 ..., ) -> 35 18 74 ...

	// precomputing powers table of y [for i=1 to 2^(window-1)]
	mul(, e0 83 80 ..., e0 83 80 ..., ) -> a4 fe 9b ...
	mul(, a4 fe 9b ..., e0 83 80 ..., ) -> 8f 2d fb ...
	mul(, 8f 2d fb ..., e0 83 80 ..., ) -> 9b 6c 68 ...
	mul(, 9b 6c 68 ..., e0 83 80 ..., ) -> 35 fc a ...
		... (total of 31 rounds)
	mul(, 91 b3 ...,  e0 83 80 ..., ) -> b5 61 b7 ...

    ...
```

 Take a moment to look at the above operations. It is first not clear why there is an addition in the beginning, but the 32-iterations loop in the end really does resemble to [the power table precomputation that OpenSSL does in its BN_mod_exp_mont_consttime function](https://github.com/openssl/openssl/blob/master/crypto/bn/bn_exp.c#L836).

To summarize the start of the algorithm so far:
1. Take the input number `m` and convert it to montgomery form
2. compute `x = m_mont * info->field1`
3. compute `y = (x + info->field3) * info->field5`
4. compute `x = x^4`
5. compute a power table of `y` which we'll call `power_table`, such that `power_table[i] == y^i`

Again, note that many times the RSA algorithm uses numbers from the *RSA info struct* (field1, field3, field5, ...). 

## Advanced algorithm preparations

OK, let's see what getting done next. Having an idea of how the layout of the RSA struct looks like
and looking at the continuation of the log, we can see that after the power-table computation loop in `R_do_rsa_preparations` that we saw earlier, there is some fiddling with **block 1** data:

```
    ...
    
	// calculating a sum multiplier from info->block1[0]
	mul(, info->block1[0][21],  info->block1[0][16], ) -> 77 85 3c ...
	mul(, 77 85 3c ..., info->block1[0][5], ) -> a8 ee 5d ...
	mul(, a8 ee 5d ..., info->block1[0][10], ) -> 03 11 61 ...
		... (total of 11 rounds)
	mul(, 8b 07 11 ..., info->block1[0][10], ) -> 08 ac ea ...

	// some more squaring (x^8) => x^32
	mul(,  35 18 74 ... {x^4} , 35 18 74 ... , ) -> af b4 69 ...
	mul(, af b4 69 ..., af b4 69 ..., ) -> bd 45 85 ...
	mul(, bd 45 85 ... bd 45 85 ..., ) -> d2 fa 9f ...

	// multiply the result of squaring using another loop on info->block1[1]
	mul(, d2 fa 9f ..., info->block1[1][32], ) -> 29 f6 06 ...
		... (total of 12 rounds)
	mul(, 7e b2 12 ..., info->block1[1][51], ) -> f6 a5 06 5d ... 

```
The order of which things happen here does not always matter, so we can reorder the above operations to:
1. raising the previously computed `x^4` to the power of 8 (so we get `x^32`)
2. multiplying that `x^32` by 12 different numbers from the _second_ table of block 1 (what we called a pre-multiplier).
3. multiplying another 12 numbers in the _first_ table of block 1 into one number, which we'll call `polynomial_sum_multiplier`.

Hmm, okay. 

Since `x` directly comes from the base number, what was done up untill now to our input is basically raising a variation of it to the power of 32 and then multlying it with a series of numbers (the algorithm that chooses which numbers to use from the table of block 1 was reversed too, but it is not important).

### Calculating some polynomials

Next up, the `R_do_rsa_preparations` function starts another 32-iteration loop that calculates a **sum** from **each table in block 2** and stores the results in an array we'll call `sums_table`. Every such sum can be seen as a result of calculating the value of a 32-order polynomial with specific coefficients, as we'll see. 

A single sum is calculated by calling an inner function `R_rsa_inner_block_2_sum`, and the function is called on each table in *block 2*. Recall that *block 2* has 32 tables, where each table contains 34 big-numbers [`x_powered_coefficient` + 33 coefficients]. 

Note that the inner function takes as parameters not only the current block 2 table, but also the `powers_table`, and the `polynomial_sum_multiplier`, which we calulcated earlier (but did not use until now).

The function is obviously obfuscated too, so we'll run the script, decompile (surprise, it works) and we'll get this (simplified and fixed):

```c
int __stdcall R_rsa_inner_block_2_sum(void *sum_result, bignum *block2TableCoeffs, bignum *powers_table, void *polynomial_sum_multiplier)
{
  ...

  R_mul_bignum_mont(&prev_sum, block2TableCoeffs[0], powers_table[0], rsa_struct);
  
  ...
  for ( i = 1; i < 32;  i+=2)
  {
    R_mul_bignum_mont(&mul_result, block2TableCoeffs[i], powers_table[i], rsa_struct);
    R_add_bignum_mont(&sum_result, prev_sum, mul_result, rsa_struct);

    R_mul_bignum_mont(&mul_result, block2TableCoeffs[i + 1], powers_table[i + 1], rsa_struct);
    R_add_bignum_mont(&prev_sum, sum_result, mul_result, rsa_struct);
   ...
  }

  R_mul_bignum_mont(&sum_result, prev_sum, polynomial_sum_multiplier, rsa_struct);
  
}
```
As can be seen above, this function basically multiplies each of the 33 coefficients in the given **block 2 table** by their corrosponding numbers in the `power_table`, sums it all up, and eventaully multiplies the sum by the `polynomial_sum_multiplier`, which as we saw comes from the first table of **block 1**. 

After calculating the sum, `R_do_rsa_preparations` completes it by adding our `x^32` multiplied by `block2Table.x_powered_coefficient` to the sum, as seen in the log:
```
// sums_table[i] = subblock_sum + (x_powerd_result * info->block2[i].x_powered_coefficient)

mul(, f6 a5 06 ... {x_powerd_result}, info->block2[i].x_powered_coefficient, ) -> c7 80 f5 ...
add(, c7 80 f5 ..., fb a0 72, ...) -> c2 21 68 ...
```
As we said, we'll call the table generated from this loop `sums_table`. Again note how this process is similar to calculating a series of 32-order polynomials.

OK.

### Finishing the preparations
After doing the above preparations, `R_do_rsa_preparations` ends and we return to to the father `R_do_rsa_decrypt` function, which, after de-obfuscation, immidiately calls a function we'll call `R_rsa_core`:

<img src="https://user-images.githubusercontent.com/11458759/112755059-b7df1580-8fe7-11eb-8b10-9cb7f5198a73.PNG">

## The RSA Core - Square and Multiply

And now, after the preparations, to the part where the real exponentiation actually happens. `R_rsa_core` is given the array of the 32 sums (or polynomials) that we just computed (`sums_table`).

The functions itself is pretty simple (again, after de-obfuscation): It's just a `info->coreIterationsCount` iterations loop that multiplies a number 6 times in every iteration:

<img src="https://user-images.githubusercontent.com/11458759/112755056-b6ade880-8fe7-11eb-9d68-ee9f99ba87c1.PNG">

And given the log, it's easy to see that while most of the multiplications are multiplications by the same number (squares), the last one is not:

```
	// *** actual exponentiation ***
	mul(, 7d c2 c6 {sums_table[info->indexesByIteration[0]]}..., 7d c2 c6 ..., ) -> 5a be 1b ...
	mul(, 5a be 1b ..., 5a be 1b ..., ) -> 50 9d d5 ...
	mul(, 50 9d d5 ..., 50 9d d5 ..., ) -> 59 1a 08 ...
	mul(, 59 1a 08 ..., 59 1a 08 ...) -> f4 3d 88 ...
	mul(, f4 3d 88 ..., f4 3d 88 ..., ) ->  e2 e3 37 ...
	mul(, e2 e3 37 ..., 21 cc 93 ... {sums_table[info->indexesByIteration[i]}, ) -> d0 64 2d ...

	mul(, d0 64 2d ..., d0 64 2d ..., )
	...
	mul(, ef 65 e5 ..., da 6b f0 ..., ) -> 97 36 a3 ...

```

Now `info->coreIterationsCount` has the value 409, which makes perfect sense because, since we're doing 5 squares per iteration (plus one multiplication) and we have a 2048-bit wide number, we'll need approximately `2048 / 5 = 409` iterations.

If this doesn't already look familiar to you at this point, take a look at [this presentation](http://2011.indocrypt.org/slides/verneuil.pdf). What's happening here, is a left-to-right (most significant bits first) square-and-always-multiply algorithm.

<img src="https://user-images.githubusercontent.com/11458759/112755061-b877ac00-8fe7-11eb-9490-9295b8c3f859.PNG">

Except here, in a way very similar way to [OpenSSL's algorithm](https://github.com/openssl/openssl/blob/master/crypto/bn/bn_exp.c#L865), we're using the [2k-ary](https://en.wikipedia.org/wiki/Exponentiation_by_squaring#2k-ary_method) method with a window size of 5 (aka we're not raising to the power of 2 but to the power of 32). 

And this is exactly the point where we recall [OpenSSL's square-and-always-multiply exponentiation in BN_mod_exp_mont_consttime()](https://github.com/openssl/openssl/blob/master/crypto/bn/bn_exp.c#L865). The OpenSSL function does the same: It performs a square-and-always-multiply algorithm by precomputing a power table and then using this power table to do a **409** iterations loop, in which it squares a number 5 times and multiplies once!

But it's not the same algorithm. It's different. 

It's different because it's not starting to square out `m_mont` (our input), and it doesn't use the plain power table of `m_mont`, but rather, it multiplies the result by the weird `sums_table[info->indexesByIteration[i]]` - which mixes in our `m_mont`, some other tables, and the power table of `y` all together. This is the whitebox.

## Finishing up the algorithm

After exiting `R_rsa_core`, there is a call to `R_other_rsa_operation`, which does this:

```
	// R_other_rsa_operation
	mul(, info->block1[2][17], info->purposeDependentNumber, ) -> 34 e4 94 ...
	mul(, 34 e4 94 ..., info->block1[2][10], ) -> 03 80 2f ...
	mul(, 03 80 2f ..., info->block1[2][16], ) -> c1 ac f4 ...
	mul(, c1 ac f4 ..., info->block1[2][20], ) -> e3 1a 78 ...
	...
	(12 iterations)
	R_other_rsa_operation returns -> 18 5e 00 4a ...

  ...
```
It multiplies 12 numbers (again) from the **third table of block 1** (which is the last table that wasn't used yet) with `info->purposeDependentNumber` and returns the result. This will in fact be the post-multiplier.

Finally, as can be seen in the last decompiler screenshot, there are two final multiplications perfomed in the end: One to multiply the result with the post-multiplier that `R_other_rsa_operation` just computed, and the second to convert the result back from montgomery form to regular form:

```
  mul(, 97 36 a3 ..., 18 5e 00 ...) -> 55 d3 1a // multiply with the computed post multiplier
  mul(, 55 d3 1a ..., __montegmery_R, ) -> 9d e9 fc 71 ...	// convert out of montogmery form
  ```
And that's it. The algorithm has now returned us the result of `m` raised to the power of the super secret exponent `d` `(mod n)`.

## Reconstruction
The next thing we'll want to do is of course to make our version of the algirthm in a high level language (such as python) so we can be independent of the DLL and investigate it more easily.

First, we'll dump relevant parts of the *RSA struct* into files and read them:
```python
modulus             = number.bytes_to_long(open("modulus.bin", "rb").read())

# block 1 tables (squashed down)
pre_multiplier      = number.bytes_to_long(open("pre_multiplier.bin", "rb").read())
sum_multiplier      = number.bytes_to_long(open("sum_multiplier.bin", "rb").read())
post_multiplier     = number.bytes_to_long(open("post_multiplier.bin", "rb").read())

field_1              = number.bytes_to_long(open("field_1.bin", "rb").read())
field_3              = number.bytes_to_long(open("field_3.bin", "rb").read())
field_5              = number.bytes_to_long(open("field_5.bin", "rb").read())

coefficients_tables = to_bignumber_list(open("struct_block_2.bin", "rb").read())
indexes_map         = open("indexes_map.bin", "rb").read()
```
Note that all the 3 tables of **block 1** were squashed down into one number each, which is just the result of multiplying the 12 numbers chosen by each other.

We'll continue by mimicing the first part of the preparations, which is muliplying our `m_mont` by `field1` to make `x`, raising the result to the power of 4 and then 8 (=32), muliplying the result again by the pre-multiplier, and also making out `y` (here called `base`) using `field3` and `field5` :

```python
# convert to mongomery form
mont_reducer = MontgomeryReducer(modulus)
input_mont = mont_reducer.convert_in(input_number)

# compute x and base
x = mont_reducer.multiply(input_mont, field_1)
x_powered = mont_reducer.multiply(mont_reducer.pow(x, 32), pre_multiplier)
base = x + field_3; base = base % modulus; 
base = mont_reducer.multiply(base, field_5)
```

Looks simple so far, right? The original algorithm also calculates the power table of `base` and generates the `sums_table` in the second part of the preparations. We don't really need to precompute a table of powers, we can just do everything inline:
```python
def generate_sums_table(modulus, coefficients_tables, base, x_powered, polynomial_multiplier):
    mont_reducer = MontgomeryReducer(modulus)

    sums_table = [0] * 32
    for i in range(len(sums_table)):
        coefficients = coefficients_tables[i*34 : (i+1)*34]
        x_powered_coeffient, coefficients = coefficients[0], coefficients[1:33]
        
        sums_table[i] = generate_sum(modulus, base, coefficients, polynomial_multiplier)

        sums_table[i] += mont_reducer.multiply(x_powered, x_powered_coeffient)
        sums_table[i] = sums_table[i] % modulus

    return sums_tablek

# R_rsa_inner_block_2_sum
def generate_sum(modulus, base, coefficients, polynomial_multiplier):
    mont_reducer = MontgomeryReducer(modulus)

    summ = 0
    for j, coefficient in enumerate(coefficients):
        summ += mont_reducer.multiply(coefficient, mont_reducer.pow(base, j))
        summ = result % modulus

    summ = mont_reducer.multiply(result, polynomial_multiplier)

    return summ
```

And, the RSA core can be translated to this in python (we can replace the 5 squares with raising to the power of 32):
```python
def do_rsa_core(modulus, sums_table, indexes_table):
    prod = sums_table[indexes_table[0]]

    mont_reducer = MontgomeryReducer(modulus)
    iterations_count = len(indexes_table)

    for i in range(1, len(indexes_table)):

        # raise to the power of 32
        # "Shift |r| to the end of the window"
        prod = mont_reducer.pow(prod, 32)

        # multiply by the secret multiplier
        prod = mont_reducer.multiply(prod, sums_table[indexes_table[i]])

    return prod
```

Finally, just call these functions in the continuation of the main function and convert back from montgomery form to regular form:
```python
...

sums_table = generate_sums_table(modulus, coefficients_tables, base, sum_multiplier, x_powered)
powered = do_rsa_core(modulus, sums_table, indexes_table, post_multiplier)

# multiply by the post multiplier
powered = mont_reducer.multiply(powered, post_multiplier)
    
# convert to regular form
result = mont_reducer.convert_out(powered)
```
And sure enough, running this algorithm and the original one from the DLL for the same inputs yields the same results.

## Breaking the whitebox - simplify, simplify, simplify
Up until now, we extracted the whitebox RSA algorithm from the DLL into python, so we can decrypt and sign arbitrary payloads as we wish. This is probably sufficient for getting content keys 100% in python, but extracting the original exponent from the whitebox algorithm is even cooler.

To do this, we'll try to simplify the algorithm and get rid of as many redundant tables and numbers as possible, in the hope that with this strategy we could eventually get rid of the weird `sums_table`.

### 1. Getting rid of `polynomial_sum_multiplier`
First, looking at the last multiplication  in `generate_sum`, it's obvious we can use the Distributive property to move it into the loop, and get rid of `polynomial_sum_multiplier` completely by creating a new `coefficients` table in which every number is multiplied  by `polynomial_sum_multiplier` (instead of multiplying at run-time). 

Now `generate_sum` is simplified to:
```python
# R_rsa_inner_block_2_sum
def generate_sum(modulus, base, coefficients, polynomial_multiplier):
    mont_reducer = MontgomeryReducer(modulus)

    result = 0
    for j, coefficient in enumerate(coefficients):
        result += mont_reducer.multiply(coefficient, mont_reducer.pow(base, j))
        result = result % modulus

    return result
```
### 2. Getting rid of `pre_multiplier`
Second, it's important to see that every iteration of `generate_sums_table` essentially **calculates a 32-order polynom** like this:
```
sum = x_powered * x_powered_coeffient + (coefficients[0] * base^ 0) +
                                        (coefficients[1] * base^ 1) +
                                        (coefficients[2] * base^ 2) + ... (mod N)
```
which is equal to
```
sum = (x^32 * pre_multiplier) * x_powered_coeffient + (coefficients[0] * base^ 0) +
                                                      (coefficients[1] * base^ 1) +
                                                      (coefficients[2] * base^ 2) + ... (mod N)
```
But we can see it as
```
sum = x^32 * (pre_multiplier * x_powered_coeffient) + (coefficients[0] * base^ 0) +
                                                      (coefficients[1] * base^ 1) +
                                                      (coefficients[2] * base^ 2) + ... (mod N)
```

So since this is the only use of `pre_multiplier`, we can get rid of it by altering the `coefficients` table again so that each `x_powered_coeffient` will be `x_powered_coeffient * pre_multiplier`.

And now the line `x_powered = mont_reducer.multiply(mont_reducer.pow(x, 32), pre_multiplier)` simply becomes `x_powered = mont_reducer.pow(x, 32)`

### 3. Getting rid of `field1`
Let's see how we can get rid of `field1`. We know that `x = m * field1`, and when `x` is used, it is used in the sum calculation
```
sum = x^32 * x_powered_coeffient + ...
```
which is therefore just
```
sum = (m * field1)^32 * x_powered_coeffient +    ...   (mod N) = 
sum = m^32 * (field1^32 * x_powered_coeffient) + ...   (mod N)
```
So we can  generate a new `coefficients` table in which every `x_powered_coeffient` is multiplied by `field1^32` (in a similar way to how we removed `pre_multiplier`).

But we're not done yet. Because `x` is not only used in this formula, it also composes `base`. But take a look at this:
```
base = (x + field3) * field5                    (x = m * field1)
base = (m * field1 + field3) * field5           
base = (m + field3/field1) * field5 * field1
```

As you can see, `field5 * field1` fits in to be the new `field5`, and `field3/field1` fits in to be the new `field3`, no `field1` needed.

So we'll replace `field5` and `field3` with new values and we can remove `field1`.

The line  `x = mont_reducer.multiply(input_mont, field_1)` is gone. Also now `x = m`.

### 4. Getting rid of `field5`
Recall that `base` is a multiplication of `field5`, because `base = (m + field3) * field5`.  Now if we substitute `base` with `base2 * field5` in the sum formula, we'll get:
```
sum = m^32 * x_powered_coeffient + (coefficients[0] * (base2 * field5)^0) + 
                                   (coefficients[1] * (base2 * field5)^1) + 
                                   (coefficients[2] * (base2 * field5)^2) + ... (mod N)
```
And after opening up some parenthesis it's actually:
```
sum = m^32 * x_powered_coeffient + ((coefficients[0] * field5^0) * base2^0) +
                                   ((coefficients[1] * field5^1) * base2^1) +
                                   ((coefficients[2] * field5^2) * base2^2) + ... (mod N)
```
As you can see above, we can again generate new `coefficients` tables in which every coefficient is multiplied by the corrosponding constant `field5 ^ j`.

So now also the line `base = mont_reducer.multiply(base, field_5)` is gone.

### 5. Getting rid of `post_multiplier`

Since `post_multiplier` is used after the core RSA operation, to get rid of it we'll use a different mathematical technique that is based on the technique used in [RSA Blinding](https://en.wikipedia.org/wiki/Blind_signature#Blind_RSA_signatures).

RSA Blinding is also common to see in RSA implementaions. It's used to protect against timing attacks and other side-channel problems, and it works by introducing a blinding factor `r^e` that's multiplied with the message `m` prior to exponentiation. After the decryption this blinding factor is removed by mulyiplying the result by `r^-1`.

In our case we can say that `post_multiplier = r^-1`, and so what's happening in our algorithm can be shown as raising a blinded number `m'` to the power of `d`, instead of raising `m`:
```
m' = m * r^e                    (mod N)
post_multiplier = r^-1          (mod N)

output = m ^ d                  (mod N) =
output = m'^d * post_multiplier (mod N)
```
(You can check that it works by opnening up `m'` in the last formula)

Now, what we can do to eliminate `post_multiplier` is to drop the multipication with it in the end, and as a compensation intoduce a new pre-multiplier `s` before the exponentiation - which is easier for us to get rid of (we'll later see how). 

We just need to require that the results of both methods will be equal:
```
decrypted = (s * m') ^ d  = m'^d * post_multiplier      (mod N) =
            s^d * m'^d    = m'^d * post_multiplier      (mod N) =
            s^d           = post_multiplier             (mod N) =
            s             = log_d(post_multiplier)      (mod N)
```
OK, so this brings us to the question: What is the `log_d` of `post_mulitplier`? Or in other words, what number `s` will result in `post_multiplier` when raised to the power of `d`? Well, the basic property of RSA says that for any `m'`:
```
m'^ed = m' (mod N)
```
Therefore
```
post_multiplier ^ ed      = post_multiplier    (mod N) =
(post_multiplier ^ e) ^ d = post_multiplier    (mod N)
```
which means, the pre-multiplier `s` we're looking for is simply `post_multiplier ^ e`, where `e` is the public key's expoent - 65537 (!).

We can now get rid of the `prod = mont_reducer.multiply(prod, post_multiplier)` line.

But there's still one problem we created: the new `s` pre-multiplier. Luckily, it's simple for us to kick it out too because it's esentially our new `field1` (it's the multiplication done to `m`)! So we'll just repeat steps 3 & 4 and we should be good.

### 6. Getting rid of `field3` and `coefficients`
OK, now that we removed some redundant numbers from our algorithm we're left with 3 components that are supposed to make up the exponent somehow: `field3`, `coefficients`, and `indexes_table`.

It's time for the trick that made the biggest difference. 

First, instead of looking at our polynom as
```
sum = m^32 * x_powered_coeffient + (coefficients[0] * base^0) +
                                   (coefficients[1] * base^1) +
                                   (coefficients[2] * base^2) + ... (mod N)
```
we'll see it as
```
sum = 
m^32 * x_powered_coeffient + (coefficients[0] * (m + field3)^0) +
                             (coefficients[1] * (m + field3)^1) +
                             (coefficients[2] * (m + field3)^2) + ... (mod N)                        
```
In which our new polynom's variable is `m`, the real base number, not the `base` variant - this is important. 

Now, we'll **further expand** the above expression (which includes expanding expressions as long as `(m + field3)^31` ). Notice that in the end we will eventually get a modular polynom of the form
```
sum = a1*m^1 + a2*m^2 + .. + (a32 + x_powered_coefficient)*m^32 + a0   (mod N)
```
In this new expression, our new `coefficients` will be `a0`, `a1`, `a2`, `a3`, and so on. 

So to open up this monster, we'll take some time to write a class in python `PolynomialMod` which can represent and do math with modular polynoms (with a symbolic variable `x`). It looks like this:
```python
import collections
import itertools

poly_N = 0  # our polynom modulus

class PolynomialMod(object):
    def __init__(self, *args):
        """
        p = PolynomialMod([1,2,3 ...])    # from sequence
        p = PolynomialMod(1, 2, 3 ...)    # from scalars
        """
        ...

    def __add__(self, val):
        ...

    def __sub__(self, val):
        "Return self-val"
        ...

    def __sub__(self, val):
        "Return self-val"
        ...

    def __call__(self, val):
        "Evaluate at X==val"
        ...

    def __mul__(self, val):
        "Return self*val"
        ...

    def __pow__(self, y, z=None):
        ...

    def __str__(self):
        "Return string formatted as aX^3 + bX^2 + c^X + d"
        ...
```
(It's probably also possible to do with [numpy](https://medium.com/asecuritysite-when-bob-met-alice/polynomials-mod-p-and-numpy-db461d0cd35c))

Next, we'll create all the `PolynomialMod` instances with their right coefficients in their place. e.g:
```python
base_polynom = PolynomialMod([field_3, 1])          # m + field3
...
lines[i] = coefficients[i] * (base_polynom**i)      # coefficients[i] * (m + field3)^i
...
final_polynom = sum(lines)
```
and after we sum up all the powers... surprise! 

When checking the values of the coefficients in the resulting polynom, all of them has the value **zero** except two - `coefficients[32]` and `coefficients[j]` (where `j` changes per the block 2 table we check).

```python
>>> print final_polynom.coeffs
[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, ..., 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, ...]
```

The reason why we got `coefficients[32]` non-empty is simple - it is the complementary coefficient to `x_powered_coeffient`. When we compute `coefficients[32] + x_powered_coeffient`,  we always get zero.

So now we can once again change the `coefficients` table in each block 2 table to be mostly zeros. Also, we got rid of `x_powered_coeffient`, and the line `sums_table[i] += mont_reducer.multiply(x_powered, x_powered_coeffient)` is gone. 

And as a bonus, `field3` was mixed in to the constant term in the formula - `coefficients[0]`, which is zero too! Say goodbye to the line `base = x + field_3; base = base % modulus;`

### Concluding the exponent - the final trick
At this point, every `sum` in the `sums_table` is no longer a sum (almost all added numbers are zero), but rather a result of our number `m` raised to some power `j` (multiplied by some coefficinet). So we'll now call that table `powers_table` instead:
```
powers_table[i] = coefficients[j] * m^j
```
Let's recall the exponentiation process. Our python script can take a number `m` and raise it to the power of `d` based on the following algorithm:
```python
def do_rsa_core(modulus, powers_table, indexes_table):
    prod = powers_table[indexes_table[0]]

    mont_reducer = MontgomeryReducer(modulus)
    iterations_count = len(indexes_table)

    for i in range(1, len(indexes_table)):
        # raise to the power of 32
        prod = mont_reducer.pow(prod, 32)

        # multiply by the secret multiplier
        multiplier = powers_table[indexes_table[i]]
        prod = mont_reducer.multiply(prod, multiplier)

    return prod
```
Taking into account the new optimization we made, now the above code means that in every iteration we raise the result to the power of 32, and then multiply it with **another power** of `m` (ignoring the coefficient for a moment).

Just look at the last multiplication in the above python code in comparasion with [OpenSSL's last multipication](https://github.com/openssl/openssl/blob/master/crypto/bn/bn_exp.c#L885). OpenSSL's `powerbuf` is like our `powers_table`, except that our `powers_table` scrambles the powers a bit.

The thing is, every iteration, and specifically **every multiplication, correlates to exactly 5 bits of the secret exponent**.

Now remember that every index in the 409-sized `indexes_table` tells us which number we should take from the `powers_table` in the next iteration. And we know to match numbers in `powers_table` to their correct powers of `m`. 

This means that - for example, if we conclude that the first iteration multiplies the result by, say, `c * m^27`, it means that the first bits of the exponent are `11011` (and so on).

By coverting each of the 409 indexes in `indexes_table` to the correct 5-bit power of `m` and concatenating all the entries, we'll get the exponent in binary. That's it.