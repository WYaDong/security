# **Security**

by yadong <br>
[MIT License]

## Security

Security is core. It provides AES encrypt, AES decrypt, Hash(MD5, HmacMD5, SHA1~SHA512) messages.

#### MD5:

```arkts
let md5 = Security.md5("md5")
```

#### AES Encrypt:

```arkts
let plainText = '1662100123'
let key = 'afae4ec844ed14ca'
let iv = '67e7d725dfe24ca1'
let result = await Security.aesEncrypt(plainText, key, iv)
```

#### AES256 Encrypt & Decrypt:

```arkts
let plainText = '1662100123'
let key = 'afae4ec844ed14ca'
let iv = '67e7d725dfe24ca1'
let result = await Security.aesEncrypt(plainText, key, iv)

// Decrypt
let dResult = await Security.aesDecrypt(result.data(), key, iv)

let d2Result: string = (await Security.aesDecryptWithHexString("323342D5B1B8558F002A75BE1EAEF305",
            "afae4ec844ed14ca", "67e7d725dfe24ca1")).utf8String()
```

## SecurityResult

SecurityResult is the result class of Security. It provides convert result data to Uint8Array, string, HEX string,
Base64 string.

```arkts
data(): Uint8Array 
utf8String(): string 
hex(): string 
hexLower(): string
base64(): string
```

## install

```arkts
ohpm install @yd/security
```


