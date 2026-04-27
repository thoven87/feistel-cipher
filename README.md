# FeistelCipher

A lightweight, pure Swift library for obfuscating numeric IDs using a **Feistel network cipher**, with human-friendly output via **Crockford Base32** encoding.

Turn a plain sequential ID like `1` into a safe, shareable token like `99G7-GB6Q-CKZB-H0` — and back again.

---

## Why?

Sequential numeric IDs expose internal data about your system — how many users you have, how many orders were placed, etc. Feistel cipher obfuscation lets you:

- **Hide enumeration**: `1, 2, 3` becomes unpredictable tokens
- **Stay reversible**: No database lookups needed — any ID can be decrypted deterministically
- **Be human-friendly**: Encoded strings are short, readable, and typo-resistant
- **Stay lightweight**: No dependencies, no key storage, pure Swift

---

## Platform Support

FeistelCipher is written in pure Swift with no platform-specific APIs. It runs anywhere Swift runs:

| Platform | Supported |
|----------|-----------|
| macOS    | [x]       |
| iOS      | [x]       |
| Linux    | [x]       |
| Android  | [x] (via Swift on Android) |
| Windows  | [x] (via Swift on Windows) |
| tvOS     | [x]       |
| watchOS  | [x]       |
| visionOS | [x]       |

---

## Installation

### Swift Package Manager

Add the package to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/thoven87/feistel-cipher.git", from: "1.0.0")
]
```

Then add `"FeistelCipher"` to your target's dependencies:

```swift
.target(
    name: "YourTarget",
    dependencies: ["FeistelCipher"]
)
```

---

## Quick Start

```swift
import FeistelCipher

// Initialize with a secret 32-bit key — keep this consistent and private
let cipher = FeistelCipher(key: 722628)

// Obfuscate a plain integer ID
let token = cipher.encode(1)
// → "99G7GB6QCKZBH0"

// Recover the original ID — throws if the token is invalid or tampered
let originalID = try cipher.decode(token)
// → 1

// Format for display or sharing
let formatted = cipher.format(token)
// → "99G7-GB6Q-CKZB-H0"
```

---

## API Reference

### `FeistelCipher`

#### Initialization

```swift
public struct FeistelCipher: Sendable {
    public let key: UInt32
    public init(key: UInt32)
}
```

| Parameter | Type     | Description                                                  |
|-----------|----------|--------------------------------------------------------------|
| `key`     | `UInt32` | Your secret key. Must stay the same across encrypt/decrypt.  |

---

#### `encrypt(_ value: UInt64) -> UInt64`

Encrypts a raw 64-bit integer using the Feistel network. Returns an obfuscated 64-bit integer.

```swift
let encrypted = cipher.encrypt(1)
// → 10_718_831_381_117_009_265
```

---

#### `decrypt(_ value: UInt64) -> UInt64`

Decrypts a previously encrypted 64-bit integer back to its original value.

```swift
let original = cipher.decrypt(10_718_831_381_117_009_265)
// → 1
```

---

#### `encode(_ value: UInt64, withChecksum: Bool = true) -> String`

Encrypts a value and encodes it as a Crockford Base32 string. Appends a typo-detection checksum character by default.

The output length varies with the magnitude of the encrypted value (typically 11–14 characters). Use the `length` overload below if you need a consistent fixed length.

```swift
let token = cipher.encode(1)
// → "99G7GB6QCKZBH0"  (with checksum)

let tokenNoChecksum = cipher.encode(1_234_567, withChecksum: false)
// → "9G0X9D4P5QCWW"
```

| Parameter      | Type     | Default | Description                              |
|----------------|----------|---------|------------------------------------------|
| `value`        | `UInt64` | —       | The plain ID to encode                   |
| `withChecksum` | `Bool`   | `true`  | Appends a modulo-37 check character      |

---

#### `encode(_ value: UInt64, length: Int, withChecksum: Bool = true) -> String`

Same as above, but left-pads the result with `'0'` characters to reach a fixed length.

Leading `'0'` characters are value-neutral in Crockford Base32, so padded tokens are decoded correctly without any modifications to the decoder. If the natural encoded length already meets or exceeds `length`, the string is returned as-is — truncation is never performed.

```swift
// encode(1) naturally produces 14 chars; pad to 16
let token = cipher.encode(1, length: 16)
// → "0099G7GB6QCKZBH0"

// The padded token decodes to the same original ID
let id = try cipher.decode(token)
// → 1
```

| Parameter      | Type     | Default | Description                                                |
|----------------|----------|---------|------------------------------------------------------------|
| `value`        | `UInt64` | —       | The plain ID to encode                                     |
| `length`       | `Int`    | —       | Desired total character count of the returned string       |
| `withChecksum` | `Bool`   | `true`  | Appends a modulo-37 check character                        |

---

#### `decode(_ value: String) throws(FeistelCipherError) -> UInt64`

Decodes a Crockford Base32 token back to the original plain ID.

The input is normalised before decoding: dashes are stripped, `O` is treated as `0`, `I` and `L` are treated as `1`, and casing is ignored. If anything is wrong with the token, a typed `FeistelCipherError` is thrown so the caller can respond to each failure mode precisely.

```swift
// Valid token
let id = try cipher.decode("99G7GB6QCKZBH0")
// → 1

// Padded token — decodes to the same value
let id = try cipher.decode("0099G7GB6QCKZBH0")
// → 1

// Checksum mismatch — throws
do {
    let id = try cipher.decode("99G7GB6QCKZBH9")
} catch FeistelCipherError.checksumMismatch {
    // Prompt the user to re-enter the token
} catch {
    // Handle other failures
}
```

---

#### `format(_ value: String) -> String`

Groups an encoded string into chunks of 4 characters separated by dashes, making it easier to read and copy.

The formatted string is accepted by `decode` because dashes are stripped during normalisation.

```swift
let formatted = cipher.format("99G7GB6QCKZBH0")
// → "99G7-GB6Q-CKZB-H0"
```

---

### `FeistelCipherError`

A typed error thrown by `decode` when a token cannot be decoded. Conforms to `Error` and `Equatable`.

```swift
public enum FeistelCipherError: Error, Equatable {
    case emptyToken
    case invalidCharacter(Character)
    case checksumMismatch
}
```

| Case                       | When it is thrown                                                                         |
|----------------------------|-------------------------------------------------------------------------------------------|
| `emptyToken`               | The token is empty, or contains only separator characters after normalisation             |
| `invalidCharacter(Character)` | The token contains a character outside the Crockford Base32 alphabet that could not be corrected automatically |
| `checksumMismatch`         | The trailing check character does not match the expected modulo-37 value — typically a transcription error |

---

## How It Works

### Feistel Network

A [Feistel network](https://en.wikipedia.org/wiki/Feistel_cipher) is a symmetric cryptographic structure used in ciphers like DES. This library runs **4 rounds** over the 64-bit input, splitting it into two 32-bit halves (left and right):

```
For each round i in [0, 1, 2, 3]:
  roundKey  = key XOR i
  nextRight = left XOR F(right, roundKey)
  left      = right
  right     = nextRight
```

The round function `F` is a MurmurHash3-style 32-bit mixer:

```
F(x, roundKey):
  x = x XOR roundKey
  x = x * 0xFF51AFD7   (with overflow)
  x = x XOR (x >> 16)
  return x
```

Decryption simply reverses the round order — no additional logic needed.

### Crockford Base32 Encoding

[Crockford Base32](https://www.crockford.com/base32.html) is a human-friendly encoding scheme designed to minimise transcription errors:

- **Alphabet**: `0123456789ABCDEFGHJKMNPQRSTVWXYZ` (excludes ambiguous characters `I`, `L`, `O`, `U`)
- **Case-insensitive**: `A` and `a` are treated the same
- **Typo correction**: `O` → `0`, `I` → `1`, `L` → `1` — applied automatically before decoding
- **Checksum**: An optional modulo-37 check character detects single-character typos at decode time

---

## Examples

### Obfuscating User IDs in a REST API

```swift
let cipher = FeistelCipher(key: 0xDEAD_BEEF)

// Encode before sending to client
let publicID = cipher.encode(userID)
// Use in your URL: GET /users/99G7GB6QCKZBH0

// Decode when receiving from client
do {
    let internalID = try cipher.decode(publicID)
    // Use internalID to query your database
} catch FeistelCipherError.checksumMismatch {
    // Token was mistyped or tampered — return 400
} catch FeistelCipherError.emptyToken {
    // Missing token — return 400
} catch {
    // Unexpected failure
}
```

### Fixed-Length Tokens

```swift
let cipher = FeistelCipher(key: 722628)

// Always produce a 16-character token regardless of the input value
let token = cipher.encode(userID, length: 16)
// → "0099G7GB6QCKZBH0"

// Decodes correctly — leading zeros are value-neutral
let id = try cipher.decode(token)
```

### Working With Raw Encrypted Integers

```swift
let cipher = FeistelCipher(key: 12345)

let encrypted = cipher.encrypt(42)
let decrypted = cipher.decrypt(encrypted)

assert(decrypted == 42) // Always true
```

---

## Security Considerations

- **This is obfuscation, not encryption.** FeistelCipher is designed to prevent casual enumeration, not to protect sensitive secrets. Do not use it to secure passwords, PII, or cryptographic material.
- **Keep your key secret.** Anyone who knows the key can decrypt any token.
- **Use a strong, random key.** Avoid obvious values like `0` or `1234`.
- **Use consistent keys.** Changing the key will invalidate all previously issued tokens.

---

## Running Tests

```sh
swift test
```

All test suites are located in `Tests/FeistelCipherTests/`.

---

## Requirements

- **Swift**: 6.0+
- **Platforms**: macOS 26+, iOS 26+, and any other Swift-supported platform

---

## License

MIT License. See [LICENSE](LICENSE) for details.