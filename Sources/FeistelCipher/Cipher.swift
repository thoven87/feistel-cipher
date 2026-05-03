/// A symmetric cipher that obfuscates and restores `UInt64` values using a Feistel network.
///
/// `FeistelCipher` operates over a configurable even bit width (8–64 bits, default 64).
/// The input is split into two equal halves of `bitWidth / 2` bits each, and four Feistel
/// rounds are applied. The same key that encrypts a value is used to decrypt it.
///
/// Choosing a smaller `bitWidth` produces shorter encoded tokens:
///
/// | `bitWidth` | Halves      | Max token (no checksum) | Max token (with checksum) |
/// |------------|-------------|-------------------------|---------------------------|
/// | 64         | 32 + 32 bit | 13 chars                | 14 chars                  |
/// | 50         | 25 + 25 bit | 10 chars                | 11 chars                  |
/// | 32         | 16 + 16 bit | 7 chars                 | 8 chars                   |
///
/// ## Example — default 64-bit
/// ```swift
/// let cipher = FeistelCipher(key: 722628)
/// let token  = cipher.encode(1)          // "99G7GB6QCKZBH0"
/// let id     = try cipher.decode(token)  // 1
/// ```
///
/// ## Example — 50-bit (exactly 10 chars without checksum)
/// ```swift
/// let cipher = FeistelCipher(key: 722628, bitWidth: 50)
/// let token  = cipher.encode(1, length: 10, withChecksum: false)  // always 10 chars
/// let id     = try cipher.decode(token)                           // 1
/// ```
///
/// - Note: This is **obfuscation**, not cryptographic encryption.
///   It prevents casual ID enumeration but should not be used to protect sensitive secrets.
public struct FeistelCipher: Sendable {

    /// The 32-bit secret key that drives every round of the cipher.
    ///
    /// All encrypt and decrypt operations are keyed on this value.
    /// Changing the key invalidates every previously encoded token.
    public let key: UInt32

    /// The total bit width of the cipher's domain.
    ///
    /// Must be an even number between 8 and 64 (inclusive). Determines the size of the
    /// input/output space: a `bitWidth`-bit cipher is a bijection of `[0, 2^bitWidth - 1]`.
    /// Smaller values produce shorter Crockford Base32 tokens.
    public let bitWidth: Int

    /// Half of `bitWidth` — the size of each Feistel half in bits.
    private let halfWidth: Int

    /// Bitmask for one Feistel half: `(1 << halfWidth) - 1`.
    ///
    /// Applied after the round function to keep values within the `halfWidth`-bit domain.
    private let halfMask: UInt64

    /// The number of Feistel rounds applied during encryption and decryption.
    ///
    /// Four rounds provide a good balance between diffusion and performance.
    let rounds: Int = 4

    /// Creates a new cipher with the given key and bit width.
    ///
    /// - Parameters:
    ///   - key: The 32-bit secret key.
    ///   - bitWidth: The total bit width of the cipher domain. Must be even and in `[8, 64]`.
    ///               Defaults to `64`.
    public init(key: UInt32, bitWidth: Int = 64) {
        precondition(
            bitWidth.isMultiple(of: 2) && bitWidth >= 8 && bitWidth <= 64,
            "bitWidth must be an even number between 8 and 64, got \(bitWidth)"
        )
        self.key = key
        self.bitWidth = bitWidth
        self.halfWidth = bitWidth / 2
        self.halfMask = (UInt64(1) << (bitWidth / 2)) - 1
    }

    // MARK: - Private

    /// The per-round mixing function applied to the right half of the Feistel network.
    ///
    /// Uses a MurmurHash3-style 32-bit mixer:
    /// 1. XOR `right` with `roundKey` to inject key material.
    /// 2. Multiply by the MurmurHash3 constant `0xFF51AFD7` (overflow discarded).
    /// 3. XOR the result with its own upper 16 bits to improve avalanche.
    ///
    /// - Parameters:
    ///   - right: The right 32-bit half of the current Feistel state.
    ///   - roundKey: The key for this specific round, derived from `key XOR roundIndex`.
    /// - Returns: A mixed 32-bit value that is XOR-ed into the left half.
    private func roundFunction(_ right: UInt32, _ roundKey: UInt32) -> UInt32 {
        var x = right ^ roundKey
        x = x.multipliedReportingOverflow(by: 0xff51_afd7).partialValue
        x ^= x >> 16
        return x
    }

    // MARK: - Core Cipher

    /// Encrypts a 64-bit integer into an obfuscated 64-bit integer using the Feistel network.
    ///
    /// The input is split into two 32-bit halves. Each round applies `roundFunction` to the
    /// right half and XORs the result into the left half, then swaps the halves.
    /// After `rounds` iterations the two halves are recombined into the output value.
    ///
    /// - Parameter value: The plain 64-bit integer to encrypt.
    /// - Returns: An obfuscated 64-bit integer that can be restored with ``decrypt(_:)``.
    ///
    /// ## Example
    /// ```swift
    /// let cipher = FeistelCipher(key: 722628)
    /// let encrypted = cipher.encrypt(1)  // 10_718_831_381_117_009_265
    /// ```
    public func encrypt(_ value: UInt64) -> UInt64 {
        var left = (value >> halfWidth) & halfMask
        var right = value & halfMask

        for i in 0..<rounds {
            let roundKey = key ^ UInt32(i)
            let f = UInt64(roundFunction(UInt32(right), roundKey)) & halfMask
            let nextRight = left ^ f
            left = right
            right = nextRight
        }
        return (right << halfWidth) | left
    }

    /// Decrypts an obfuscated 64-bit integer back to its original plain value.
    ///
    /// Applies the same Feistel rounds as ``encrypt(_:)`` but in reverse order,
    /// which is sufficient to undo the transformation without any additional logic.
    ///
    /// - Parameter value: A 64-bit integer previously produced by ``encrypt(_:)``.
    /// - Returns: The original plain value passed to ``encrypt(_:)``.
    ///
    /// ## Example
    /// ```swift
    /// let cipher = FeistelCipher(key: 722628)
    /// let original = cipher.decrypt(10_718_831_381_117_009_265)  // 1
    /// ```
    public func decrypt(_ value: UInt64) -> UInt64 {
        var right = (value >> halfWidth) & halfMask
        var left = value & halfMask

        for i in (0..<rounds).reversed() {
            let roundKey = key ^ UInt32(i)
            let f = UInt64(roundFunction(UInt32(left), roundKey)) & halfMask
            let prevLeft = right ^ f
            right = left
            left = prevLeft
        }
        return (left << halfWidth) | right
    }

    // MARK: - String Encoding

    /// Encrypts a value and encodes it as a Crockford Base32 string.
    ///
    /// Internally calls ``encrypt(_:)`` and then encodes the result using
    /// [Crockford Base32](https://www.crockford.com/base32.html).
    /// When `withChecksum` is `true` (the default), a modulo-37 check character is
    /// appended so that single-character typos can be detected during ``decode(_:)``.
    ///
    /// The output length varies with the magnitude of the encrypted value (typically
    /// 11–14 characters). Use ``encode(_:length:withChecksum:)`` if you need a fixed length.
    ///
    /// - Parameters:
    ///   - value: The plain 64-bit integer to encrypt and encode.
    ///   - withChecksum: When `true`, a typo-detection check character is appended. Defaults to `true`.
    /// - Returns: A Crockford Base32 string representing the encrypted value.
    ///
    /// ## Example
    /// ```swift
    /// let cipher = FeistelCipher(key: 722628)
    /// cipher.encode(1)                          // "99G7GB6QCKZBH0"  (with checksum)
    /// cipher.encode(1_234_567, withChecksum: false)  // "9G0X9D4P5QCWW"
    /// ```
    public func encode(_ value: UInt64, withChecksum: Bool = true) -> String {
        let data = encrypt(value)
        return CrockfordEncoder.encode(data, withChecksum: withChecksum)
    }

    /// Encrypts a value and encodes it as a Crockford Base32 string padded to a fixed length.
    ///
    /// Calls ``encode(_:withChecksum:)`` and left-pads the result with `'0'` characters
    /// until it reaches `length`. Leading zeros are value-neutral in Crockford Base32 —
    /// the decoder accumulates digits as `numericValue * 32 + digit`, so a leading `'0'`
    /// (digit value 0) leaves the result unchanged. Padded tokens therefore round-trip
    /// through ``decode(_:)`` correctly without any modifications to the decoder.
    ///
    /// If the natural encoded length already meets or exceeds `length`,
    /// the string is returned as-is. Truncation is never performed.
    ///
    /// - Parameters:
    ///   - value: The plain 64-bit integer to encrypt and encode.
    ///   - length: The desired total character count of the returned string.
    ///   - withChecksum: When `true`, a typo-detection check character is appended. Defaults to `true`.
    /// - Returns: A Crockford Base32 string of at least `length` characters.
    ///
    /// ## Example
    /// ```swift
    /// let cipher = FeistelCipher(key: 722628)
    ///
    /// // encode(1) naturally produces 14 chars; pad to 16
    /// cipher.encode(1, length: 16)  // "0099G7GB6QCKZBH0"
    ///
    /// // Decoding the padded token returns the original ID
    /// cipher.decode("0099G7GB6QCKZBH0")  // 1
    /// ```
    public func encode(_ value: UInt64, length: Int, withChecksum: Bool = true) -> String {
        let encoded = encode(value, withChecksum: withChecksum)
        guard encoded.count < length else { return encoded }
        let padding = String(repeating: "0", count: length - encoded.count)
        return padding + encoded
    }

    /// Decodes a Crockford Base32 token back to the original plain 64-bit integer.
    ///
    /// The input is normalised before decoding:
    /// - Dashes (`-`) are stripped.
    /// - The letter `O` is treated as `0`.
    /// - The letters `I` and `L` are treated as `1`.
    /// - Case is ignored.
    ///
    /// Leading `'0'` characters in the value portion are safe and value-neutral,
    /// so tokens produced by ``encode(_:length:withChecksum:)`` decode correctly.
    ///
    /// - Parameter value: A Crockford Base32 string previously produced by ``encode(_:withChecksum:)``
    ///   or ``encode(_:length:withChecksum:)``.
    /// - Parameters:
    ///   - value: A Crockford Base32 string previously produced by ``encode(_:withChecksum:)``
    ///     or ``encode(_:length:withChecksum:)``.
    ///   - withChecksum: When `true` (the default), the trailing check character is validated
    ///     before decoding. Set to `false` when decoding tokens that were encoded with
    ///     `withChecksum: false`.
    /// - Returns: The original plain integer.
    /// - Throws:
    ///   - ``FeistelCipherError/emptyToken`` if the token is empty after normalisation.
    ///   - ``FeistelCipherError/invalidCharacter(_:)`` if the token contains a character outside
    ///     the Crockford Base32 alphabet that could not be corrected automatically.
    ///   - ``FeistelCipherError/checksumMismatch`` if `withChecksum` is `true` and the trailing
    ///     check character does not match.
    ///
    /// ## Example
    /// ```swift
    /// let cipher = FeistelCipher(key: 722628)
    ///
    /// // Default — checksum validated
    /// try cipher.decode("99G7GB6QCKZBH0")                  // 1
    ///
    /// // Token encoded without checksum — must decode the same way
    /// let token = cipher.encode(1, withChecksum: false)
    /// try cipher.decode(token, withChecksum: false)         // 1
    /// ```
    public func decode(_ value: String, withChecksum: Bool = true) throws(FeistelCipherError)
        -> UInt64
    {
        let decoded = try CrockfordEncoder.decode(value, withChecksum: withChecksum)
        return decrypt(decoded)
    }

    /// Formats a Crockford Base32 token into dash-separated groups of four characters.
    ///
    /// Groups of four characters are easier to read, transcribe, and verify by eye.
    /// The formatted string is accepted by ``decode(_:)`` because dashes are stripped
    /// during normalisation.
    ///
    /// - Parameter value: A raw Crockford Base32 string, such as one returned by ``encode(_:withChecksum:)``.
    /// - Returns: The same string with a dash inserted after every fourth character.
    ///
    /// ## Example
    /// ```swift
    /// let cipher = FeistelCipher(key: 722628)
    /// cipher.format("99G7GB6QCKZBH0")  // "99G7-GB6Q-CKZB-H0"
    /// ```
    public func format(_ value: String) -> String {
        CrockfordEncoder.formatForCopying(value)
    }
}
