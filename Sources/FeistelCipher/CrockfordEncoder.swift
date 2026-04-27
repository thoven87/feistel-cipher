/// A namespace for encoding and decoding `UInt64` values using
/// [Crockford Base32](https://www.crockford.com/base32.html).
///
/// Crockford Base32 is designed to be human-friendly:
/// - Ambiguous characters (`I`, `L`, `O`, `U`) are excluded from the alphabet.
/// - The encoding is case-insensitive; common look-alike characters (`O` → `0`, `I`/`L` → `1`) are
///   normalised automatically on decode.
/// - An optional modulo-37 check symbol can be appended to detect single-character transcription
///   errors before the value is even processed.
struct CrockfordEncoder {

    /// The 32-symbol Base32 alphabet defined by the Crockford standard.
    ///
    /// Characters that are visually ambiguous in most fonts — `I`, `L`, `O`, and `U` — are
    /// deliberately omitted. Each character's position in this string is its numeric value
    /// (0 – 31) in the encoding.
    static let alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

    /// The 37-symbol set used to compute and verify the optional check character.
    ///
    /// The check character is chosen as `value % 37`, which allows the symbol set to extend
    /// beyond the 32-character alphabet with five additional symbols (`*`, `~`, `$`, `=`, `U`).
    /// This makes single-character substitution errors detectable before decryption.
    static let checkSymbols = "0123456789ABCDEFGHJKMNPQRSTVWXYZ*~$=U"  // Modulo 37

    // MARK: - Decoding

    /// Decodes a Crockford Base32 string that includes a trailing check character and returns
    /// the original `UInt64` value.
    ///
    /// Decoding is tolerant of common transcription mistakes:
    /// - Dashes (`-`) are stripped and ignored (they are treated as visual separators).
    /// - The letter `O` is normalised to `0`.
    /// - The letters `I` and `L` are normalised to `1`.
    /// - The input is uppercased before processing.
    ///
    /// The last character of the cleaned input is treated as the check symbol. If it does not
    /// match the expected `value % 37` symbol, ``FeistelCipherError/checksumMismatch`` is thrown
    /// so the caller can distinguish a typo from other failure modes.
    ///
    /// - Parameter input: A Crockford Base32-encoded string with a trailing check character.
    /// - Returns: The decoded `UInt64` value.
    /// - Throws:
    ///   - ``FeistelCipherError/emptyToken`` if the token is empty after normalisation.
    ///   - ``FeistelCipherError/invalidCharacter(_:)`` if the token contains a character outside
    ///     the Crockford Base32 alphabet that could not be corrected automatically.
    ///   - ``FeistelCipherError/checksumMismatch`` if the trailing check character does not match.
    static func decode(_ input: String) throws(FeistelCipherError) -> UInt64 {
        let clean = input.uppercased()
            .replacing("-", with: "")
            .replacing("O", with: "0")
            .replacing("I", with: "1")
            .replacing("L", with: "1")

        guard !clean.isEmpty else { throw .emptyToken }

        // 1. Separate the value from the check symbol (last character)
        let valuePart = String(clean.dropLast())
        let providedCheckChar = clean.last!

        // 2. Decode the value part, throwing on any unrecognised character
        var numericValue: UInt64 = 0
        for char in valuePart {
            guard let index = alphabet.firstIndex(of: char) else {
                throw .invalidCharacter(char)
            }
            numericValue =
                numericValue * 32 + UInt64(alphabet.distance(from: alphabet.startIndex, to: index))
        }

        // 3. Validate the check symbol
        let expectedCheckIndex = Int(numericValue % 37)
        let expectedCheckChar = checkSymbols[
            checkSymbols.index(checkSymbols.startIndex, offsetBy: expectedCheckIndex)]

        guard providedCheckChar == expectedCheckChar else {
            throw .checksumMismatch
        }

        return numericValue
    }

    // MARK: - Encoding

    /// Encodes a `UInt64` value as a Crockford Base32 string and appends a modulo-37 check
    /// character to the end.
    ///
    /// The check character is derived from `value % 37` and selected from ``checkSymbols``.
    /// It allows ``decode(_:)`` to detect single-character transcription errors without any
    /// external state or database lookup.
    ///
    /// - Parameter value: The `UInt64` value to encode.
    /// - Returns: A Crockford Base32 string with a trailing check character.
    static func encodeWithChecksum(_ value: UInt64) -> String {
        var result = encode(value)
        let checkIndex = Int(value % 37)
        let checkChar = checkSymbols[
            checkSymbols.index(checkSymbols.startIndex, offsetBy: checkIndex)
        ]
        result.append(checkChar)
        return result
    }

    /// Encodes a `UInt64` value as a Crockford Base32 string **without** a check character.
    ///
    /// Each character in the result maps to a 5-bit group of the value, using the 32-symbol
    /// ``alphabet``. Leading zero characters are suppressed; `0` is returned for a zero input.
    ///
    /// > Note: Strings produced by this function cannot be verified or decoded by ``decode(_:)``,
    /// > which always expects a trailing check character. Use ``encodeWithChecksum(_:)`` when the
    /// > result will be decoded later.
    ///
    /// - Parameter value: The `UInt64` value to encode.
    /// - Returns: A Crockford Base32 string with no trailing check character.
    static func encode(_ value: UInt64) -> String {
        var n = value
        if n == 0 { return "0" }

        var result = ""
        let base = UInt64(alphabet.count)

        while n > 0 {
            let index = Int(n % base)
            let char = alphabet[alphabet.index(alphabet.startIndex, offsetBy: index)]
            result.insert(char, at: result.startIndex)
            n /= base
        }

        return result
    }

    // MARK: - Formatting

    /// Formats an encoded string into dash-separated groups of four characters for improved
    /// readability and ease of manual transcription.
    ///
    /// For example, `"99G7GB6QCKZBH0"` becomes `"99G7-GB6Q-CKZB-H0"`.
    ///
    /// The dashes are purely cosmetic. ``decode(_:)`` strips them automatically, so a formatted
    /// string can be passed directly to ``decode(_:)`` without pre-processing.
    ///
    /// - Parameter encoded: A raw Crockford Base32 string (with or without a check character).
    /// - Returns: The same string with a `-` inserted after every fourth character.
    static func formatForCopying(_ encoded: String) -> String {
        // Group into chunks of 4 for maximum readability
        var result = ""
        let characters = Array(encoded)
        for (index, char) in characters.enumerated() {
            if index > 0 && index % 4 == 0 {
                result.append("-")
            }
            result.append(char)
        }
        return result
    }
}
