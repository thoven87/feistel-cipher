/// Errors thrown by ``FeistelCipher`` and ``FeistelCipher32`` during decoding operations.
public enum FeistelCipherError: Error, Equatable {

    /// The token is empty, or contains only separator characters after normalisation.
    case emptyToken

    /// The token contains a character that is not part of the Crockford Base32 alphabet
    /// and could not be corrected automatically.
    ///
    /// Automatically corrected look-alikes (`O` → `0`, `I` / `L` → `1`) and
    /// separator dashes are stripped before this check, so only genuinely
    /// unrecognisable characters produce this error.
    case invalidCharacter(Character)

    /// The check character at the end of the token does not match the expected
    /// modulo-37 value computed from the token body.
    ///
    /// This error typically indicates a single-character transcription mistake.
    /// The caller may prompt the user to re-enter or re-scan the token.
    case checksumMismatch

    /// The decoded numeric value exceeds the range supported by the cipher variant.
    ///
    /// Thrown by ``FeistelCipher32/decode(_:)`` when the token encodes a value larger
    /// than `UInt32.max` — for example, when a token produced by the 64-bit
    /// ``FeistelCipher`` is mistakenly passed to the 32-bit variant.
    case valueOutOfRange
}
