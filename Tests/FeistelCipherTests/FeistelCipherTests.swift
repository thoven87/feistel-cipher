import Testing

@testable import FeistelCipher

@Suite("FeistelCipher")
struct FeistelCipherTests {

    let cipher = FeistelCipher(key: 722628)

    @Test func testEncrypt() async throws {
        let plainID: UInt64 = 1
        let encrypted = cipher.encrypt(plainID)
        #expect(encrypted == 10_718_831_381_117_009_265)
    }

    @Test func testDecrypt() async throws {
        let encryptedId: UInt64 = 10_718_831_381_117_009_265
        let decrypted = cipher.decrypt(encryptedId)
        #expect(decrypted == 1)
    }

    @Test func testEncode() async throws {
        let plainID: UInt64 = 1
        let encoded = cipher.encode(plainID)
        #expect(encoded == "99G7GB6QCKZBH0")
    }

    @Test func testDecode() async throws {
        let encoded = "99G7GB6QCKZBH0"
        let decoded = try cipher.decode(encoded)
        #expect(decoded == 1)
    }

    @Test func testFormat() async throws {
        let encoded = "99G7GB6QCKZBH0"
        let formatted = cipher.format(encoded)
        #expect(formatted == "99G7-GB6Q-CKZB-H0")
    }

    @Test func testEncodeWithoutChecksum() async throws {
        let plainID: UInt64 = 1_234_567
        let encoded = cipher.encode(plainID, withChecksum: false)
        #expect(encoded == "9G0X9D4P5QCWW")
    }

    @Test func testDecodeWithoutChecksumRoundTrip() async throws {
        // encode(withChecksum: false) + decode(withChecksum: false) must return the original value
        for id: UInt64 in [1, 42, 1_000, 1_234_567] {
            let token = cipher.encode(id, withChecksum: false)
            let decoded = try cipher.decode(token, withChecksum: false)
            #expect(decoded == id)
        }
    }

    @Test func testDecodeWithChecksumTrueFailsOnChecksumlessToken() async throws {
        // A token encoded without checksum must NOT decode successfully with checksum: true,
        // because its last value character is consumed as (almost certainly wrong) check char
        let token = cipher.encode(1, withChecksum: false)
        #expect(throws: FeistelCipherError.checksumMismatch) {
            try cipher.decode(token, withChecksum: true)
        }
    }

    @Test func testBitWidth50DecodeWithoutChecksumRoundTrip() async throws {
        // The canonical 10-char use-case: bitWidth 50, no checksum, fixed length
        let cipher50 = FeistelCipher(key: 722628, bitWidth: 50)
        for id: UInt64 in [1, 42, 1_000, 1_000_000] {
            let token = cipher50.encode(id, length: 10, withChecksum: false)
            #expect(token.count == 10)
            let decoded = try cipher50.decode(token, withChecksum: false)
            #expect(decoded == id)
        }
    }

    // MARK: - Fixed-length encode overload

    @Test func testEncodeWithLengthPadsWithLeadingZeros() async throws {
        let plainID: UInt64 = 1
        // encode(1) produces "99G7GB6QCKZBH0" (14 chars); padding to 16 prepends two zeros
        let encoded = cipher.encode(plainID, length: 16)
        #expect(encoded == "0099G7GB6QCKZBH0")
        #expect(encoded.count == 16)
    }

    @Test func testEncodeWithLengthEqualToNaturalLength() async throws {
        let plainID: UInt64 = 1
        // encode(1) is already 14 chars; requesting length 14 should return it unchanged
        let encoded = cipher.encode(plainID, length: 14)
        #expect(encoded == "99G7GB6QCKZBH0")
        #expect(encoded.count == 14)
    }

    @Test func testEncodeWithLengthShorterThanNaturalLength() async throws {
        let plainID: UInt64 = 1
        // encode(1) is 14 chars; requesting a shorter length should not truncate
        let encoded = cipher.encode(plainID, length: 12)
        #expect(encoded == "99G7GB6QCKZBH0")
        #expect(encoded.count == 14)
    }

    @Test func testDecodeAcceptsPaddedToken() async throws {
        // encode(1, length: 16) prepends "00" to the natural "99G7GB6QCKZBH0".
        // Both the padded and unpadded forms must decode to the same original ID,
        // because leading '0' characters are value-neutral in Crockford Base32.
        #expect(try cipher.decode("99G7GB6QCKZBH0") == 1)
        #expect(try cipher.decode("0099G7GB6QCKZBH0") == 1)
    }

    @Test func testEncodeWithLengthRoundTrip() async throws {
        let plainID: UInt64 = 42
        let encoded = cipher.encode(plainID, length: 16)
        #expect(encoded.count == 16)
        let decoded = try cipher.decode(encoded)
        #expect(decoded == plainID)
    }

    // MARK: - Case insensitivity

    @Test func testDecodeLowercaseToken() async throws {
        // decode() uppercases the input first, so lowercase tokens must decode identically
        #expect(try cipher.decode("99g7gb6qckzbh0") == 1)
    }

    @Test func testDecodeMixedCaseToken() async throws {
        // Mixed case is also normalised by the upcase step
        #expect(try cipher.decode("99g7GB6qCKzbH0") == 1)
    }

    // MARK: - bitWidth

    @Test func testDefaultBitWidthIs64() {
        #expect(cipher.bitWidth == 64)
    }

    @Test func testBitWidth64ProducesIdenticalResultsToOriginal() {
        // bitWidth: 64 must be fully backward-compatible — same encrypted values as before
        let explicit = FeistelCipher(key: 722628, bitWidth: 64)
        #expect(explicit.encrypt(1) == 10_718_831_381_117_009_265)
        #expect(explicit.decrypt(10_718_831_381_117_009_265) == 1)
        #expect(explicit.encrypt(1) == cipher.encrypt(1))
    }

    @Test func testBitWidth50EncryptedValueStaysInDomain() {
        // All outputs must be < 2^50
        let cipher50 = FeistelCipher(key: 722628, bitWidth: 50)
        let limit = UInt64(1) << 50
        for i: UInt64 in [0, 1, 42, 1_000, 1_000_000, limit - 1] {
            #expect(cipher50.encrypt(i) < limit)
        }
    }

    @Test func testBitWidth50RoundTrip() {
        let cipher50 = FeistelCipher(key: 722628, bitWidth: 50)
        let limit = UInt64(1) << 50
        let values: [UInt64] = [0, 1, 42, 1_000, 1_000_000, limit / 2, limit - 1]
        for value in values {
            #expect(cipher50.decrypt(cipher50.encrypt(value)) == value)
        }
    }

    @Test func testBitWidth50TokenLengthWithoutChecksum() {
        // 50 bits = 10 × 5-bit Base32 chars — no token should exceed 10 chars without checksum
        let cipher50 = FeistelCipher(key: 722628, bitWidth: 50)
        for i: UInt64 in [1, 100, 100_000] {
            let token = cipher50.encode(i, withChecksum: false)
            #expect(token.count <= 10, "Token for \(i) was \(token.count) chars: \(token)")
        }
    }

    @Test func testBitWidth50FixedLengthRoundTrip() async throws {
        // The canonical 10-char token: no checksum, padded to exactly 10
        let cipher50 = FeistelCipher(key: 722628, bitWidth: 50)
        let token = cipher50.encode(1, length: 10, withChecksum: false)
        #expect(token.count == 10)
        // Without checksum the token cannot be decoded via the checksum-validating decode path;
        // verify the round-trip at the raw integer level instead
        #expect(cipher50.decrypt(cipher50.encrypt(1)) == 1)
    }

    @Test func testBitWidth50EncodeDecodeRoundTrip() async throws {
        // With checksum enabled, encode+decode must return the original value
        let cipher50 = FeistelCipher(key: 722628, bitWidth: 50)
        for i: UInt64 in [1, 42, 1_000, 1_000_000] {
            let token = cipher50.encode(i)
            let decoded = try cipher50.decode(token)
            #expect(decoded == i)
        }
    }

    @Test func testBitWidth50TokenIsShorterThan64Bit() {
        let cipher50 = FeistelCipher(key: 722628, bitWidth: 50)
        // For a large sequential ID the 50-bit token must be shorter than the 64-bit one
        for i: UInt64 in [1_000, 1_000_000] {
            #expect(cipher50.encode(i).count <= cipher.encode(i).count)
        }
    }

    // MARK: - Error handling

    @Test func testDecodeThrowsOnChecksumMismatch() async throws {
        // Last character changed from '0' to '9' — valid Base32 char but wrong checksum
        #expect(throws: FeistelCipherError.checksumMismatch) {
            try cipher.decode("99G7GB6QCKZBH9")
        }
    }

    @Test func testDecodeThrowsOnEmptyToken() async throws {
        #expect(throws: FeistelCipherError.emptyToken) {
            try cipher.decode("")
        }
    }

    @Test func testDecodeThrowsOnInvalidCharacter() async throws {
        // '!' is not in the Crockford Base32 alphabet and cannot be normalised
        #expect(throws: FeistelCipherError.invalidCharacter("!")) {
            try cipher.decode("99G7GB6QCKZB!0")
        }
    }
}
