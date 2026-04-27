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
