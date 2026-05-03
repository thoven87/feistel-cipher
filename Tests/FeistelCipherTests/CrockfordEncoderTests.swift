import Testing

@testable import FeistelCipher

@Suite("CrockfordEncoder")
struct CrockfordEncoderTests {

    @Test func encodeWithChecksum() async throws {
        let value: UInt64 = 1_234_567_890
        let encoded = CrockfordEncoder.encodeWithChecksum(value)
        #expect(encoded == "14SC0PJV")
    }

    @Test func decodeWithChecksum() async throws {
        let encoded = "14SC0PJV"
        let decoded = try CrockfordEncoder.decode(encoded)
        #expect(decoded == 1_234_567_890)
    }

    @Test func decodeWithTypo() async throws {
        #expect(throws: FeistelCipherError.checksumMismatch) {
            try CrockfordEncoder.decode("14SC0PJ")
        }
    }

    @Test func decodeWithoutChecksum() async throws {
        // encode (no checksum) → decode (no checksum) must round-trip
        let value: UInt64 = 1_234_567_890
        let encoded = CrockfordEncoder.encode(value)
        let decoded = try CrockfordEncoder.decode(encoded, withChecksum: false)
        #expect(decoded == value)
    }

    @Test func decodeWithChecksumFalseIgnoresLastChar() async throws {
        // When withChecksum is false every character is treated as a value digit —
        // passing a token that HAS a checksum would decode to a different (larger) number
        let value: UInt64 = 1_234_567_890
        let withCheck = CrockfordEncoder.encodeWithChecksum(value)  // e.g. "14SC0PJV"
        let withoutCheck = CrockfordEncoder.encode(value)  // e.g. "14SC0PJ"
        let decodedFull = try CrockfordEncoder.decode(withoutCheck, withChecksum: false)
        #expect(decodedFull == value)
        // The checksum-bearing token decoded without checksum would be a different value
        let decodedFull2 = try CrockfordEncoder.decode(withCheck, withChecksum: false)
        #expect(decodedFull2 != value)
    }

    @Test func formatForCopying() async throws {
        let encoded = "1234567890"
        let formatted = CrockfordEncoder.formatForCopying(encoded)
        #expect(formatted == "1234-5678-90")
    }
}
