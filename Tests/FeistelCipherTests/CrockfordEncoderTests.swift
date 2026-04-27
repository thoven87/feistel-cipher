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

    @Test func formatForCopying() async throws {
        let encoded = "1234567890"
        let formatted = CrockfordEncoder.formatForCopying(encoded)
        #expect(formatted == "1234-5678-90")
    }
}
