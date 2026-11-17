import XCTest
@testable import Multikey

final class MultikeyTests: XCTestCase {

    func testRoundTripEd25519() throws {
        let keyBytes = Data(repeating: 0xAB, count: 32)
        let mk = Multikey(keyType: .ed25519, keyBytes: keyBytes)
        let encoded = mk.encode()
        let decoded = try Multikey.decode(from: encoded)
        XCTAssertEqual(decoded.keyType, .ed25519)
        XCTAssertEqual(decoded.keyBytes, keyBytes)
    }

    func testRoundTripMLDSA65() throws {
        let keyBytes = Data(repeating: 0xCD, count: 1952)
        let mk = Multikey(keyType: .mlDSA65, keyBytes: keyBytes)
        let hex = mk.hexEncoded
        let decoded = try Multikey.decode(fromHex: hex)
        XCTAssertEqual(decoded.keyType, .mlDSA65)
        XCTAssertEqual(decoded.keyBytes, keyBytes)
    }

    func testEd25519PrefixByte() {
        let mk = Multikey(keyType: .ed25519, keyBytes: Data([0x01, 0x02]))
        let encoded = mk.encode()
        XCTAssertEqual(encoded[0], 0xed)
    }

    func testMultibyteVarintMLDSA65() {
        let mk = Multikey(keyType: .mlDSA65, keyBytes: Data())
        let encoded = mk.encode()
        XCTAssertGreaterThan(encoded.count, 1, "ML-DSA-65 code 0x1207 requires multi-byte varint")
    }

    func testUnknownKeyTypeThrows() {
        let unknown = Data([0xFF, 0xFF, 0x01, 0xAA])
        XCTAssertThrowsError(try Multikey.decode(from: unknown))
    }

    func testHexRoundTrip() throws {
        let keyBytes = Data((0..<32).map { UInt8($0) })
        let mk = Multikey(keyType: .secp256k1, keyBytes: keyBytes)
        let hex = mk.hexEncoded
        let decoded = try Multikey.decode(fromHex: hex)
        XCTAssertEqual(decoded, mk)
    }
}

/// The hex paths against Multikey 1.0.0's own code, verbatim.
final class HexDifferentialTests: XCTestCase {
    static func referenceHex(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }

    static func referenceData(hexString: String) -> Data? {
        let hex = hexString.hasPrefix("0x") ? String(hexString.dropFirst(2)) : hexString
        guard hex.count % 2 == 0 else { return nil }
        var data = Data(capacity: hex.count / 2)
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<next], radix: 16) else { return nil }
            data.append(byte)
            index = next
        }
        return data
    }

    struct SplitMix64: RandomNumberGenerator {
        var state: UInt64
        mutating func next() -> UInt64 {
            state &+= 0x9e3779b97f4a7c15
            var z = state
            z = (z ^ (z >> 30)) &* 0xbf58476d1ce4e5b9
            z = (z ^ (z >> 27)) &* 0x94d049bb133111eb
            return z ^ (z >> 31)
        }
    }

    func testHexEncodedMatchesFormatSpelling() {
        var rng = SplitMix64(state: 1)
        for _ in 0..<2_000 {
            let type = KeyType.allCases.randomElement(using: &rng)!
            let bytes = Data((0..<Int.random(in: 0...64, using: &rng)).map { _ in UInt8.random(in: 0...255, using: &rng) })
            let key = Multikey(keyType: type, keyBytes: bytes)
            XCTAssertEqual(key.hexEncoded, Self.referenceHex(key.encode()))
        }
    }

    /// Both cases of digit, the `0x`/`0X` prefixes, the signs
    /// `UInt8(_:radix:)` accepts, and non-ASCII text, including a combining
    /// mark that joins a digit into one Character and a CR LF pair that is one.
    func testHexDecodingMatchesTheStringParser() {
        let alphabet = [
            "0", "1", "7", "9", "a", "c", "e", "d", "f", "A", "F", "x", "X", "+", "-",
            " ", "g", "0x", "0X", "\u{301}", "é", "０", "\r\n", "\u{0}",
        ]
        var rng = SplitMix64(state: 2)
        var inputs = ["", "0x", "0X", "+f", "-0", "-1", "0x+f", "0x\u{301}00", "0\u{301}0", "\r\n00", "ed01", "ED01", "0xed01"]
        for _ in 0..<20_000 {
            inputs.append((0..<Int.random(in: 0...10, using: &rng)).map { _ in alphabet.randomElement(using: &rng)! }.joined())
        }
        for input in inputs {
            XCTAssertEqual(Data(hexString: input), Self.referenceData(hexString: input), input.debugDescription)
            let decoded = try? Multikey.decode(fromHex: input)
            let reference = Self.referenceData(hexString: input).flatMap { try? Multikey.decode(from: $0) }
            XCTAssertEqual(decoded, reference, input.debugDescription)
        }
    }
}
