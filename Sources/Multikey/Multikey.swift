import Foundation

/// Registered key types from the multicodec table.
/// https://github.com/multiformats/multicodec/blob/master/table.csv
public enum KeyType: UInt64, Sendable, Codable, CaseIterable {
    case ed25519    = 0xed
    case secp256k1  = 0xe7
    case p256       = 0x1200
    case p384       = 0x1201
    case p521       = 0x1202
    case mlDSA44    = 0x1205   // ML-DSA-44  (Dilithium level 2)
    case mlDSA65    = 0x1207   // ML-DSA-65  (Dilithium level 3)
    case mlDSA87    = 0x1208   // ML-DSA-87  (Dilithium level 5)

    public var name: String {
        switch self {
        case .ed25519:   return "ed25519"
        case .secp256k1: return "secp256k1"
        case .p256:      return "p256"
        case .p384:      return "p384"
        case .p521:      return "p521"
        case .mlDSA44:   return "ml-dsa-44"
        case .mlDSA65:   return "ml-dsa-65"
        case .mlDSA87:   return "ml-dsa-87"
        }
    }
}

/// A public key encoded as varint(keyType) + keyBytes.
/// Compatible with the multicodec/multikey spec.
public struct Multikey: Sendable, Equatable, Hashable {
    public let keyType: KeyType
    public let keyBytes: Data

    public init(keyType: KeyType, keyBytes: Data) {
        self.keyType = keyType
        self.keyBytes = keyBytes
    }

    // MARK: - Encoding

    public func encode() -> Data {
        var out = Data()
        out.append(contentsOf: uvarint(keyType.rawValue))
        out.append(keyBytes)
        return out
    }

    /// Lowercase, two digits per byte: what `String(format: "%02x")` spells.
    public var hexEncoded: String {
        let bytes = encode()
        return String(unsafeUninitializedCapacity: bytes.count * 2) { buffer in
            var index = 0
            for byte in bytes {
                buffer[index] = hexDigit(byte >> 4)
                buffer[index + 1] = hexDigit(byte & 0x0f)
                index += 2
            }
            return index
        }
    }

    // MARK: - Decoding

    public static func decode(from data: Data) throws -> Multikey {
        var offset = 0
        let (code, bytesRead) = try readUvarint(data, offset: &offset)
        guard let keyType = KeyType(rawValue: code) else {
            throw MultikeyError.unknownKeyType(code)
        }
        let keyBytes = data[offset...]
        return Multikey(keyType: keyType, keyBytes: Data(keyBytes))
    }

    public static func decode(fromHex hex: String) throws -> Multikey {
        guard let data = Data(hexString: hex) else {
            throw MultikeyError.invalidEncoding
        }
        return try decode(from: data)
    }
}

// MARK: - Errors

public enum MultikeyError: Error, Sendable {
    case unknownKeyType(UInt64)
    case invalidEncoding
    case varintOverflow
    case varintTruncated
}

// MARK: - Varint helpers

private func uvarint(_ value: UInt64) -> [UInt8] {
    var v = value
    var bytes: [UInt8] = []
    while v >= 0x80 {
        bytes.append(UInt8(v & 0x7F) | 0x80)
        v >>= 7
    }
    bytes.append(UInt8(v))
    return bytes
}

private func readUvarint(_ data: Data, offset: inout Int) throws -> (UInt64, Int) {
    var result: UInt64 = 0
    var shift = 0
    let start = offset
    while offset < data.count {
        let byte = data[offset]
        offset += 1
        guard shift < 64 else { throw MultikeyError.varintOverflow }
        result |= UInt64(byte & 0x7F) << shift
        if byte & 0x80 == 0 { return (result, offset - start) }
        shift += 7
    }
    throw MultikeyError.varintTruncated
}

// MARK: - Hex helpers

@inline(__always)
private func hexDigit(_ value: UInt8) -> UInt8 {
    value < 10 ? value &+ UInt8(ascii: "0") : value &- 10 &+ UInt8(ascii: "a")
}

@inline(__always)
private func hexValue(_ digit: UInt8) -> UInt8? {
    switch digit {
    case UInt8(ascii: "0")...UInt8(ascii: "9"): digit &- UInt8(ascii: "0")
    case UInt8(ascii: "a")...UInt8(ascii: "f"): digit &- UInt8(ascii: "a") &+ 10
    case UInt8(ascii: "A")...UInt8(ascii: "F"): digit &- UInt8(ascii: "A") &+ 10
    default: nil
    }
}

extension Data {
    /// Text of ASCII hex digits alone, after an optional `0x`, is read a byte
    /// at a time. Anything else takes the Character-wise parse, which is what
    /// defines the result: it counts Characters, and `UInt8(_:radix:)` also
    /// takes a sign (`+f`, `-0`). On ASCII hex digits the two agree.
    init?(hexString: String) {
        var digits = Substring(hexString).utf8
        if digits.starts(with: "0x".utf8) { digits = digits.dropFirst(2) }
        if digits.allSatisfy({ hexValue($0) != nil }) {
            guard digits.count % 2 == 0 else { return nil }
            var data = Data(count: digits.count / 2)
            data.withUnsafeMutableBytes { bytes in
                var index = digits.startIndex
                for offset in 0..<bytes.count {
                    let high = hexValue(digits[index])!
                    index = digits.index(after: index)
                    bytes[offset] = high << 4 | hexValue(digits[index])!
                    index = digits.index(after: index)
                }
            }
            self = data
            return
        }
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
        self = data
    }
}
