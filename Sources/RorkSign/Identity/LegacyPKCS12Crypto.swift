#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
import Foundation

/// PKCS#12 v1.0 password-based key derivation.
///
/// Legacy `.p12` files do not use PBKDF2. They use the PKCS#12 SHA-1 KDF with
/// different diversifier bytes for keys and IVs. The password input is a
/// big-endian BMPString terminated by two zero bytes.
enum LegacyPKCS12KDF {
    enum Purpose: UInt8 {
        case key = 1
        case iv = 2
        case mac = 3
    }

    enum HashAlgorithm {
        case sha1
        case sha256
        case sha384
        case sha512

        var digestByteCount: Int {
            switch self {
            case .sha1:
                return 20
            case .sha256:
                return 32
            case .sha384:
                return 48
            case .sha512:
                return 64
            }
        }

        var blockByteCount: Int {
            switch self {
            case .sha1, .sha256:
                return 64
            case .sha384, .sha512:
                return 128
            }
        }

        func digest(_ data: Data) -> Data {
            switch self {
            case .sha1:
                return Data(Insecure.SHA1.hash(data: data))
            case .sha256:
                return Data(SHA256.hash(data: data))
            case .sha384:
                return Data(SHA384.hash(data: data))
            case .sha512:
                return Data(SHA512.hash(data: data))
            }
        }

        func authenticationCode(for data: Data, key: SymmetricKey) -> Data {
            switch self {
            case .sha1:
                return Data(HMAC<Insecure.SHA1>.authenticationCode(for: data, using: key))
            case .sha256:
                return Data(HMAC<SHA256>.authenticationCode(for: data, using: key))
            case .sha384:
                return Data(HMAC<SHA384>.authenticationCode(for: data, using: key))
            case .sha512:
                return Data(HMAC<SHA512>.authenticationCode(for: data, using: key))
            }
        }
    }

    static func passwordBytes(_ password: String) -> Data {
        var output = Data()
        for codeUnit in password.utf16 {
            output.append(UInt8(codeUnit >> 8))
            output.append(UInt8(codeUnit & 0xff))
        }
        output.append(contentsOf: [0x00, 0x00])
        return output
    }

    static func derive(
        password: Data,
        salt: Data,
        id: Purpose,
        iterations: Int,
        outputByteCount: Int,
        hashAlgorithm: HashAlgorithm = .sha1
    ) -> Data {
        let v = hashAlgorithm.blockByteCount
        let diversifier = Data(repeating: id.rawValue, count: v)
        var input = repeatToMultiple(salt, blockSize: v) + repeatToMultiple(password, blockSize: v)
        var output = Data()

        while output.count < outputByteCount {
            var digestInput = diversifier + input
            var a = hashAlgorithm.digest(digestInput)
            if iterations > 1 {
                for _ in 1..<iterations {
                    a = hashAlgorithm.digest(a)
                }
            }
            output.append(a)

            let b = repeatToLength(a, count: v)
            guard !input.isEmpty else {
                continue
            }
            for offset in stride(from: 0, to: input.count, by: v) {
                addOnePlus(input: &input, blockOffset: offset, blockSize: v, value: b)
            }
            digestInput.removeAll(keepingCapacity: false)
        }

        return output.prefixData(outputByteCount)
    }

    /// Repeats `data` to the next non-zero multiple of `blockSize`.
    private static func repeatToMultiple(_ data: Data, blockSize: Int) -> Data {
        guard !data.isEmpty else {
            return Data()
        }
        let count = ((data.count + blockSize - 1) / blockSize) * blockSize
        return repeatToLength(data, count: count)
    }

    private static func repeatToLength(_ data: Data, count: Int) -> Data {
        guard !data.isEmpty, count > 0 else {
            return Data()
        }
        var output = Data()
        output.reserveCapacity(count)
        while output.count < count {
            output.append(data.prefixData(min(data.count, count - output.count)))
        }
        return output
    }

    /// Adds `value + 1` to one big-endian `input` block modulo 2^(8*blockSize).
    private static func addOnePlus(input: inout Data, blockOffset: Int, blockSize: Int, value: Data) {
        var carry = 1
        for index in stride(from: blockSize - 1, through: 0, by: -1) {
            let inputIndex = blockOffset + index
            let sum = Int(input[inputIndex]) + Int(value[index]) + carry
            input[inputIndex] = UInt8(sum & 0xff)
            carry = sum >> 8
        }
    }
}

/// Triple-DES CBC with PKCS#7 padding removal.
enum TripleDESCBC {
    static func decrypt(_ ciphertext: Data, key: Data, iv: Data) throws -> Data {
        guard (key.count == 16 || key.count == 24), iv.count == 8 else {
            throw RorkSignError.invalidSigningIdentity("3DES-CBC key or IV has an invalid size.")
        }
        guard ciphertext.count > 0, ciphertext.count.isMultiple(of: 8) else {
            throw RorkSignError.invalidSigningIdentity("3DES-CBC ciphertext has an invalid size.")
        }

        let k1 = DES(key: key.subdata(in: 0..<8))
        let k2 = DES(key: key.subdata(in: 8..<16))
        let k3 = key.count == 16
            ? k1
            : DES(key: key.subdata(in: 16..<24))
        var previous = bytesToUInt64(iv)
        var plaintext = Data()
        plaintext.reserveCapacity(ciphertext.count)

        for offset in stride(from: 0, to: ciphertext.count, by: 8) {
            let block = bytesToUInt64(ciphertext.subdata(in: offset..<(offset + 8)))
            let decrypted = k1.decrypt(k2.encrypt(k3.decrypt(block))) ^ previous
            plaintext.appendUInt64BE(decrypted)
            previous = block
        }
        try plaintext.removePKCS7Padding(blockSize: 8)
        return plaintext
    }
}

/// DES CBC with PKCS#7 padding removal.
enum DESCBC {
    static func decrypt(_ ciphertext: Data, key: Data, iv: Data) throws -> Data {
        guard key.count == 8, iv.count == 8 else {
            throw RorkSignError.invalidSigningIdentity("DES-CBC key or IV has an invalid size.")
        }
        guard ciphertext.count > 0, ciphertext.count.isMultiple(of: 8) else {
            throw RorkSignError.invalidSigningIdentity("DES-CBC ciphertext has an invalid size.")
        }

        let des = DES(key: key)
        var previous = bytesToUInt64(iv)
        var plaintext = Data()
        plaintext.reserveCapacity(ciphertext.count)

        for offset in stride(from: 0, to: ciphertext.count, by: 8) {
            let block = bytesToUInt64(ciphertext.subdata(in: offset..<(offset + 8)))
            let decrypted = des.decrypt(block) ^ previous
            plaintext.appendUInt64BE(decrypted)
            previous = block
        }
        try plaintext.removePKCS7Padding(blockSize: 8)
        return plaintext
    }
}

/// RC2 CBC with PKCS#7 padding removal.
enum RC2CBC {
    static func decrypt(_ ciphertext: Data, key: Data, effectiveKeyBits: Int, iv: Data) throws -> Data {
        guard iv.count == 8 else {
            throw RorkSignError.invalidSigningIdentity("RC2-CBC IV has an invalid size.")
        }
        guard ciphertext.count > 0, ciphertext.count.isMultiple(of: 8) else {
            throw RorkSignError.invalidSigningIdentity("RC2-CBC ciphertext has an invalid size.")
        }

        let rc2 = try RC2(key: key, effectiveKeyBits: effectiveKeyBits)
        var previous = Array(iv)
        var plaintext = Data()
        plaintext.reserveCapacity(ciphertext.count)

        for offset in stride(from: 0, to: ciphertext.count, by: 8) {
            let block = Array(ciphertext[offset..<(offset + 8)])
            let decrypted = try rc2.decryptBlock(block)
            plaintext.append(contentsOf: zip(decrypted, previous).map { $0 ^ $1 })
            previous = block
        }
        try plaintext.removePKCS7Padding(blockSize: 8)
        return plaintext
    }
}

/// DES block cipher used only for legacy PKCS#12 3DES-CBC import.
private struct DES {
    private let subkeys: [UInt64]

    init(key: Data) {
        subkeys = DES.makeSubkeys(bytesToUInt64(key))
    }

    func encrypt(_ block: UInt64) -> UInt64 {
        crypt(block, subkeys: subkeys)
    }

    func decrypt(_ block: UInt64) -> UInt64 {
        crypt(block, subkeys: subkeys.reversed())
    }

    private func crypt<S: Sequence>(_ block: UInt64, subkeys: S) -> UInt64 where S.Element == UInt64 {
        let permuted = Self.permute(block, table: Self.initialPermutation, inputBitCount: 64)
        var left = UInt32(permuted >> 32)
        var right = UInt32(permuted & 0xffff_ffff)

        for subkey in subkeys {
            let nextLeft = right
            right = left ^ Self.feistel(right, subkey: subkey)
            left = nextLeft
        }

        let preoutput = (UInt64(right) << 32) | UInt64(left)
        return Self.permute(preoutput, table: Self.finalPermutation, inputBitCount: 64)
    }

    private static func makeSubkeys(_ key: UInt64) -> [UInt64] {
        let permuted = permute(key, table: pc1, inputBitCount: 64)
        var c = UInt32((permuted >> 28) & 0x0fff_ffff)
        var d = UInt32(permuted & 0x0fff_ffff)
        var subkeys: [UInt64] = []
        subkeys.reserveCapacity(16)

        for shift in rotations {
            c = rotateLeft28(c, by: shift)
            d = rotateLeft28(d, by: shift)
            subkeys.append(permute((UInt64(c) << 28) | UInt64(d), table: pc2, inputBitCount: 56))
        }
        return subkeys
    }

    private static func feistel(_ value: UInt32, subkey: UInt64) -> UInt32 {
        let expanded = permute(UInt64(value), table: expansion, inputBitCount: 32) ^ subkey
        var substituted: UInt32 = 0
        for index in 0..<8 {
            let chunk = UInt8((expanded >> UInt64(42 - index * 6)) & 0x3f)
            let row = Int(((chunk & 0x20) >> 4) | (chunk & 0x01))
            let column = Int((chunk >> 1) & 0x0f)
            substituted = (substituted << 4) | UInt32(sboxes[index][row * 16 + column])
        }
        return UInt32(permute(UInt64(substituted), table: permutation, inputBitCount: 32))
    }

    private static func permute(_ value: UInt64, table: [UInt8], inputBitCount: Int) -> UInt64 {
        var output: UInt64 = 0
        for position in table {
            output <<= 1
            output |= (value >> UInt64(inputBitCount - Int(position))) & 1
        }
        return output
    }

    private static func rotateLeft28(_ value: UInt32, by count: UInt8) -> UInt32 {
        ((value << UInt32(count)) | (value >> UInt32(28 - count))) & 0x0fff_ffff
    }

    private static let rotations: [UInt8] = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

    private static let initialPermutation: [UInt8] = [
        58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
    ]

    private static let finalPermutation: [UInt8] = [
        40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
    ]

    private static let expansion: [UInt8] = [
        32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9,
        8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
    ]

    private static let permutation: [UInt8] = [
        16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
        2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25,
    ]

    private static let pc1: [UInt8] = [
        57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4,
    ]

    private static let pc2: [UInt8] = [
        14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
        23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
    ]

    private static let sboxes: [[UInt8]] = [
        [14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13],
        [15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9],
        [10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12],
        [7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14],
        [2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3],
        [12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13],
        [4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12],
        [13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11],
    ]
}

/// RC2 block cipher used only for legacy PKCS#12 RC2-CBC import.
private struct RC2 {
    private let keys: [UInt16]

    init(key: Data, effectiveKeyBits: Int) throws {
        guard (1...1024).contains(effectiveKeyBits), (1...128).contains(key.count) else {
            throw RorkSignError.invalidSigningIdentity("RC2 key parameters are invalid.")
        }
        keys = Self.expandKey(Array(key), effectiveKeyBits: effectiveKeyBits)
    }

    func decryptBlock(_ block: [UInt8]) throws -> [UInt8] {
        guard block.count == 8 else {
            throw RorkSignError.invalidSigningIdentity("RC2 block has an invalid size.")
        }
        var r0 = UInt16(block[0]) | (UInt16(block[1]) << 8)
        var r1 = UInt16(block[2]) | (UInt16(block[3]) << 8)
        var r2 = UInt16(block[4]) | (UInt16(block[5]) << 8)
        var r3 = UInt16(block[6]) | (UInt16(block[7]) << 8)
        var j = 63

        for round in stride(from: 15, through: 0, by: -1) {
            if round == 10 || round == 4 {
                r3 &-= keys[Int(r2 & 63)]
                r2 &-= keys[Int(r1 & 63)]
                r1 &-= keys[Int(r0 & 63)]
                r0 &-= keys[Int(r3 & 63)]
            }

            r3 = Self.rotateRight(r3, by: 5)
            r3 &-= (r0 & ~r2) &+ (r1 & r2) &+ keys[j]
            j -= 1
            r2 = Self.rotateRight(r2, by: 3)
            r2 &-= (r3 & ~r1) &+ (r0 & r1) &+ keys[j]
            j -= 1
            r1 = Self.rotateRight(r1, by: 2)
            r1 &-= (r2 & ~r0) &+ (r3 & r0) &+ keys[j]
            j -= 1
            r0 = Self.rotateRight(r0, by: 1)
            r0 &-= (r1 & ~r3) &+ (r2 & r3) &+ keys[j]
            j -= 1
        }

        return [r0, r1, r2, r3].flatMap { [UInt8($0 & 0xff), UInt8($0 >> 8)] }
    }

    private static func expandKey(_ key: [UInt8], effectiveKeyBits: Int) -> [UInt16] {
        var expanded = Array(repeating: UInt8(0), count: 128)
        for index in key.indices {
            expanded[index] = key[index]
        }
        for index in key.count..<128 {
            expanded[index] = piTable[Int(expanded[index - 1] &+ expanded[index - key.count])]
        }

        let t8 = (effectiveKeyBits + 7) / 8
        let mask = UInt8(255 >> (8 * t8 - effectiveKeyBits))
        expanded[128 - t8] = piTable[Int(expanded[128 - t8] & mask)]
        if 128 - t8 > 0 {
            for index in stride(from: 127 - t8, through: 0, by: -1) {
                expanded[index] = piTable[Int(expanded[index + 1] ^ expanded[index + t8])]
            }
        }

        return stride(from: 0, to: 128, by: 2).map { index in
            UInt16(expanded[index]) | (UInt16(expanded[index + 1]) << 8)
        }
    }

    private static func rotateRight(_ value: UInt16, by count: UInt16) -> UInt16 {
        (value >> count) | (value << (16 - count))
    }

    private static let piTable: [UInt8] = [
        217,120,249,196,25,221,181,237,40,233,253,121,74,160,216,157,
        198,126,55,131,43,118,83,142,98,76,100,136,68,139,251,162,
        23,154,89,245,135,179,79,19,97,69,109,141,9,129,125,50,
        189,143,64,235,134,183,123,11,240,149,33,34,92,107,78,130,
        84,214,101,147,206,96,178,28,115,86,192,20,167,140,241,220,
        18,117,202,31,59,190,228,209,66,61,212,48,163,60,182,38,
        111,191,14,218,70,105,7,87,39,242,29,155,188,148,67,3,
        248,17,199,246,144,239,62,231,6,195,213,47,200,102,30,215,
        8,232,234,222,128,82,238,247,132,170,114,172,53,77,106,42,
        150,26,210,113,90,21,73,116,75,159,208,94,4,24,164,236,
        194,224,65,110,15,81,203,204,36,145,175,80,161,244,112,57,
        153,124,58,133,35,184,180,122,252,2,54,91,37,85,151,49,
        45,93,250,152,227,138,146,174,5,223,41,16,103,108,186,201,
        211,0,230,207,225,158,168,44,99,22,1,63,88,226,137,169,
        13,56,52,27,171,51,255,176,187,72,12,95,185,177,205,46,
        197,243,219,71,229,165,156,119,10,166,32,104,254,127,193,173,
    ]
}

/// RC4 stream cipher used only for legacy PKCS#12 RC4 PBE import.
enum RC4 {
    /// Decrypts `ciphertext` with RC4.
    ///
    /// RC4 encryption and decryption are the same XOR operation over the
    /// generated keystream. PKCS#12 uses RC4 only in legacy PBE algorithms; the
    /// key material is produced by `LegacyPKCS12KDF` before reaching this type.
    static func decrypt(_ ciphertext: Data, key: Data) throws -> Data {
        guard (1...256).contains(key.count) else {
            throw RorkSignError.invalidSigningIdentity("RC4 key has an invalid size.")
        }

        var state = Array(UInt8.min...UInt8.max)
        var j = 0
        for i in 0..<256 {
            j = (j + Int(state[i]) + Int(key[i % key.count])) & 0xff
            state.swapAt(i, j)
        }

        var i = 0
        j = 0
        var output = Data()
        output.reserveCapacity(ciphertext.count)
        for byte in ciphertext {
            i = (i + 1) & 0xff
            j = (j + Int(state[i])) & 0xff
            state.swapAt(i, j)
            let keyByte = state[(Int(state[i]) + Int(state[j])) & 0xff]
            output.append(byte ^ keyByte)
        }
        return output
    }
}

private func bytesToUInt64(_ data: Data) -> UInt64 {
    data.reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
}

private extension Data {
    mutating func removePKCS7Padding(blockSize: Int) throws {
        guard let padding = last,
              padding > 0,
              padding <= blockSize,
              count >= Int(padding),
              suffix(Int(padding)).allSatisfy({ $0 == padding }) else {
            throw RorkSignError.invalidSigningIdentity("Invalid PKCS#7 padding.")
        }
        removeLast(Int(padding))
    }

    func prefixData(_ count: Int) -> Data {
        Data(prefix(count))
    }
}
