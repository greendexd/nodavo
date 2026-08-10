import Foundation

enum StrictJSONDuplicateKeyValidator {
    static let maximumBytes = 64 * 1024
    static let maximumDepth = 64

    enum ValidationError: Error {
        case duplicateKey
        case malformed
        case tooDeep
        case tooLarge
    }

    static func validate(_ data: Data) throws {
        guard !data.isEmpty, data.count <= maximumBytes else {
            throw ValidationError.tooLarge
        }
        var parser = Parser(bytes: Array(data))
        try parser.parseValue(depth: 0)
        parser.skipWhitespace()
        guard parser.isAtEnd else { throw ValidationError.malformed }
    }

    private struct Parser {
        let bytes: [UInt8]
        let keyDecoder = JSONDecoder()
        var index = 0

        var isAtEnd: Bool { index == bytes.count }

        mutating func parseValue(depth: Int) throws {
            skipWhitespace()
            guard index < bytes.count else { throw ValidationError.malformed }
            switch bytes[index] {
            case 0x7B: // {
                guard depth < maximumDepth else { throw ValidationError.tooDeep }
                try parseObject(depth: depth + 1)
            case 0x5B: // [
                guard depth < maximumDepth else { throw ValidationError.tooDeep }
                try parseArray(depth: depth + 1)
            case 0x22: // "
                _ = try parseStringRange()
            default:
                try parsePrimitive()
            }
        }

        mutating func parseObject(depth: Int) throws {
            try consume(0x7B)
            skipWhitespace()
            if consumeIfPresent(0x7D) { return }

            var keys = Set<String>()
            while true {
                skipWhitespace()
                guard index < bytes.count, bytes[index] == 0x22 else {
                    throw ValidationError.malformed
                }
                let range = try parseStringRange()
                let key: String
                do {
                    key = try keyDecoder.decode(String.self, from: Data(bytes[range]))
                } catch {
                    throw ValidationError.malformed
                }
                guard keys.insert(key).inserted else {
                    throw ValidationError.duplicateKey
                }

                skipWhitespace()
                try consume(0x3A) // :
                try parseValue(depth: depth)
                skipWhitespace()
                if consumeIfPresent(0x7D) { return }
                try consume(0x2C) // ,
            }
        }

        mutating func parseArray(depth: Int) throws {
            try consume(0x5B)
            skipWhitespace()
            if consumeIfPresent(0x5D) { return }
            while true {
                try parseValue(depth: depth)
                skipWhitespace()
                if consumeIfPresent(0x5D) { return }
                try consume(0x2C)
            }
        }

        mutating func parseStringRange() throws -> Range<Int> {
            let start = index
            try consume(0x22)
            while index < bytes.count {
                let byte = bytes[index]
                index += 1
                if byte == 0x22 {
                    return start ..< index
                }
                if byte == 0x5C {
                    guard index < bytes.count else { throw ValidationError.malformed }
                    index += 1
                } else if byte < 0x20 {
                    throw ValidationError.malformed
                }
            }
            throw ValidationError.malformed
        }

        mutating func parsePrimitive() throws {
            let start = index
            while index < bytes.count {
                switch bytes[index] {
                case 0x09, 0x0A, 0x0D, 0x20, 0x2C, 0x5D, 0x7D:
                    guard index > start else { throw ValidationError.malformed }
                    return
                case 0x22, 0x5B, 0x7B:
                    throw ValidationError.malformed
                default:
                    index += 1
                }
            }
            guard index > start else { throw ValidationError.malformed }
        }

        mutating func skipWhitespace() {
            while index < bytes.count {
                switch bytes[index] {
                case 0x09, 0x0A, 0x0D, 0x20:
                    index += 1
                default:
                    return
                }
            }
        }

        mutating func consume(_ expected: UInt8) throws {
            guard index < bytes.count, bytes[index] == expected else {
                throw ValidationError.malformed
            }
            index += 1
        }

        mutating func consumeIfPresent(_ expected: UInt8) -> Bool {
            guard index < bytes.count, bytes[index] == expected else { return false }
            index += 1
            return true
        }
    }
}
