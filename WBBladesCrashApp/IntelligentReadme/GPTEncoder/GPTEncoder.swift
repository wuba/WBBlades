//
//  GPTEncoder.swift
//  WBBladesCrashApp
//
//  Created by zengqinglong on 2023/6/2.
//

import Foundation

let bundle = GPTResourceBundle.resourceBundle

public final class GPTEncoder {
    
    public init() {}
    
    public private(set) var cache = GPTAtomicMap<String, String>()
    
    private let regex = try! NSRegularExpression(pattern: #"\'s|\'t|\'re|\'ve|\'m|\'ll|\'d| ?\p{L}+| ?\p{N}+| ?[^\s\p{L}\p{N}]+|\s+(?!\S)|\s+"#, options: .anchorsMatchLines)
    
    private let bpe: String = {
        let fileURL = bundle.url(forResource: "vocabulary", withExtension: "bpe")!
        let bpe = try! Data(contentsOf: fileURL)
        return String(data: bpe, encoding: .utf8)!
    }()
    
    private let encoder: [String: Int] = {
        let fileURL = bundle.url(forResource: "encoderBundle", withExtension: "json")!
        let jsonEncoderData = try! Data(contentsOf: fileURL)
        return try! JSONSerialization.jsonObject(with: jsonEncoderData) as! [String: Int]
    }()

    
    private lazy var decoder: [Int: String] = {
        var decoder: [Int: String] = [:]
        self.encoder.forEach({ key, value in
            decoder[value] = key
        })
        return decoder
    }()
    
    private lazy var bpeMerges: [[String]] = {
        let lines = self.bpe.split(separator: "\n").dropFirst()
        let bpeMerges = lines.map { (line) in
            String(line).split(separator: " ").map { String($0) }
                .filter { String($0).trimmingCharacters(in: .whitespacesAndNewlines).count > 0}
        }
        return bpeMerges
    }()
    
    private let byteEncoder: [Int: String] = {
        bytesToUnicode()
    }()
    
    private lazy var byteDecoder: [String: Int] = {
        var byteDecoder: [String: Int] = [:]
        self.byteEncoder.forEach({ key, value in
            byteDecoder[value] = key
        })
        return byteDecoder
    }()
    
    private lazy var bpeRanks: [[String]: Int] = {
        dictZip(x: bpeMerges, y: range(start: 0, end: bpeMerges.count))
    }()
    
    public func decode(tokens: [Int]) -> String {
        let text  = tokens.compactMap { token in decoder[token]}.joined(separator: "")
        let arrays = text.map { String($0) }.compactMap { byteDecoder[String($0)]}.map { UInt8($0) }
        return decodeString(array: arrays, byteEncoder: byteEncoder)
    }
    
    public func encode(text: String) -> [Int] {
        var bpe_tokens = [Int]()
        let matches = regex.matches(in: text, options: [], range: NSRange(text.startIndex..., in: text))
            .compactMap { match in
                if let range = Range(match.range, in: text) {
                    return String(text[range])
                } else {
                    return nil
                }
            }
        
        for match in matches {
            let token = encodeString(text: match).compactMap { byteEncoder[Int($0)] }.joined(separator: "")
            let bpe = bpe(token: token)
            let splits = bpe.split(separator: " ")
            let newTokens = splits.compactMap { self.encoder[String($0)]}
            bpe_tokens.append(contentsOf: newTokens)
        }
        return bpe_tokens
    }
        
    private func bpe(token: String) -> String {
        if let cachedToken = cache[token] {
            return cachedToken
        }
        var word = token.map { String($0) }
        var pairs = getPairs(words: word)
        
        if (pairs.isEmpty) {
            return token
        }
        
        while true {
            var minPairs: [Int: [String]] = [:]
            pairs.forEach{ pair in
                if let rank = bpeRanks[pair] ?? bpeRanks[pair.reversed()], !Double(rank).isNaN {
                    minPairs[rank] = pair
                } else {
                    minPairs[10_000_000] = pair
                }
            }
            
            let min = minPairs.map { v in v.key }.min() ?? -1
            let bigram = minPairs[min] ?? []
            
            if bpeRanks[bigram] == nil {
                break
            }
            
            let first = bigram[0]
            let second = bigram[1]
            var newWord = [String]()
            var i = 0
            
            while i < word.count {
                guard let j = word.dropFirst(i).firstIndex(of: first) else {
                    newWord.append(contentsOf: Array(word.suffix(from: i)))
                    break
                }
                newWord.append(contentsOf: Array(word.prefix(j).suffix(from: i)))
                i = Int(j)
                
                if (word[i] == first && i < word.count - 1 && word[i + 1] == second) {
                    newWord.append(first + second)
                    i += 2
                } else {
                    newWord.append(word[i])
                    i += 1
                }
            }
            
            word = newWord
            if word.count == 1 {
                break
            } else {
                pairs = getPairs(words: word)
            }
        }
        
        let finalWord = word.joined(separator: " ")
        cache[token] = finalWord
        return finalWord
    }
    
    public func clearCache() {
        self.cache = GPTAtomicMap<String, String>()
    }

}
