//
//  EncoderUtils.swift
//  WBBladesCrashApp
//
//  Created by zengqinglong on 2023/6/2.
//

import Foundation

func range(start: Int, end: Int) -> [Int] {
    (start..<end).toArray
}

func dictZip(x: [[String]], y: [Int]) -> [[String]: Int] {
    var result = [[String]: Int]()
    x.enumerated().forEach{ (i, e) in
        result[x[i]] = y[i]
        
    }
    return result
        
}

func bytesToUnicode() -> [Int: String] {
    var bs = range(start: "!".ord!, end: "~".ord! + 1)
            + range(start: "¡".ord!, end: "¬".ord! + 1)
            + range(start: "®".ord!, end: "ÿ".ord! + 1)
    var cs = bs
    var n = 0
    var b = 0
    while (b < Int(pow(2.0, 8))) {
        if bs.firstIndex(of: b) == nil {
            bs.append(b)
            cs.append(Int(pow(2.0, 8)) + n)
            n += 1
        }
        b += 1
    }
 
    let charCodes = cs.map { "\($0)".fromCharCode! }
    var result = [Int: String]()
    bs.enumerated().forEach { i, _ in
        result[bs[i]] = charCodes[i]
    }
    return result
}


func getPairs(words: [String]) -> Set<[String]> {
    var pairs = Set<[String]>()
    var prevChar = words[0]
    (1..<words.count).enumerated().forEach { _, i in
        let char = words[i]
        pairs.insert([prevChar, char])
        prevChar = char
    }
    return pairs
}

func encodeString(text: String) -> [UInt8] {
    return Array(text.utf8)
}

func decodeString(array: [UInt8], byteEncoder: [Int: String]) -> String {
    String(bytes: array, encoding: .isoLatin1) ?? ""
}
