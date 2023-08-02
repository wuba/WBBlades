//
//  GPTAtomicMap.swift
//  WBBladesCrashApp
//
//  Created by zengqinglong on 2023/6/2.
//

import Foundation


public class GPTAtomicMap<Key: Hashable, Value>: CustomDebugStringConvertible {
    private var dictStorage = [Key: Value]()
    
    private let queue = DispatchQueue(label: "com.swiftgptencoder.atomic", qos: .utility, attributes: .concurrent,
                                      autoreleaseFrequency: .inherit, target: .global())
    
    public init() {}
    
    public subscript(key: Key) -> Value? {
        get { queue.sync { dictStorage[key] }}
        set { queue.async(flags: .barrier) { [weak self] in self?.dictStorage[key] = newValue } }
    }
    
    public var debugDescription: String {
        return dictStorage.debugDescription
    }
}
