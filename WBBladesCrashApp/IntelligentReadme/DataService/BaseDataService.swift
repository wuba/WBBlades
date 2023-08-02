//
//  BaseDataService.swift
//  WBBladesCrashApp
//
//  Created by zengqinglong on 2023/6/7.
//

import Foundation

protocol BaseDataService {
    
    var dataURL: URL { get }
    
    func getData() -> Data?
    
    func saveData(data: Data?)
    
    func clear()
}

extension BaseDataService {
    
    func getData() -> Data? {
        do {
            return try Data(contentsOf: dataURL)
        } catch {
            print("get data occur error: \(error.localizedDescription)")
            return nil
        }
    }
    
    func saveData(data: Data?) {
        if let data = data {
            do {
                try data.write(to: dataURL, options: [.atomic])
            } catch {
                print("save data occur error: \(error.localizedDescription)")
            }
        }
    }
    
    func clear() {
        do {
            try FileManager.default.removeItem(at: dataURL)
        } catch {
            
        }
    }
}
