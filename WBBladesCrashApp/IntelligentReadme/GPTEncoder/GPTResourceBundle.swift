//
//  GPTResourceBundle.swift
//  WBBladesCrashApp
//
//  Created by zengqinglong on 2023/6/2.
//

import Foundation

public final class GPTResourceBundle {
    public static let resourceBundle: Bundle = {
        let candidates = [
            Bundle.main.resourceURL,

            Bundle(for: GPTResourceBundle.self).resourceURL,
        ]

        let bundleName = "GPTEncoder_GPTEncoder"

        for candidate in candidates {
            let bundlePath = candidate?.appendingPathComponent(bundleName + ".bundle")
            if let bundle = bundlePath.flatMap(Bundle.init(url:)) {
                return bundle
            }
        }

        return Bundle(for: GPTResourceBundle.self)
    }()
}
