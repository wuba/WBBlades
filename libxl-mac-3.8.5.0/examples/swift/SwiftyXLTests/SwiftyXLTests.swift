//
//  SwiftyXLTests.swift
//  SwiftyXLTests
//
//  Created by Dmitry Rodionov on 18/10/2016.
//  Copyright © 2016 Internals Exposed. All rights reserved.
//

import Foundation
import XCTest

class SwiftyXLTestCase: XCTestCase
{

    func sampleBook(named name: String) -> String?
    {
        return path(forTestResource: (name as NSString).deletingPathExtension,
                    type: (name as NSString).pathExtension)
    }

    func samplePicture(named name: String) -> String?
    {
        return path(forTestResource: name, type: "png")
    }



    func path(forTestResource resource: String, type: String?) -> String?
    {
        let bundle = Bundle(for: SwiftyXLTestCase.self)
        return bundle.path(forResource: resource, ofType: type)
    }

    func path(forTemporaryFile filename: String) -> String
    {
        return (temporaryDirectory() as NSString).appendingPathComponent(filename)
    }

    private func temporaryDirectory() -> String
    {
        let directory = (NSTemporaryDirectory() as NSString).appendingPathComponent("SwiftyXLTests")
        try! FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true, attributes: nil)
        return directory
    }

    func cleanupTemporaryFiles()
    {
        try! FileManager.default.removeItem(atPath: temporaryDirectory())
    }
}


