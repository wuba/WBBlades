//
//  Picture.swift
//  SwiftyXL
//
//  Created by Dmitry Rodionov on 18/10/2016.
//  Copyright © 2016 Internals Exposed. All rights reserved.
//

import Foundation
import Libxl

public enum PictureType {
    case PNG
    case JPEG
    case WMF
    case DIB
    case EMF
    case TIFF
    case Error

    static func from(rawValue raw: Int32) -> PictureType
    {
        switch raw {
        case Int32(PICTURETYPE_PNG.rawValue):  return .PNG
        case Int32(PICTURETYPE_JPEG.rawValue): return .JPEG
        case Int32(PICTURETYPE_WMF.rawValue):  return .WMF
        case Int32(PICTURETYPE_DIB.rawValue):  return .DIB
        case Int32(PICTURETYPE_EMF.rawValue):  return .EMF
        case Int32(PICTURETYPE_TIFF.rawValue): return .TIFF
        default:
            return .Error
        }
    }
}

public typealias PictureIdentiifer = Int


public class Picture {
    public let type: PictureType
    public let data: Data

    public init(type: PictureType, data: Data)
    {
        self.type = type
        self.data = data
    }
}
