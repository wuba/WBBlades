//
//  WBBMScanLogModel.swift
//  WBBladesCrash
//
//  Created by 朴惠姝 on 2021/4/27.
//

import Foundation

enum WBBMSystemLogEndLine: String{
    case BrinaryImages = "Binary Images:"
    case CrashedWithArm64State = "crashed with ARM Thread State (64-bit):"
    case CrashedWithArm32State = "crashed with ARM Thread State (32-bit):"
    case WakeUpPowerStats = "Powerstats for:"
}

class WBBMSystemLogNewTypeLibraryModel{
    public var libraryName: String = ""
    public var libraryStartAddress: String = ""
    public var libraryEndAddress: String = ""
    
    public init() {}
}
