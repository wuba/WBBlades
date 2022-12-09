//
//  WBBMScanLogModel.swift
//  WBBladesCrash
//
//  Created by wbblades on 2021/4/27.
//

import Foundation

enum WBBMSystemLogEndLine: String{
    case BrinaryImages = "Binary Images:"
    case CrashedWithArm64State = "crashed with ARM Thread State (64-bit):"
    case CrashedWithArm32State = "crashed with ARM Thread State (32-bit):"
    case WakeUpPowerStats = "Powerstats for:"
}

class WBBMSystemLogNewTypeLibraryModel{
    public var libraryName: String = ""                     //library name in system crash log
    public var libraryStartAddress: String = ""             //the start address of library in system crash log
    public var libraryEndAddress: String = ""               //the end address of library in system crash log
    
    public init() {}
}
