//
//  WBBMScanLogModel.swift
//  WBBrightMirror
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

class WBBMSystemLogNewTypeProcessModel{
    public var processName: String = ""
    public var processStartAddress: String = ""
    public var processEndAddress: String = ""
    
    public init() {}
}
