//
//  WBBrightMirrorModel.swift
//  WBBrightMirror
//
//  Created by 朴惠姝 on 2021/4/26.
//

import Foundation

public enum WBBMLogType: String {
    case Unknown = ""
    case SystemCrash = "109"
    case SystemDemoCrash = "109demo"
    case SystemWakeUp = "142"
    case SystemNewCrash = "309"
    case BuglyType = "bugly"
}

open class WBBMLogModel{
    public var logType: WBBMLogType = .Unknown
    public var processName: String = ""  //required
    public var processUUID: String = ""  //required
    public var version: String = ""
    public var detailModel: WBBMLogDetailModel!
    public var originalLogPath: URL!
    public var extendParams: Dictionary<String,Any> = [:]
    public var issueid: String = "" //bugly异常ID

    public init() {}
}

open class WBBMLogDetailModel{
    public var headerLogString: String = ""
    public var identifier: String = ""
    public var hardwareModel: String = ""
    public var processName: String = ""
    public var foundedAddress: Bool = true //正常情况下认为可以获取到进程的起始地址
    public var crashTime: String = ""
    public var launchTime: String = ""
    public var osVersion: String = ""
    public var exceptionType: String = ""
    public var terminationReason: String = ""
    public var terminationDescription: String = ""
    public var triggeredThread: String = ""
    public var threadInfoArray: Array<WBBMThreadInfoModel> = Array.init() //required

    public init() {}
}

open class WBBMThreadInfoModel{
    public var threadSequence: String = ""
    public var threadName: String = ""
    public var stackArray: Array<WBBMStackModel> = Array.init()

    public init() {}
}

open class WBBMStackModel{
    public var squence = 0;
    public var process: String = ""
    public var address: String = ""
    public var processStartAddress: String = ""
    public var processEndAddress: String = ""
    public var offset: String = ""
    public var analyzeResult: String = ""

    public init() {}
}
