//
//  WBBladesCrashModel.swift
//  WBBladesCrash
//
//  Created by wbblades on 2021/4/26.
//

import Foundation

public enum WBBMLogType: String {
    case Unknown = ""                       // type unknown
    case SystemCrash = "109"                // normal crash type
    case SystemDemoCrash = "109demo"        // normal crash type, without header info
    case SystemWakeUp = "142"               // wake up crash type
    case SystemNewCrash = "309"             // json crash type(iOS 14+)
    case BuglyType = "bugly"                // bugly crash type
    case HuaweiType = "HuaweiType"                // Huawei crash type

}

open class WBBMLogModel{
    public var logType: WBBMLogType = .Unknown              // crash log type
    public var processName: String = ""                     // crash process name
    public var processUUID: String = ""                     // crash process uuid
    public var version: String = ""                         // crash process version
    public var detailModel: WBBMLogDetailModel!             // log model
    public var originalLogPath: URL!                        // crash log path in mac
    public var extendParams: Dictionary<String,Any> = [:]   // extend params
    public var issueid: String = ""                         // bugly type issu id

    public init() {}
}

open class WBBMLogDetailModel{
    public var headerLogString: String = ""                 //crash log header
    public var identifier: String = ""                      //process identifier
    public var processName: String = ""                     //process name
    public var foundedAddress: Bool = true                  //whether process base address is obtained.In the normal, the base address of the process can be obtained, but sometimes cannot
    public var crashTime: String = ""                       //application crash time
    public var launchTime: String = ""                      //application launch time
    public var hardwareModel: String = ""                   //device hardware
    public var osVersion: String = ""                       //device os version
    public var exceptionType: String = ""                   //crash exception type
    public var terminationReason: String = ""               //crash termination reason
    public var terminationDescription: String = ""          //crash termination description
    public var triggeredThread: String = ""                 //crash triggered thread
    public var threadInfoArray: Array<WBBMThreadInfoModel> = Array.init() //all thread stack of crash log

    public init() {}
}

open class WBBMThreadInfoModel{
    public var threadSequence: String = ""                      //thread sequence
    public var threadName: String = ""                          //thread name
    public var stackArray: Array<WBBMStackModel> = Array.init() //stacks of the thread

    public init() {}
}

open class WBBMStackModel{
    public var squence = 0;                                     //original squence
    public var library: String = ""                             //which library the class belongs to
    public var address: String = ""                             //stack real address
    public var libraryStartAddress: String = ""                 //the begin address of library
    public var libraryEndAddress: String = ""                   //the end address of library
    public var offset: String = ""                              //stack offset
    public var analyzeResult: String = ""                       //the result of analyzing

    public init() {}
}
