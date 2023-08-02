//
//  GPTMsgModels.swift
//  WBBladesCrashApp
//
//  Created by zengqinglong on 2023/6/2.
//


import Foundation

public struct BaseReqMessage: Codable {
    public let role: String
    public let content: String
    
    public init(role: String, content: String) {
        self.role = role
        self.content = content
    }
    
}

public struct Message: Codable {
    var baseReqMsg: BaseReqMessage
    var responseError: String?
    lazy var textHeight: CGFloat = {
        return Message.getTextHeigh(textStr: self.messageContent)
    }()
    lazy var messageContent: String = {
        if (self.responseError == nil) {
            return self.baseReqMsg.content
        }
        else {
            return self.responseError ?? ""
        }
    }()
    public init(role: String, content: String) {
        self.baseReqMsg = BaseReqMessage(role: role, content: content)
    }
    
    public init(baseMsg: BaseReqMessage) {
        self.baseReqMsg = baseMsg
    }
    
    
}

extension Message {
    static func getTextHeigh(textStr: String) -> CGFloat{
        let normalText : NSString = textStr as NSString
        let font = NSFont.systemFont(ofSize: 13)
        let size = CGSize(width: 700, height:1000)
        let dic = NSDictionary(object: font, forKey : kCTFontAttributeName as! NSCopying)
        let stringSize = normalText.boundingRect(with: size, options: .usesLineFragmentOrigin, attributes: dic as? [NSAttributedString.Key:Any], context:nil).size
        return stringSize.height
    }
}

extension Array where Element == BaseReqMessage {
    
    var contentCount: Int { self.count }
    var content: String { reduce("") { $0 + $1.content } }
}

struct Request: Codable {
    let model: String
    let temperature: Double
    let messages: [BaseReqMessage]
    let stream: Bool
}

struct ErrorRootResponse: Decodable {
    let error: ErrorResponse
}

struct ErrorResponse: Decodable {
    let message: String
    let type: String?
}

struct CompletionResponse: Decodable {
    let choices: [Choice]
    let usage: Usage?
}

struct Usage: Decodable {
    let promptTokens: Int?
    let completionTokens: Int?
    let totalTokens: Int?
}

struct Choice: Decodable {
    let finishReason: String?
    let message: BaseReqMessage
}

//struct StreamCompletionResponse: Decodable {
//    let choices: [StreamChoice]
//}
//
//struct StreamChoice: Decodable {
//    let finishReason: String?
//    let delta: StreamMessage
//}
//
//struct StreamMessage: Decodable {
//    let content: String?
//    let role: String?
//}

