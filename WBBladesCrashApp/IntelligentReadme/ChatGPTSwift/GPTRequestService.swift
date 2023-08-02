//
//  GPTRequestService.swift
//  WBBladesCrashApp
//
//  Created by zengqinglong on 2023/6/2.
//

import Foundation
import os

public class GPTRequestService: @unchecked Sendable {
    
    public enum Constants {
        public static let defaultModel = "gpt-3.5-turbo"
        public static let defaultSystemText = "WBBlades是基于Mach-O文件解析的工具集，包括App一键体检（支持OC和Swift的无用类检测）、包大小分析（支持单个静态库/动态库的包大小分析）、点对点崩溃解析（基于系统日志，支持有符号状态和无符号状态）、基于Mach-O的Class自动提取并Hook能力。"
        + "WBBlades主要利用了__Text汇编代码分析、架构提取、符号表剥离、dYSM文件提取、崩溃文件(ips)解析等技术手段实现，支持big method /small method 解析 以及 iOS 15以上关于 dyld_chained_fixups的处理。"
        + "WBBlades提供了可视化和cli两种方式进行使用。可视化方式选择target WBBladesCrashApp直接操作即可，具体可参考文章https://mp.weixin.qq.com/s/QFtlp0sG4eJRZ7NrDMAopw。对于cli方式，如下使用方法："
           + "一键诊断：blades -diagnose xxx.app"
           + "无用代码检测：blades -unused xxx.app"
           + "包大小分析：blades -size xxx.a"
           + "无符号表日志符号化：blades -symbol xxx.app -logPath xxx.ips"
           + "WBBlades无用类检测有一些限制，比如，OC类名是字符串拼接，进行runtime动态调用如NSClassFromString(@\"My\" + @\"Class\")这种情况下检测不出来。再一种是Swift容器中作为类型声明，如var array:[MyClass]也检测不出来。"
           + "WBBlades提供了反馈和交流渠道，开发者可以通过提交PR或者Issue来反馈建议和问题，也可以添加微信号\"zqlong320\"来和项目负责人直接线上交流。"
        public static let defaultTemperature = 0.5
    }
    
    private let urlString = "https://api.openai.com/v1/chat/completions"
    private let gptEncoder = GPTEncoder()
    public private(set) var historyList = [Message]()
    public private(set) var requestHistoryList = [BaseReqMessage]()

    private var isSaveHistory: Bool = true
//    private var logger: Logger = .init(subsystem: "ChatGPT", category: "ViewModel")

    let dateFormatter: DateFormatter = {
        let df = DateFormatter()
        df.dateFormat = "YYYY-MM-dd"
        return df
    }()
    
    private let jsonDecoder: JSONDecoder = {
        let jsonDecoder = JSONDecoder()
        jsonDecoder.keyDecodingStrategy = .convertFromSnakeCase
        return jsonDecoder
    }()
    
    private var headers: [String: String] {
        [
            "Content-Type": "application/json",
            "Authorization": "Bearer \(apiKey())"
        ]
    }
    
    func apiKey() -> String {
        return UserDefaults().value(forKey: "GPT_API_KEY") as? String ?? ""
    }
    private func systemMessage(content: String) -> BaseReqMessage {
        .init(role: "system", content: content)
    }
    
    public init() {
        if (!self.apiKey().isEmpty) {
            self.fetchMessageData()
        }
    }
    
    private func generateMessages(from text: String, systemText: String) -> [BaseReqMessage] {
        if requestHistoryList.count == 0 {
            requestHistoryList = historyList.map({$0.baseReqMsg})
        }
        var messages = [systemMessage(content: systemText)] + requestHistoryList + [BaseReqMessage.init(role: "user", content: text)]
        if gptEncoder.encode(text: messages.content).count > 4096  {
            _ = requestHistoryList.removeFirst()
            messages = generateMessages(from: text, systemText: systemText)
        }
        return messages
    }
    
    private func chatJsonBody(text: String) throws -> Data {
        let request = Request(model: GPTRequestService.Constants.defaultModel,
                        temperature: GPTRequestService.Constants.defaultTemperature,
                        messages: generateMessages(from: text, systemText: GPTRequestService.Constants.defaultSystemText),
                        stream: false)
        return try JSONEncoder().encode(request)
    }
    
    private func checkJsonBody() throws -> Data {
        let msgs: [BaseReqMessage] = [.init(role: "user", content: "Hello!")]
        let request = Request(model: GPTRequestService.Constants.defaultModel,
                        temperature: GPTRequestService.Constants.defaultTemperature,
                        messages: msgs,
                        stream: false)
        return try JSONEncoder().encode(request)
    }
    
    public func appendToHistoryList(userText: String) {
        self.historyList.append(Message(role: "user", content: userText))
        self.saveMessageData()
    }
    
    public func appendToHistoryList(responseText: String, errorText: String?) {
        var resp: Message = .init(role: "assistant", content: responseText)
        if (errorText != nil) {
            resp.responseError = errorText
        }
        self.historyList.append(resp)
        self.saveMessageData()
    }
    
    
    private let urlSession = URLSession.shared
    private var urlRequest: URLRequest {
        let url = URL(string: urlString)!
        var urlRequest = URLRequest(url: url)
        urlRequest.httpMethod = "POST"
        headers.forEach {  urlRequest.setValue($1, forHTTPHeaderField: $0) }
        return urlRequest
    }

//    public func sendMessageStream(text: String,
//                                  model: String = GPTRequestService.Constants.defaultModel,
//                                  systemText: String = GPTRequestService.Constants.defaultSystemText,
//                                  temperature: Double = GPTRequestService.Constants.defaultTemperature) async throws -> AsyncThrowingStream<String, Error> {
//        var urlRequest = self.urlRequest
//        urlRequest.httpBody = try jsonBody(text: text, model: model, systemText: systemText, temperature: temperature)
//        let (result, response) = try await urlSession.bytes(for: urlRequest)
//        try Task.checkCancellation()
//
//        guard let httpResponse = response as? HTTPURLResponse else {
//            throw "Invalid response"
//        }
//
//        guard 200...299 ~= httpResponse.statusCode else {
//            var errorText = ""
//            for try await line in result.lines {
//                try Task.checkCancellation()
//                errorText += line
//            }
//            if let data = errorText.data(using: .utf8), let errorResponse = try? jsonDecoder.decode(ErrorRootResponse.self, from: data).error {
//                errorText = "\n\(errorResponse.message)"
//            }
//            throw "Bad Response: \(httpResponse.statusCode). \(errorText)"
//        }
//
//
//        var responseText = ""
//        return AsyncThrowingStream { [weak self] in
//            guard let self else { return nil }
//            for try await line in result.lines {
//                try Task.checkCancellation()
//                if line.hasPrefix("data: "),
//                   let data = line.dropFirst(6).data(using: .utf8),
//                   let response = try? self.jsonDecoder.decode(StreamCompletionResponse.self, from: data),
//                   let text = response.choices.first?.delta.content {
//                    responseText += text
//                    return text
//                }
//            }
//            self.appendToHistoryList(userText: text, responseText: responseText)
//            return nil
//        }
//    }

    public func sendMessage(text: String, isChatMsg:Bool) async throws -> String {
        var urlRequest = self.urlRequest
        if isChatMsg {
            urlRequest.httpBody = try chatJsonBody(text: text)
        }
        else {
            urlRequest.httpBody = try checkJsonBody()
        }
        let (data, response) = try await urlSession.data(for: urlRequest)
        try Task.checkCancellation()
        guard let httpResponse = response as? HTTPURLResponse else {
            throw "Invalid response"
        }
        
        guard 200...299 ~= httpResponse.statusCode else {
            var error = "Bad Response: \(httpResponse.statusCode)"
            if let errorResponse = try? jsonDecoder.decode(ErrorRootResponse.self, from: data).error {
                error.append("\n\(errorResponse.message)")
            }
            throw error
        }
        
        do {
            let completionResponse = try self.jsonDecoder.decode(CompletionResponse.self, from: data)
            let responseText = completionResponse.choices.first?.message.content ?? ""
            return responseText
        } catch {
            throw error
        }
    }
    
    public func deleteHistoryList() {
        self.historyList.removeAll()
    }
    
    public func replaceHistoryList(with messages: [Message]) {
        self.historyList = messages
    }
    
}

extension GPTRequestService {
    private func fetchMessageData() {
        if !isSaveHistory {
            return
        }
        guard let data = GPTMsgDataService().getData() else {
            return
        }
        
        do {
            let jsonDecoder = JSONDecoder()
            let messages = try jsonDecoder.decode([Message].self, from: data)
            self.historyList.append(contentsOf: messages)
        } catch {
//            logger.error("fetch message data occur error: \(error.localizedDescription)")
        }
    }
    
    private func saveMessageData() {
        if !isSaveHistory {
            return
        }
        
        Task {
//            logger.info("save messages \(self.messages.count) records at thread: \(Thread.current)")
            do {
                let data = try JSONEncoder().encode(historyList)
                GPTMsgDataService().saveData(data: data)
            } catch {
//                logger.error("save message data occur error: \(error.localizedDescription)")
            }
        }
    }
    
}

