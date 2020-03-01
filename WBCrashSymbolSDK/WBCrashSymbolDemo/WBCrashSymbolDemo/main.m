//
//  main.m
//  WBCrashSymbolDemo
//
//  Created by 邓竹立 on 2020/1/8.
//  Copyright © 2020 邓竹立. All rights reserved.
//

#import <UIKit/UIKit.h>
#import "AppDelegate.h"
//#import "WBCrashSymbol.h"
int main(int argc, char * argv[]) {
    NSString * appDelegateClassName;
    @autoreleasepool {
        // Setup code that might create autoreleased objects goes here.
        appDelegateClassName = NSStringFromClass([AppDelegate class]);
    }
    return UIApplicationMain(argc, argv, nil, appDelegateClassName);
}
