//
//  SYFlatButton.h
//  SYFlatButton
//
//  Created by Sunnyyoung on 2016/11/17.
//  Copyright © 2016年 Sunnyyoung. All rights reserved.
//

#import <Cocoa/Cocoa.h>
#import <Quartz/Quartz.h>
#import <CoreGraphics/CoreGraphics.h>

IB_DESIGNABLE
@interface SYFlatButton : NSButton

@property (nonatomic, assign) IBInspectable BOOL momentary;                     // Default:NO   - Restore button state when mouse up
@property (nonatomic, assign) IBInspectable CGFloat onAnimateDuration;          // Default:0.0  - The animation duration from NSOffState to NSOnState
@property (nonatomic, assign) IBInspectable CGFloat offAnimateDuration;         // Default:0.0  - The animation duration from NSOnState to NSOffState
@property (nonatomic, assign) IBInspectable CGFloat cornerRadius;               // Default:0.0  - Button's border corner radius
@property (nonatomic, assign) IBInspectable CGFloat borderWidth;                // Default:0.0  - Button's border width
@property (nonatomic, assign) IBInspectable CGFloat spacing;                    // Default:0.0  - Button's spacint between image and title
@property (nonatomic, strong) IBInspectable NSColor *borderNormalColor;         // Default:nil  - Button's border color when state off
@property (nonatomic, strong) IBInspectable NSColor *borderHighlightColor;      // Default:nil  - Button's border color when state on
@property (nonatomic, strong) IBInspectable NSColor *backgroundNormalColor;     // Default:nil  - Button's background color when state off
@property (nonatomic, strong) IBInspectable NSColor *backgroundHighlightColor;  // Default:nil  - Button's background color when state on
@property (nonatomic, strong) IBInspectable NSColor *imageNormalColor;          // Default:nil  - Button's image color when state off
@property (nonatomic, strong) IBInspectable NSColor *imageHighlightColor;       // Default:nil  - Button's image color when state on
@property (nonatomic, strong) IBInspectable NSColor *titleNormalColor;          // Default:nil  - Button's title color when state off
@property (nonatomic, strong) IBInspectable NSColor *titleHighlightColor;       // Default:nil  - Button's title color when state on

@end
