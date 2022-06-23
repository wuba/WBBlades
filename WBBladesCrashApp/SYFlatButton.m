//
//  SYFlatButton.m
//  SYFlatButton
//
//  Created by Sunnyyoung on 2016/11/17.
//  Copyright © 2016年 Sunnyyoung. All rights reserved.
//

#import "SYFlatButton.h"

@interface SYFlatButton () <CALayerDelegate>

@property (nonatomic, strong) CAShapeLayer *imageLayer;
@property (nonatomic, strong) CATextLayer *titleLayer;
@property (nonatomic, assign) BOOL mouseDown;

@end

@implementation SYFlatButton

#pragma mark - Lifecycle

- (instancetype)initWithCoder:(NSCoder *)coder {
    self = [super initWithCoder:coder];
    if (self) {
        [self setup];
        [self setupImageLayer];
        [self setupTitleLayer];
    }
    return self;
}

- (instancetype)initWithFrame:(NSRect)frameRect {
    self = [super initWithFrame:frameRect];
    if (self) {
        [self setup];
        [self setupImageLayer];
        [self setupTitleLayer];
    }
    return self;
}

- (void)awakeFromNib {
    [super awakeFromNib];
    [self addTrackingArea:[[NSTrackingArea alloc] initWithRect:self.bounds options:NSTrackingActiveAlways|NSTrackingInVisibleRect|NSTrackingMouseEnteredAndExited owner:self userInfo:nil]];
}

#pragma mark - Drawing method

- (void)drawRect:(NSRect)dirtyRect {
    // Do nothing
}

- (BOOL)layer:(CALayer *)layer shouldInheritContentsScale:(CGFloat)newScale fromWindow:(NSWindow *)window {
    return YES;
}

#pragma mark - Setup method

- (void)setup {
    // Setup layer
    self.wantsLayer = YES;
    self.layer.masksToBounds = YES;
    self.layer.delegate = self;
    self.layer.backgroundColor = [NSColor redColor].CGColor;
    self.alphaValue = self.isEnabled ? 1.0 : 0.5;
}

- (void)setupImageLayer {
    // Ignore image layer if has no image or imagePosition equal to NSNoImage
    if (!self.image || self.imagePosition == NSNoImage) {
        [self.imageLayer removeFromSuperlayer];
        return;
    }
    
    CGSize buttonSize = self.frame.size;
    CGSize imageSize = self.image.size;
    CGSize titleSize = [self.title sizeWithAttributes:@{NSFontAttributeName: self.font}];
    CGFloat x = 0.0; // Image's origin x
    CGFloat y = 0.0; // Image's origin y
    
    // Caculate the image's and title's position depends on button's imagePosition and imageHugsTitle property
    switch (self.imagePosition) {
        case NSNoImage:
            return;
            break;
        case NSImageOnly: {
            x = (buttonSize.width - imageSize.width) / 2.0;
            y = (buttonSize.height - imageSize.height) / 2.0;
            break;
        }
        case NSImageOverlaps: {
            x = (buttonSize.width - imageSize.width) / 2.0;
            y = (buttonSize.height - imageSize.height) / 2.0;
            break;
        }
        case NSImageLeading:
        case NSImageLeft: {
            x = self.imageHugsTitle ? ((buttonSize.width - imageSize.width - titleSize.width) / 2.0 - self.spacing) : self.spacing;
            y = (buttonSize.height - imageSize.height) / 2.0;
            break;
        }
        case NSImageTrailing:
        case NSImageRight: {
            x = self.imageHugsTitle ? ((buttonSize.width - imageSize.width + titleSize.width) / 2.0 + self.spacing) : (buttonSize.width - imageSize.width - self.spacing);
            y = (buttonSize.height - imageSize.height) / 2.0;
            break;
        }
        case NSImageAbove: {
            x = (buttonSize.width - imageSize.width) / 2.0;
            y = self.imageHugsTitle ? ((buttonSize.height - imageSize.height - titleSize.height) / 2.0 - self.spacing) : self.spacing;
            break;
        }
        case NSImageBelow: {
            x = (buttonSize.width - imageSize.width) / 2.0;
            y = self.imageHugsTitle ? ((buttonSize.height - imageSize.height + titleSize.height) / 2.0 + self.spacing) : (buttonSize.height - imageSize.height - self.spacing);
            break;
        }
        default: {
            break;
        }
    }
    
    // Setup image layer
    self.imageLayer.frame = self.bounds;
    self.imageLayer.mask = ({
        CALayer *layer = [CALayer layer];
        NSRect rect = NSMakeRect(round(x), round(y), imageSize.width, imageSize.height);
        layer.frame = rect;
        layer.contents = (__bridge id _Nullable)[self.image CGImageForProposedRect:&rect context:nil hints:nil];
        layer;
    });
    [self.layer addSublayer:self.imageLayer];
}

- (void)setupTitleLayer {
    // Ignore title layer if has no title or imagePosition equal to NSImageOnly
    if (!self.title || self.imagePosition == NSImageOnly) {
        [self.titleLayer removeFromSuperlayer];
        return;
    }
    
    CGSize buttonSize = self.frame.size;
    CGSize imageSize = self.image.size;
    CGSize titleSize = [self.title sizeWithAttributes:@{NSFontAttributeName: self.font}];
    CGFloat x = 0.0; // Title's origin x
    CGFloat y = 0.0; // Title's origin y
    
    // Caculate the image's and title's position depends on button's imagePosition and imageHugsTitle property
    switch (self.imagePosition) {
        case NSImageOnly: {
            return;
            break;
        }
        case NSNoImage: {
            x = (buttonSize.width - titleSize.width) / 2.0;
            y = (buttonSize.height - titleSize.height) / 2.0;
            break;
        }
        case NSImageOverlaps: {
            x = (buttonSize.width - titleSize.width) / 2.0;
            y = (buttonSize.height - titleSize.height) / 2.0;
            break;
        }
        case NSImageLeading:
        case NSImageLeft: {
            x = self.imageHugsTitle ? ((buttonSize.width + imageSize.width - titleSize.width) / 2.0 + self.spacing) : (buttonSize.width - titleSize.width - self.spacing);
            y = (buttonSize.height - titleSize.height) / 2.0;
            break;
        }
        case NSImageTrailing:
        case NSImageRight: {
            x = self.imageHugsTitle ? ((buttonSize.width - imageSize.width - titleSize.width) / 2.0 - self.spacing) : self.spacing;
            y = (buttonSize.height - titleSize.height) / 2.0;
            break;
        }
        case NSImageAbove: {
            x = (buttonSize.width - titleSize.width) / 2.0;
            y = self.imageHugsTitle ? ((buttonSize.height + imageSize.height - titleSize.height) / 2.0 + self.spacing) : (buttonSize.height - titleSize.height - self.spacing);
            break;
        }
        case NSImageBelow: {
            y = self.imageHugsTitle ? ((buttonSize.height - imageSize.height - titleSize.height) / 2.0 - self.spacing) : self.spacing;
            x = (buttonSize.width - titleSize.width) / 2.0;
            break;
        }
        default: {
            break;
        }
    }
    
    // Setup title layer
    self.titleLayer.frame = NSMakeRect(round(x), round(y), ceil(titleSize.width), ceil(titleSize.height));
    self.titleLayer.string = self.title;
    self.titleLayer.font = (__bridge CFTypeRef _Nullable)(self.font);
    self.titleLayer.fontSize = self.font.pointSize;
    [self.layer addSublayer:self.titleLayer];
}

#pragma mark - Animation method

- (void)removeAllAnimations {
    [self.layer removeAllAnimations];
    [self.layer.sublayers enumerateObjectsUsingBlock:^(CALayer * _Nonnull layer, NSUInteger index, BOOL * _Nonnull stop) {
        [layer removeAllAnimations];
    }];
}

- (void)animateColorWithState:(NSCellStateValue)state {
    [self removeAllAnimations];
    CGFloat duration = (state == NSOnState) ? self.onAnimateDuration : self.offAnimateDuration;
    NSColor *borderColor = (state == NSOnState) ? self.borderHighlightColor : self.borderNormalColor;
    NSColor *backgroundColor = (state == NSOnState) ? self.backgroundHighlightColor : self.backgroundNormalColor;
    NSColor *titleColor = (state == NSOnState) ? self.titleHighlightColor : self.titleNormalColor;
    NSColor *imageColor = (state == NSOnState) ? self.imageHighlightColor : self.imageNormalColor;
    [self animateLayer:self.layer color:borderColor keyPath:@"borderColor" duration:duration];
    [self animateLayer:self.layer color:backgroundColor keyPath:@"backgroundColor" duration:duration];
    [self animateLayer:self.imageLayer color:imageColor keyPath:@"backgroundColor" duration:duration];
    [self animateLayer:self.titleLayer color:titleColor keyPath:@"foregroundColor" duration:duration];
}

- (void)animateLayer:(CALayer *)layer color:(NSColor *)color keyPath:(NSString *)keyPath duration:(CGFloat)duration {
    CGColorRef oldColor = (__bridge CGColorRef)([layer valueForKeyPath:keyPath]);
    if (!(CGColorEqualToColor(oldColor, color.CGColor))) {
        CABasicAnimation *animation = [CABasicAnimation animationWithKeyPath:keyPath];
        animation.fromValue = [layer valueForKeyPath:keyPath];
        animation.toValue = (id)color.CGColor;
        animation.duration = duration;
        animation.removedOnCompletion = NO;
        [layer addAnimation:animation forKey:keyPath];
        [layer setValue:(id)color.CGColor forKey:keyPath];
    }
}

#pragma mark - Event Response

- (NSView *)hitTest:(NSPoint)point {
    return self.isEnabled ? [super hitTest:point] : nil;
}

- (void)mouseDown:(NSEvent *)event {
    if (self.isEnabled) {
        self.mouseDown = YES;
        self.state = (self.state == NSOnState) ? NSOffState : NSOnState;
    }
}

- (void)mouseEntered:(NSEvent *)event {
    if (self.mouseDown) {
        self.state = (self.state == NSOnState) ? NSOffState : NSOnState;
    }
}

- (void)mouseExited:(NSEvent *)event {
    if (self.mouseDown) {
        self.mouseDown = NO;
        self.state = (self.state == NSOnState) ? NSOffState : NSOnState;
    }
}

- (void)mouseUp:(NSEvent *)event {
    if (self.mouseDown) {
        self.mouseDown = NO;
        if (self.momentary) {
            self.state = (self.state == NSOnState) ? NSOffState : NSOnState;
        }
        [NSApp sendAction:self.action to:self.target from:self];
    }
}

#pragma mark - Property method

- (void)setFrame:(NSRect)frame {
    [super setFrame:frame];
    [self setupTitleLayer];
}

- (void)setFont:(NSFont *)font {
    [super setFont:font];
    [self setupTitleLayer];
}

- (void)setTitle:(NSString *)title {
    [super setTitle:title];
    [self setupTitleLayer];
}

- (void)setImage:(NSImage *)image {
    [super setImage:image];
    [self setupImageLayer];
}

- (void)setState:(NSInteger)state {
    [super setState:state];
    [self animateColorWithState:state];
}

- (void)setImagePosition:(NSCellImagePosition)imagePosition {
    [super setImagePosition:imagePosition];
    [self setupImageLayer];
    [self setupTitleLayer];
}

- (void)setMomentary:(BOOL)momentary {
    _momentary = momentary;
    [self animateColorWithState:self.state];
}

- (void)setCornerRadius:(CGFloat)cornerRadius {
    _cornerRadius = cornerRadius;
    self.layer.cornerRadius = _cornerRadius;
}

- (void)setBorderWidth:(CGFloat)borderWidth {
    _borderWidth = borderWidth;
    self.layer.borderWidth = _borderWidth;
}

- (void)setSpacing:(CGFloat)spacing {
    _spacing = spacing;
    [self setupImageLayer];
    [self setupTitleLayer];
}

- (void)setBorderNormalColor:(NSColor *)borderNormalColor {
    _borderNormalColor = borderNormalColor;
    [self animateColorWithState:self.state];
}

- (void)setBorderHighlightColor:(NSColor *)borderHighlightColor {
    _borderHighlightColor = borderHighlightColor;
    [self animateColorWithState:self.state];
}

- (void)setBackgroundNormalColor:(NSColor *)backgroundNormalColor {
    _backgroundNormalColor = backgroundNormalColor;
    [self animateColorWithState:self.state];
}

- (void)setBackgroundHighlightColor:(NSColor *)backgroundHighlightColor {
    _backgroundHighlightColor = backgroundHighlightColor;
    [self animateColorWithState:self.state];
}

- (void)setImageNormalColor:(NSColor *)imageNormalColor {
    _imageNormalColor = imageNormalColor;
    [self animateColorWithState:self.state];
}

- (void)setImageHighlightColor:(NSColor *)imageHighlightColor {
    _imageHighlightColor = imageHighlightColor;
    [self animateColorWithState:self.state];
}

- (void)setTitleNormalColor:(NSColor *)titleNormalColor {
    _titleNormalColor = titleNormalColor;
    [self animateColorWithState:self.state];
}

- (void)setTitleHighlightColor:(NSColor *)titleHighlightColor {
    _titleHighlightColor = titleHighlightColor;
    [self animateColorWithState:self.state];
}

- (CAShapeLayer *)imageLayer {
    if (_imageLayer == nil) {
        _imageLayer = [[CAShapeLayer alloc] init];
        _imageLayer.delegate = self;
    }
    return _imageLayer;
}

- (CATextLayer *)titleLayer {
    if (_titleLayer == nil) {
        _titleLayer = [[CATextLayer alloc] init];
        _titleLayer.delegate = self;
    }
    return _titleLayer;
}

@end
