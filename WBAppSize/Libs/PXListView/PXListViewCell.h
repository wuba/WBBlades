//
//  PXListViewCell.h
//  PXListView
//
//  Created by Alex Rozanski on 29/05/2010.
//  Copyright 2010 Alex Rozanski. http://perspx.com. All rights reserved.
//

#import <Cocoa/Cocoa.h>
#import "PXListViewDropHighlight.h"


@class PXListView;

@interface PXListViewCell : NSView
{
//	NSString *_reusableIdentifier;
//	
//	PXListViewDropHighlight	_dropHighlight;
}

@property (nonatomic, weak) PXListView *listView;

@property (readonly, copy) NSString *reusableIdentifier;
@property (readwrite) NSUInteger row;

@property (readonly,getter=isSelected) BOOL selected;
@property (nonatomic, assign) PXListViewDropHighlight dropHighlight;

+ (id)cellLoadedFromNibNamed:(NSString*)nibName reusableIdentifier:(NSString*)identifier;
+ (id)cellLoadedFromNibNamed:(NSString*)nibName bundle:(NSBundle*)bundle reusableIdentifier:(NSString*)identifier;

- (id)initWithReusableIdentifier:(NSString*)identifier;
- (void)prepareForReuse;

-(void)layoutSubviews;

@end
