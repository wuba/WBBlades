//
//  AppDelegate.h
//  libxl-example
//

#import <Cocoa/Cocoa.h>

@interface AppDelegate : NSObject <NSApplicationDelegate>
{
	NSWindow *window;
	NSMatrix *excelFormat;
}
@property (assign) IBOutlet NSTextField *lastPath;
@property (assign) IBOutlet NSTextField *currentPath;

@property (assign) IBOutlet NSWindow *window;

- (IBAction)createExcel:(id)sender;

@end
