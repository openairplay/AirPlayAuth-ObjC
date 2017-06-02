//
//  AppDelegate.m
//  AirPlayAuth
//
//  Created by Vik on 6/1/17.
//
//

#import "AppDelegate.h"

#define SERVER_ADDRESS  @"192.168.25.57"
#define SERVER_PORT     7000
#define CLIENT_ID       @"a8:86:dd:b2:bd:37"
#define PIN             @"1111"

@interface AppDelegate ()

@property (weak) IBOutlet NSWindow *window;
@end

@implementation AppDelegate

- (void)applicationDidFinishLaunching:(NSNotification *)aNotification {
    // Insert code here to initialize your application
    
    self.airPlaySenderConnection = [[AirPlaySenderConnection alloc] initWithHost:SERVER_ADDRESS port:SERVER_PORT clientID:CLIENT_ID pin:PIN];
    [self.airPlaySenderConnection setup];
    [self.airPlaySenderConnection startPairing];
}


- (void)applicationWillTerminate:(NSNotification *)aNotification {
    // Insert code here to tear down your application
    [self.airPlaySenderConnection close];
}


@end
