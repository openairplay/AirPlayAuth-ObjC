//
//  AppDelegate.h
//  AirPlayAuth
//
//  Created by Vik on 6/1/17.
//
//

#import <Cocoa/Cocoa.h>
#import "AirPlaySenderConnection.h"

@interface AppDelegate : NSObject <NSApplicationDelegate>

@property (strong) AirPlaySenderConnection *airPlaySenderConnection;

@end

