//
//  AirPlaySenderConnection.h
//  AirPlayAuth
//
//  Created by Vik on 6/1/17.
//
//

#import <Foundation/Foundation.h>

@interface AirPlaySenderConnection : NSObject<NSStreamDelegate> 

- (id)initWithHost:(NSString *)aHost port:(int)aPort clientID:(NSString *)aClientID pin:(NSString *)aPin;

- (void)setup;
- (void)close;

- (void)startPairing;


@end
