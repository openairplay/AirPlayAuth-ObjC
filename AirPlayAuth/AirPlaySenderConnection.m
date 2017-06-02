//
//  AirPlaySenderConnection.m
//  AirPlayAuth
//
//  Created by Vik on 6/1/17.
//
//

#import "AirPlaySenderConnection.h"
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCryptor.h>
#import "IAGAesGcm.h"
#import "ed25519.h"
#import "srp.h"

extern void curve25519_donna(unsigned char *output, const unsigned char *a,
                             const unsigned char *b);

@interface AirPlaySenderConnection () <NSStreamDelegate>

@property (strong) NSString         *clientID;
@property (strong) NSString         *pin;
@property (strong) NSString			*host;
@property (assign) int              port;
@property (assign) struct SRPUser   *user;

@property (assign) BOOL             pairingStarted;

@property (strong) NSInputStream    *inputStream;
@property (strong) NSOutputStream   *outputStream;
@property (strong) NSMutableData    *inputBuffer;
@property (strong) NSMutableArray   *dataWriteQueue;
@property (assign) int              currentDataOffset;
@property (assign) BOOL             canSendDirectly;

@property (strong) NSData           *privateKey1Data;
@property (strong) NSData           *publicKey1Data;
@property (strong) NSData           *privateKey2Data;
@property (strong) NSData           *publicKey2Data;

@end

@implementation AirPlaySenderConnection

- (id)initWithHost:(NSString *)aHost port:(int)aPort clientID:(NSString *)aClientID pin:(NSString *)aPin {
    self = [super init];
    if (self) {
        _clientID = aClientID;
        _host = aHost;
        _port = aPort;
        _pin = aPin;
        _pairingStarted = NO;
        _dataWriteQueue = [[NSMutableArray alloc] init];
        _currentDataOffset = 0;
        _canSendDirectly = true;
    }
    return self;
}

#pragma mark -
#pragma mark Setup/Close

- (void)setup {
    self.pairingStarted = NO;
    
    NSURL *serverURL = [NSURL URLWithString:[NSString stringWithFormat:@"http://%@", self.host]];
    //Creates readable and writable streams connected to a socket.
    CFReadStreamRef readStream;
    CFWriteStreamRef writeStream;
    CFStreamCreatePairWithSocketToHost(kCFAllocatorDefault, (__bridge CFStringRef)[serverURL host], self.port, &readStream, &writeStream);
    //Cast these objects to an NSInputStream and an NSOutputStream
    self.inputStream = (__bridge NSInputStream *)readStream;
    self.outputStream = (__bridge NSOutputStream *)writeStream;
    //Once you have cast the CFStreams to NSStreams, set the delegate, schedule the stream on a run loop, and open the stream as usual.
    //The delegate should begin to receive stream-event messages (stream:handleEvent:)
    [self.inputStream setDelegate:self];
    [self.outputStream setDelegate:self];
    [self.inputStream scheduleInRunLoop:[NSRunLoop currentRunLoop] forMode:NSDefaultRunLoopMode];
    [self.outputStream scheduleInRunLoop:[NSRunLoop currentRunLoop] forMode:NSDefaultRunLoopMode];
    [self.inputStream open];
    [self.outputStream open];
}

- (void)close {
    [self.inputStream close];
    [self.outputStream close];
    [self.inputStream removeFromRunLoop:[NSRunLoop currentRunLoop] forMode:NSDefaultRunLoopMode];
    [self.outputStream removeFromRunLoop:[NSRunLoop currentRunLoop] forMode:NSDefaultRunLoopMode];
    [self.inputStream setDelegate:nil];
    [self.outputStream setDelegate:nil];
    self.inputStream = nil;
    self.outputStream = nil;
}

#pragma mark -
#pragma mark NSStreamDelegate Protocol Support

- (void)stream:(NSStream *)stream handleEvent:(NSStreamEvent)event {
    switch (event) {
        case NSStreamEventHasSpaceAvailable:
            [self _sendData];
            break;
        case NSStreamEventHasBytesAvailable:;
            uint8_t buf[16 * 1024];
            uint8_t *buffer = NULL;
            NSUInteger len = 0;
            //Returns by reference a pointer to a read buffer and, by reference,
            //the number of bytes available, and returns a Boolean value that
            //indicates whether the buffer is available.
            if (![_inputStream getBuffer:&buffer length:&len]) {
                //Reads up to a given number of bytes into a given buffer.
                //Returns a number indicating the outcome of the operation:
                //  A positive number indicates the number of bytes read;
                //  0 indicates that the end of the buffer was reached;
                //  A negative number means that the operation failed.
                NSInteger amount = [_inputStream read:buf maxLength:sizeof(buf)];
                buffer = buf;
                len = amount;
            }
            if (0 < len) {
                if (!_inputBuffer) {
                    _inputBuffer = [[NSMutableData alloc] init];
                }
                @try {
                    [_inputBuffer appendBytes:buffer length:len];
                }
                @catch (NSException *exception) {
                    NSLog(@"Exception was thrown: %@.", exception.description);
                }
            }
            do {} while ([self processIncomingBytes]);
            break;
        case NSStreamEventErrorOccurred:
            NSLog(@"An error has occurred on the stream.");
            break;
        case NSStreamEventEndEncountered:
            NSLog(@"The end of the stream has been reached.");
            break;
        default:
            break;
    }
}

// YES return means that a complete request was parsed, and the caller
// should call again as the buffered bytes may have another complete
// request available.
- (BOOL)processIncomingBytes {
    BOOL isRequest = FALSE;
    CFHTTPMessageRef message = CFHTTPMessageCreateEmpty(kCFAllocatorDefault, isRequest);
    CFHTTPMessageAppendBytes(message, [_inputBuffer bytes], [_inputBuffer length]);
    
    if (CFHTTPMessageIsHeaderComplete(message)) {
        NSString *contentLengthValue = (__bridge NSString *)CFHTTPMessageCopyHeaderFieldValue(message, (CFStringRef)@"Content-Length");
        
        unsigned contentLength = contentLengthValue ? [contentLengthValue intValue] : 0;
        NSData *body = (__bridge NSData *)CFHTTPMessageCopyBody(message);
        NSUInteger bodyLength = [body length];
        if (contentLength <= bodyLength) {
            NSData *newBody = [NSData dataWithBytes:[body bytes] length:contentLength];
            [_inputBuffer setLength:0];
            [_inputBuffer appendBytes:([body bytes] + contentLength) length:(bodyLength - contentLength)];
            CFHTTPMessageSetBody(message, (__bridge CFDataRef)newBody);
        } else {
            CFRelease(message);
            return NO;
        }
    } else {
        return NO;
    }
    
    [self handleMessage:message];
    CFRelease(message);
    
    return YES;
}

#pragma mark -
#pragma mark Handling Responses

- (void)handleMessage:(CFHTTPMessageRef)message {
    [self printHTTPMessage:message];
    
    signed long statusCode = CFHTTPMessageGetResponseStatusCode(message);
    if (statusCode == 401) {
        //TODO: handle HTTP/1.1 401 Unauthorized
        return;
    } else if (statusCode == 453) {
        //TODO: handle HTTP/1.1 453 Not Enough Bandwidth
        return;
    } else if (statusCode == 403) {
        //TODO: handle HTTP/1.1 403 Forbidden
        return;
    } else if (statusCode == 200) { //OK
        if (self.pairingStarted == NO) {
            self.pairingStarted = YES;
            
            [self doPairing];
            return;
        }
        //Gets the body from a CFHTTPMessage object.
        NSString *contentLengthValue = (__bridge NSString *)CFHTTPMessageCopyHeaderFieldValue(message, (CFStringRef)@"Content-Length");
        unsigned contentLength = contentLengthValue ? [contentLengthValue intValue] : 0;
        if (contentLength != 0) {
            NSString *contentTypeValue = (__bridge NSString *)CFHTTPMessageCopyHeaderFieldValue(message, (CFStringRef)@"Content-Type");
            if ([contentTypeValue isEqualToString:@"application/x-apple-binary-plist"]) {
                NSData *requestBody = (__bridge NSData *)CFHTTPMessageCopyBody(message);
                NSPropertyListFormat format;
                NSError *error = nil;
                NSDictionary *plist = [NSPropertyListSerialization propertyListWithData:requestBody options:NSPropertyListImmutable format:&format error:&error];
                if (plist == nil) {
                } else {
                    NSLog(@"%@", plist.description);
                    
                    id pk = [plist objectForKey:@"pk"]; //256 bytes
                    id salt = [plist objectForKey:@"salt"]; //16 bytes
                    if (pk != nil && salt != nil) {
                        NSLog(@"pk and salt received!");
                        if ([pk isKindOfClass:[NSData class]] && [salt isKindOfClass:[NSData class]]) {
                            NSData *pkData = (NSData *)pk;
                            NSData *saltData = (NSData *)salt;
                            [self doPairSetupPin2WithServerPublicKey:pkData salt:saltData];
                        }
                    } else {
                        id proof = [plist objectForKey:@"proof"];
                        if (proof != nil) {
                            NSLog(@"proof received!");
                            if ([proof isKindOfClass:[NSData class]]) {
                                NSData *proofData = (NSData *)proof;
                                [self doPairSetupPin3WithServerProof:proofData];
                            }
                        } else {
                            id epk = [plist objectForKey:@"epk"];
                            id authTag = [plist objectForKey:@"authTag"];
                            if (epk != nil && authTag != nil) {
                                NSLog(@"epk and authTag received!");
                                if ([epk isKindOfClass:[NSData class]] && [authTag isKindOfClass:[NSData class]]) {
                                    [self doPairVerify1];
                                }
                            }
                        }
                    }
                }
            } else if ([contentTypeValue isEqualToString:@"application/octet-stream"]) {
                NSLog(@"application/octet-stream received.");
                NSData *requestBody = (__bridge NSData *)CFHTTPMessageCopyBody(message);
                [self doPairVerify2WithData:requestBody];
            }
        }
    }
}

#pragma mark -
#pragma mark POST/GET Helpers
//Executes a POST to a resource
- (void)post:(NSString *)resource {
    NSDictionary *headers = @{@"Content-Length":@"0"};
    [self post:resource body:nil headers:headers];
}

- (void)post:(NSString *)resource body:(NSData *)bodyData headers:(NSDictionary *)requestHeaders {
    CFStringRef requestMethod = CFSTR("POST");
    [self prepareRequest:requestMethod resource:resource body:bodyData headers:requestHeaders];
}

//Executes a GET to a resource
- (void)get:(NSString *)resource {
    CFStringRef requestMethod = CFSTR("GET");
    [self prepareRequest:requestMethod resource:resource body:nil headers:nil];
}

- (void)prepareRequest:(CFStringRef)requestMethod resource:(NSString *)resource body:(NSData *)bodyData headers:(NSDictionary *)requestHeaders {
    CFStringRef requestURLString = (__bridge CFStringRef)resource;
    CFURLRef requestURL = CFURLCreateWithString(kCFAllocatorDefault, requestURLString, NULL);
    CFHTTPMessageRef request = CFHTTPMessageCreateRequest(kCFAllocatorDefault, requestMethod, requestURL, kCFHTTPVersion1_1);
    if (bodyData != nil) {
        CFHTTPMessageSetBody(request, (__bridge CFDataRef)bodyData);
    }
    [self sendRequest:request headers:requestHeaders];
    CFRelease(requestURL);
    CFRelease(request);
}

- (void)sendRequest:(CFHTTPMessageRef)request headers:(NSDictionary *)requestHeaders {
    //The defaults connection headers
    CFHTTPMessageSetHeaderFieldValue(request, (CFStringRef)@"User-Agent", (CFStringRef)@"AirPlay/320.20");
    CFHTTPMessageSetHeaderFieldValue(request, (CFStringRef)@"X-Apple-Device-ID", (__bridge CFStringRef)_clientID);
    
    //optional headers
    if (requestHeaders != nil) {
        for (NSString *headerName in requestHeaders) {
            CFHTTPMessageSetHeaderFieldValue(request, (__bridge CFStringRef)headerName, (__bridge CFStringRef)[requestHeaders objectForKey:headerName]);
        }
    }
    
    [self printHTTPMessage:request];
    
    //Serializes a CFHTTPMessage object
    NSData *serializedMsg = (__bridge NSData *)CFHTTPMessageCopySerializedMessage(request);
    [self sendData:serializedMsg];
}

- (void)sendData:(NSData *)data {
    [_dataWriteQueue insertObject:data atIndex:0];
    if (_canSendDirectly) [self _sendData];
}

- (void)_sendData {
    _canSendDirectly = NO;
    NSData *data = [_dataWriteQueue lastObject];
    if (data == nil) {
        _canSendDirectly = YES;
        return;
    }
    uint8_t *readBytes = (uint8_t *)[data bytes];
    readBytes += _currentDataOffset;
    NSUInteger dataLength = [data length];
    NSUInteger lengthOfDataToWrite = (dataLength - _currentDataOffset >= 1024) ? 1024 : (dataLength - _currentDataOffset);
    NSInteger bytesWritten = [_outputStream write:readBytes maxLength:lengthOfDataToWrite];
    if (bytesWritten > 0) {
        _currentDataOffset += bytesWritten;
        if (_currentDataOffset == dataLength) {
            [_dataWriteQueue removeLastObject];
            _currentDataOffset = 0;
        }
    }
}

#pragma mark -
#pragma mark ATV Device Verification

- (void)startPairing {
    [self post:@"/pair-pin-start"];
}

- (void)doPairing {
    _user = srp_user_new(SRP_SHA1, SRP_NG_2048, _clientID.UTF8String, (const unsigned char *)_pin.UTF8String, 4, 0, 0);
    NSDictionary *plist = @{@"method": @"pin",
                            @"user": _clientID};
    
    NSData *data = [NSPropertyListSerialization dataWithPropertyList:plist format:NSPropertyListBinaryFormat_v1_0 options:0 error:nil];
    NSMutableDictionary *headers = [NSMutableDictionary dictionaryWithCapacity:2];
    [headers setObject:@"application/x-apple-binary-plist" forKey:@"Content-Type"];
    [headers setObject:[NSString stringWithFormat:@"%lu", (unsigned long)data.length] forKey:@"Content-Length"];
    [self post:@"/pair-setup-pin" body:data headers:headers];
}

- (void)doPairSetupPin2WithServerPublicKey:(NSData *)pk salt:(NSData *)salt {
    const char *auth_username = 0;
    const unsigned char *pkA;
    int pkA_len;
    const unsigned char *M1;
    int M1_len;
    
    //get public client value and client evidence
    // Calculate A
    srp_user_start_authentication(_user, &auth_username, &pkA, &pkA_len);
    
    // Calculate M1 (client proof)
    srp_user_process_challenge(_user, salt.bytes, (int)salt.length, pk.bytes, (int)pk.length, &M1, &M1_len);
    
//    NSLog(@"A: %s (%d bytes)", pkA, pkA_len);
//    NSLog(@"M1: %s (%d bytes)", M1, M1_len);
    
    NSDictionary *plist = @{@"pk": [NSData dataWithBytes:pkA length:pkA_len],
                            @"proof": [NSData dataWithBytes:M1 length:M1_len]};
    NSData *data = [NSPropertyListSerialization dataWithPropertyList:plist format:NSPropertyListBinaryFormat_v1_0 options:0 error:nil];
    NSMutableDictionary *headers = [NSMutableDictionary dictionaryWithCapacity:2];
    [headers setObject:@"application/x-apple-binary-plist" forKey:@"Content-Type"];
    [headers setObject:[NSString stringWithFormat:@"%lu", (unsigned long)data.length] forKey:@"Content-Length"];
    [self post:@"/pair-setup-pin" body:data headers:headers];
}

- (void)doPairSetupPin3WithServerProof:(NSData *)proof {
    // Check M2
    srp_user_verify_session(_user, proof.bytes);
    if (!srp_user_is_authenticated(_user)) {
        NSLog(@"Server authentication failed\n");
        return;
    }
    NSLog(@"Stage 1 complete - you did it!!\n");
    
    NSString *aesKeyStr = @"Pair-Setup-AES-Key";
    NSString *aesIVStr = @"Pair-Setup-AES-IV";
    NSData *aesKeyStrData = [aesKeyStr dataUsingEncoding:NSUTF8StringEncoding];
    NSData *aesIVStrData = [aesIVStr dataUsingEncoding:NSUTF8StringEncoding];
    const void *aesKeyBytes = aesKeyStrData.bytes;
    const void *aesIVBytes = aesIVStrData.bytes;
    
    int sessionKeyLen = 0;
    const unsigned char * sessionKey = srp_user_get_session_key(_user, &sessionKeyLen);
    
    unsigned char hash[CC_SHA512_DIGEST_LENGTH];
    CC_SHA512_CTX context;
    CC_SHA512_Init(&context);
    CC_SHA512_Update(&context, aesKeyBytes, (CC_LONG)aesKeyStrData.length);
    CC_SHA512_Update(&context, sessionKey, (CC_LONG)sessionKeyLen);
    CC_SHA512_Final(hash, &context);
    
    char aesKey[16];
    memcpy(aesKey, hash, 16);
    
    unsigned char hash2[CC_SHA512_DIGEST_LENGTH];
    CC_SHA512_CTX context2;
    CC_SHA512_Init(&context2);
    CC_SHA512_Update(&context2, aesIVBytes, (CC_LONG)aesIVStrData.length);
    CC_SHA512_Update(&context2, sessionKey, (CC_LONG)sessionKeyLen);
    CC_SHA512_Final(hash2, &context2);
    
    char aesIV[16];
    memcpy(aesIV, hash2, 16);
    
    int lengthB;
    int lengthA = lengthB = 15;
    for (; lengthB >= 0 && 256 == ++aesIV[lengthA]; lengthA = lengthB += -1) ;
    
    NSData *key = [NSData dataWithBytes:aesKey length:sizeof(aesKey)];
    NSData *iv = [NSData dataWithBytes:aesIV length:sizeof(aesIV)];
    
    unsigned char public_key[32], private_key[64];
    NSString *randomString = [self randomStringWithLength:32];
    ed25519_create_keypair(public_key, private_key, [randomString dataUsingEncoding:NSUTF8StringEncoding].bytes);
    _privateKey1Data = [NSData dataWithBytes:private_key length:64];
    _publicKey1Data = [NSData dataWithBytes:public_key length:32];
    
    NSData *aad = [NSData data];
    // Authenticated Encryption Function
    IAGCipheredData *cipheredData = [IAGAesGcm cipheredDataByAuthenticatedEncryptingPlainData:_publicKey1Data
                                                              withAdditionalAuthenticatedData:aad
                                                                      authenticationTagLength:IAGAuthenticationTagLength128
                                                                         initializationVector:iv
                                                                                          key:key
                                                                                        error:nil];
    
    NSUInteger cipheredBufferLength = cipheredData.cipheredBufferLength;
    const void * cipheredBuffer = cipheredData.cipheredBuffer;
    
    NSData *epkData = [NSData dataWithBytes:cipheredBuffer length:cipheredBufferLength];
    const void *authTagBytes = cipheredData.authenticationTag;
    NSUInteger authTagLen = cipheredData.authenticationTagLength;
    NSData *authTagData = [NSData dataWithBytes:authTagBytes length:authTagLen];
    
    NSDictionary *plist = @{@"epk": epkData,
                            @"authTag": authTagData};
    
    NSData *data = [NSPropertyListSerialization dataWithPropertyList:plist format:NSPropertyListBinaryFormat_v1_0 options:0 error:nil];
    NSMutableDictionary *headers = [NSMutableDictionary dictionaryWithCapacity:2];
    [headers setObject:@"application/x-apple-binary-plist" forKey:@"Content-Type"];
    [headers setObject:[NSString stringWithFormat:@"%lu", (unsigned long)data.length] forKey:@"Content-Length"];
    [self post:@"/pair-setup-pin" body:data headers:headers];
}

- (void)doPairVerify1 {
    uint8_t privateKey[32];
    arc4random_buf(privateKey, 32);
//    privateKey[0] &= 248;
//    privateKey[31] &= 127;
//    privateKey[31] |= 64;
    const uint8_t basepoint[32] = {9};
    unsigned char publicKey[32];
    curve25519_donna(publicKey, privateKey, basepoint);
    _privateKey2Data = [NSData dataWithBytes:privateKey length:32];
    _publicKey2Data = [[NSData alloc] initWithBytes:publicKey length:32];
    
    NSMutableData *data = [[NSMutableData alloc] init];
    char bytesToAppend[4] = {1, 0, 0, 0};
    [data appendBytes:bytesToAppend length:4];
    [data appendData:_publicKey2Data];
    [data appendData:_publicKey1Data];
    
    NSMutableDictionary *headers = [NSMutableDictionary dictionaryWithCapacity:2];
    [headers setObject:@"application/octet-stream" forKey:@"Content-Type"];
    [headers setObject:[NSString stringWithFormat:@"%lu", (unsigned long)data.length] forKey:@"Content-Length"];
    [self post:@"/pair-verify" body:data headers:headers];
}

- (void)doPairVerify2WithData:(NSData *)pairVerify1Response {
    NSData *atvPublicKey = [pairVerify1Response subdataWithRange:NSMakeRange(0, 32)];
    
    uint8_t sharedSecret[32];
    curve25519_donna(sharedSecret, _privateKey2Data.bytes, atvPublicKey.bytes);
    
    NSString *aesKeyStr = @"Pair-Setup-AES-Key";
    NSString *aesIVStr = @"Pair-Setup-AES-IV";
    NSData *aesKeyStrData = [aesKeyStr dataUsingEncoding:NSUTF8StringEncoding];
    NSData *aesIVStrData = [aesIVStr dataUsingEncoding:NSUTF8StringEncoding];
    const void *aesKeyBytes = aesKeyStrData.bytes;
    const void *aesIVBytes = aesIVStrData.bytes;
    
    unsigned char hash[CC_SHA512_DIGEST_LENGTH];
    CC_SHA512_CTX context;
    CC_SHA512_Init(&context);
    CC_SHA512_Update(&context, aesKeyBytes, (CC_LONG)aesKeyStrData.length);
    CC_SHA512_Update(&context, sharedSecret, 32);
    CC_SHA512_Final(hash, &context);
    
    char sharedSecretSha512AesKey[16];
    memcpy(sharedSecretSha512AesKey, hash, 16);
    
    unsigned char hash2[CC_SHA512_DIGEST_LENGTH];
    CC_SHA512_CTX context2;
    CC_SHA512_Init(&context2);
    CC_SHA512_Update(&context2, aesIVBytes, (CC_LONG)aesIVStrData.length);
    CC_SHA512_Update(&context2, sharedSecret, 32);
    CC_SHA512_Final(hash2, &context2);
    
    char sharedSecretSha512AesIV[16];
    memcpy(sharedSecretSha512AesIV, hash2, 16);
    
    CCCryptorRef cryptor;
    CCCryptorStatus result = CCCryptorCreateWithMode(kCCEncrypt, kCCModeCTR, kCCAlgorithmAES128, ccNoPadding,
                                                     sharedSecretSha512AesIV,
                                                     sharedSecretSha512AesKey, 16, NULL, 0, 0, kCCModeOptionCTR_BE,
                                                     &cryptor);
    if (result != kCCSuccess) {
        NSLog(@"Failed to create cryptor: %d", result);
        return;
    }
    
    NSData *additionalData = [pairVerify1Response subdataWithRange:NSMakeRange(32, pairVerify1Response.length - 32)];
    size_t bufferLength = CCCryptorGetOutputLength(cryptor, additionalData.length, false);
    NSMutableData *buffer = [NSMutableData dataWithLength:bufferLength];
    
    size_t outLength;
    
    result = CCCryptorUpdate(cryptor,
                             [additionalData bytes],
                             [additionalData length],
                             [buffer mutableBytes],
                             [buffer length],
                             &outLength);
    
    
    if (result != kCCSuccess) {
        NSLog(@"Failed to encrypt: %d", result);
        CCCryptorRelease(cryptor);
        return;
    }
    
    NSMutableData *dataToSign = [NSMutableData dataWithData:_publicKey2Data];
    [dataToSign appendData:atvPublicKey];
    
    unsigned char signature[64];
    ed25519_sign(signature, dataToSign.bytes, dataToSign.length, _publicKey1Data.bytes, _privateKey1Data.bytes);
    result = CCCryptorUpdate(cryptor, signature, 64, [buffer mutableBytes], [buffer length], &outLength);
    if (result != kCCSuccess) {
        NSLog(@"Failed to encrypt: %d", result);
        CCCryptorRelease(cryptor);
        return;
    }
    
    NSMutableData *data = [[NSMutableData alloc] init];
    char bytesToAppend[4] = {0, 0, 0, 0};
    [data appendBytes:bytesToAppend length:4];
    [data appendData:buffer];
    NSMutableDictionary *headers = [NSMutableDictionary dictionaryWithCapacity:2];
    [headers setObject:@"application/octet-stream" forKey:@"Content-Type"];
    [headers setObject:[NSString stringWithFormat:@"%lu", (unsigned long)data.length] forKey:@"Content-Length"];
    [self post:@"/pair-verify" body:data headers:headers];
}

#pragma mark -
#pragma mark Helpers

- (void)printHTTPMessage:(CFHTTPMessageRef)message {
    BOOL isRequest = CFHTTPMessageIsRequest(message);
    NSMutableString *info = [[NSMutableString alloc] init];
    if (isRequest) {
        [info appendString:@"\n\nCLIENT -> SERVER:\n"];
        NSString *method = (__bridge NSString *)(CFHTTPMessageCopyRequestMethod(message));
        NSString *url = (__bridge NSString *)(CFHTTPMessageCopyRequestURL(message));
        [info appendFormat:@"%@ %@\n", method, url];
    } else {
        [info appendString:@"\n\nSERVER -> CLIENT:\n"];
        NSString *version = (__bridge NSString *)(CFHTTPMessageCopyVersion(message));
        CFIndex statusCode = CFHTTPMessageGetResponseStatusCode(message);
        [info appendFormat:@"%@ %ld\n", version, statusCode];
    }
    NSDictionary *allHeaders = (__bridge NSDictionary *)(CFHTTPMessageCopyAllHeaderFields(message));
    for (NSString *header in allHeaders) {
        [info appendFormat:@"%@: %@\n", header, [allHeaders objectForKey:header]];
    }
    NSLog(@"%@\n\n", info);
}

- (NSString *)randomStringWithLength:(int)len {
    NSString *letters = @"abcdef0123456789";
    NSMutableString *randomString = [NSMutableString stringWithCapacity: len];
    for (int i=0; i<len; i++) {
        [randomString appendFormat: @"%C", [letters characterAtIndex:arc4random_uniform([letters length])]];
    }
    
    return randomString;
}

@end
