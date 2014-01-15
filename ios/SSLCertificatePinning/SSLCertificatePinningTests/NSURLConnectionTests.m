//
//  NSURLConnectionTests.m
//  SSLCertificatePinning
//
//  Created by Alban Diquet on 1/14/14.
//  Copyright (c) 2014 iSEC Partners. All rights reserved.
//

#import <XCTest/XCTest.h>

#import "ISPSSLPinnedNSURLConnectionDelegate.h"
#import "ISPSSLCertificatePinning.h"


// Delegate we'll use for our tests
@interface NSURLConnectionDelegateTest : ISPSSLPinnedNSURLConnectionDelegate <NSURLConnectionDelegate>
    @property BOOL connectionFinished;
    @property BOOL connectionSucceeded;
@end



@interface NSURLConnectionTests : XCTestCase

@end


@implementation NSURLConnectionTests


+ (NSData*)loadCertificateFromFile:(NSString*)fileName {
    NSString *certPath =  [[NSBundle bundleForClass:[self class]] pathForResource:fileName ofType:@"der"];
    NSData *certData = [[NSData alloc] initWithContentsOfFile:certPath];
    return certData;
}


- (void)setUp
{
    [super setUp];
}

- (void)tearDown
{
    [super tearDown];
}

#pragma mark SSL pinning test


// This is sample code to demonstrate how to implement certificate pinning with NSURLConnection
- (void)testNSURLConnectionSSLPinning
{

    // Build our dictionnary of domain => certificates
    NSMutableDictionary *domainsToPin = [[NSMutableDictionary alloc] init];
    
    
    // For Twitter, we pin the anchor/CA certificate
    NSData *twitterCertData = [NSURLConnectionTests loadCertificateFromFile:@"VeriSignClass3PublicPrimaryCertificationAuthority-G5"];
    if (twitterCertData == nil) {
        NSLog(@"Failed to load a certificate");
    }
    NSArray *twitterTrustedCerts = [NSArray arrayWithObject:twitterCertData];
    [domainsToPin setObject:twitterTrustedCerts forKey:@"twitter.com"];
    
    
    // For iSEC, we pin the server/leaf certificate
    NSData *isecCertData = [NSURLConnectionTests loadCertificateFromFile:@"www.isecpartners.com"];
    if (isecCertData == nil) {
        NSLog(@"Failed to load a certificate");
    }
    // We also pin Twitter's CA cert just to show that you can pin multiple certs to a single domain
    // This is useful when transitioning between two certificates on the server
    // The connection will be succesful if at least one of the pinned certs is found in the server's certificate trust chain
    NSArray *iSECTrustedCerts = [NSArray arrayWithObjects:isecCertData, twitterCertData, nil];
    [domainsToPin setObject:iSECTrustedCerts forKey:@"www.isecpartners.com"];
    
    
    // For NCC group, we pin an invalid certificate (Twitter's)
    NSArray *NCCTrustedCerts = [NSArray arrayWithObject:twitterCertData];
    [domainsToPin setObject:NCCTrustedCerts forKey:@"www.nccgroup.com"];
    
    
    // Save the SSL pins
    if ([ISPSSLCertificatePinning setupSSLPinsUsingDictionnary:domainsToPin] != YES) {
        NSLog(@"Failed to pin the certificates");
    }
    
    // Connect to Twitter
    NSURLRequest *request = [NSURLRequest requestWithURL:[NSURL URLWithString:@"https://twitter.com/"]];
    NSURLConnectionDelegateTest *connectionDelegate = [[NSURLConnectionDelegateTest alloc] init];
    NSURLConnection *connection=[[NSURLConnection alloc] initWithRequest:request delegate:connectionDelegate];
    [connection start];
    
    // Connect to iSEC
    NSURLRequest *request2 = [NSURLRequest requestWithURL:[NSURL URLWithString:@"https://www.isecpartners.com/"]];
    NSURLConnectionDelegateTest *connectionDelegate2 = [[NSURLConnectionDelegateTest alloc] init];
    NSURLConnection *connection2 = [[NSURLConnection alloc] initWithRequest:request2 delegate:connectionDelegate2];
    [connection2 start];
    
    // Connect to NCC Group => will fail
    NSURLRequest *request3 = [NSURLRequest requestWithURL:[NSURL URLWithString:@"https://www.nccgroup.com/"]];
    NSURLConnectionDelegateTest *connectionDelegate3 = [[NSURLConnectionDelegateTest alloc] init];
    NSURLConnection *connection3 = [[NSURLConnection alloc] initWithRequest:request3 delegate:connectionDelegate3];
    [connection3 start];
    
    
    // Do some polling to wait for the connections to complete
#define POLL_INTERVAL 0.2 // 200ms
#define N_SEC_TO_POLL 3.0 // poll for 3s
#define MAX_POLL_COUNT N_SEC_TO_POLL / POLL_INTERVAL
    
    NSUInteger pollCount = 0;
    while (!(connectionDelegate.connectionFinished && connectionDelegate2.connectionFinished && connectionDelegate3.connectionFinished) && (pollCount < MAX_POLL_COUNT)) {
        NSDate* untilDate = [NSDate dateWithTimeIntervalSinceNow:POLL_INTERVAL];
        [[NSRunLoop currentRunLoop] runUntilDate:untilDate];
        pollCount++;
    }
    
    if (pollCount == MAX_POLL_COUNT) {
        XCTFail(@"Could not connect in time");
    }
    
    
    // The first two connections should succeed
    XCTAssertTrue(connectionDelegate.connectionSucceeded, @"Connection to Twitter failed");
    XCTAssertTrue(connectionDelegate2.connectionSucceeded, @"Connection to iSEC Partners failed");
    
    // The last connection should fail
    XCTAssertFalse(connectionDelegate3.connectionSucceeded, @"Connection to NCC succeeded");
}


@end




#pragma mark Delegate class

@implementation NSURLConnectionDelegateTest

@synthesize connectionSucceeded;
@synthesize connectionFinished;

-(instancetype) init {
    if (self = [super init])
    {
        self.connectionSucceeded = NO;
        self.connectionFinished = NO;
    }
    return self;
}


- (void)connectionDidFinishLoading:(NSURLConnection *)connection {
    self.connectionSucceeded = YES;
    self.connectionFinished = YES;
}

- (void)connection:(NSURLConnection *)connection didFailWithError:(NSError *)error {
    self.connectionSucceeded = NO;
    self.connectionFinished = YES;
}

- (void)connection:(NSURLConnection *)connection didReceiveData:(NSData *)data {
    self.connectionSucceeded = YES;
    self.connectionFinished = YES;
}

- (NSCachedURLResponse *)connection:(NSURLConnection *)connection willCacheResponse:(NSCachedURLResponse *)cachedResponse {
    return cachedResponse;
}

- (void)connection:(NSURLConnection *)connection didReceiveResponse:(NSURLResponse *)response {
    self.connectionSucceeded = YES;
    self.connectionFinished = YES;
}

- (NSURLRequest *)connection:(NSURLConnection *)connection willSendRequest:(NSURLRequest *)request redirectResponse:(NSURLResponse *)redirectResponse {
    return request;
}

@end