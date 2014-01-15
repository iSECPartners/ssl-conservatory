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

@end



@interface NSURLConnectionTests : XCTestCase

@end

@implementation NSURLConnectionTests

- (void)setUp
{
    [super setUp];
}

- (void)tearDown
{
    [super tearDown];
}


+ (NSData*)loadCertificateFromFile:(NSString*)fileName {
    NSString *certPath = [[NSString alloc] initWithFormat:@"%@/%@", [[NSBundle mainBundle] bundlePath], fileName];
    NSData *certData = [[NSData alloc] initWithContentsOfFile:certPath];
    return certData;
}


#pragma mark SSL pinning test

- (void)testNSURLConnectionSSLPinning
{

    // Build our dictionnary of domain => certificates
    NSMutableDictionary *domainsToPin = [[NSMutableDictionary alloc] init];
    
    
    // For Twitter, we pin the anchor/CA certificate
    NSData *twitterCertData = [NSURLConnectionTests loadCertificateFromFile:@"VeriSignClass3PublicPrimaryCertificationAuthority-G5.der"];
    if (twitterCertData == nil) {
        NSLog(@"Failed to load a certificate");
        return;
    }
    NSArray *twitterTrustedCerts = [NSArray arrayWithObject:twitterCertData];
    [domainsToPin setObject:twitterTrustedCerts forKey:@"twitter.com"];
    
    
    // For iSEC, we pin the server/leaf certificate
    NSData *isecCertData = [NSURLConnectionTests loadCertificateFromFile:@"www.isecpartners.com.der"];
    if (isecCertData == nil) {
        NSLog(@"Failed to load a certificate");
        return;
    }
    // We pin the same cert twice just to show that you can pin multiple certs to a single domain
    // This is useful when transitioning between two certificates on the server
    // The connection will be succesful if at least one of the pinned certs is found in the server's certificate trust chain
    NSArray *iSECTrustedCerts = [NSArray arrayWithObjects:isecCertData, isecCertData, nil];
    [domainsToPin setObject:iSECTrustedCerts forKey:@"www.isecpartners.com"];
    
    
    // For NCC group, we pin an invalid certificate (Twitter's)
    NSArray *NCCTrustedCerts = [NSArray arrayWithObject:twitterCertData];
    [domainsToPin setObject:NCCTrustedCerts forKey:@"www.nccgroup.com"];
    
    
    // Save the SSL pins
    if ([ISPSSLCertificatePinning storeSSLPinsFromDERCertificates:domainsToPin] != YES) {
        NSLog(@"Failed to pin the certificates");
        return;
    }
    
    // Connect to Twitter
    NSLog(@"Connecting to www.twitter.com");
    NSURLRequest *request = [NSURLRequest requestWithURL:[NSURL URLWithString:@"https://twitter.com/"]];
    NSURLConnectionDelegateTest *connectionDelegate = [[NSURLConnectionDelegateTest alloc] init];
    NSURLConnection *connection=[[NSURLConnection alloc] initWithRequest:request delegate:connectionDelegate];
    [connection start];
    
    // Connect to iSEC
    NSLog(@"Connecting to www.isecpartners.com");
    NSURLRequest *request2 = [NSURLRequest requestWithURL:[NSURL URLWithString:@"https://www.isecpartners.com/"]];
    NSURLConnectionDelegateTest *connectionDelegate2 = [[NSURLConnectionDelegateTest alloc] init];
    NSURLConnection *connection2 = [[NSURLConnection alloc] initWithRequest:request2 delegate:connectionDelegate2];
    [connection2 start];
    
    // Connect to NCC Group => will fail
    NSLog(@"Connecting to www.nccgroup.com");
    NSURLRequest *request3 = [NSURLRequest requestWithURL:[NSURL URLWithString:@"https://www.nccgroup.com/"]];
    NSURLConnectionDelegateTest *connectionDelegate3 = [[NSURLConnectionDelegateTest alloc] init];
    NSURLConnection *connection3 = [[NSURLConnection alloc] initWithRequest:request3 delegate:connectionDelegate3];
    [connection3 start];
}


@end




#pragma mark Delegate class

@implementation NSURLConnectionDelegateTest

- (void)connectionDidFinishLoading:(NSURLConnection *)connection {
    
}

- (void)connection:(NSURLConnection *)connection didFailWithError:(NSError *)error {
    NSLog(@"NSURLConnectionDelegateTest - failed: %@", error);
}

- (void)connection:(NSURLConnection *)connection didReceiveData:(NSData *)data {
    NSLog(@"NSURLConnectionDelegateTest - received %d bytes", [data length]);
}

- (NSCachedURLResponse *)connection:(NSURLConnection *)connection willCacheResponse:(NSCachedURLResponse *)cachedResponse {
    return cachedResponse;
}

- (void)connection:(NSURLConnection *)connection didReceiveResponse:(NSURLResponse *)response {
    NSLog(@"NSURLConnectionDelegateTest - success: %@", [[response URL] host]);
}

- (NSURLRequest *)connection:(NSURLConnection *)connection willSendRequest:(NSURLRequest *)request redirectResponse:(NSURLResponse *)redirectResponse {
    return request;
}

@end