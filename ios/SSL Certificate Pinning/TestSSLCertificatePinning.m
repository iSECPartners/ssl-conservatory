//
//  TestSSLCertificatePinning.m
//  SSL Certificate Pinning
//
//  Created by Alban Diquet on 1/31/13.
//  Copyright (c) 2013 iSEC Partners. All rights reserved.
//

#import "TestSSLCertificatePinning.h"

#pragma mark Test Cases
@implementation TestSSLCertificatePinning


+ (void)startTest {
    
    // Build our dictionnary of domain => certificates
    NSMutableDictionary *domainsToPin = [[NSMutableDictionary alloc] init];
    
    // For Twitter, we pin the anchor/CA certificate
    NSData *twitterCertData = [TestSSLCertificatePinning loadCertificateFromFile:@"VeriSignClass3PublicPrimaryCertificationAuthority-G5.der"];
    if (twitterCertData == nil) {
        NSLog(@"Failed to load the certificates");
        return;
    }
    [domainsToPin setObject:twitterCertData forKey:@"twitter.com"];
    
    // For iSEC, we pin the server/leaf certificate
    NSData *isecCertData = [TestSSLCertificatePinning loadCertificateFromFile:@"www.isecpartners.com.der"];
    if (isecCertData == nil) {
        NSLog(@"Failed to load the certificates");
        return;
    }
    [domainsToPin setObject:isecCertData forKey:@"www.isecpartners.com"];
    
    // For NCC group, we pin an invalid certificate(Twitter's)
    [domainsToPin setObject:twitterCertData forKey:@"www.nccgroup.com"];
    
    
    // Save the SSL pins
    if ([SSLCertificatePinning loadSSLPinsFromDERCertificates:domainsToPin] != YES) {
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



+ (NSData*)loadCertificateFromFile:(NSString*)fileName {
    NSString *certPath = [[NSString alloc] initWithFormat:@"%@/%@", [[NSBundle mainBundle] bundlePath], fileName];
    NSData *certData = [[NSData alloc] initWithContentsOfFile:certPath];
    return certData;
}


@end


#pragma mark Delegate Class

@implementation NSURLConnectionDelegateTest

- (void)connectionDidFinishLoading:(NSURLConnection *)connection {
    
}

- (void)connection:(NSURLConnection *)connection didFailWithError:(NSError *)error {
    NSLog(@"NSURLConnectionDelegateTest - failed: %@", error);
}

- (void)connection:(NSURLConnection *)connection didReceiveData:(NSData *)data {
    //NSLog(@"NSURLConnectionDelegateTest - received %d bytes", [data length]);
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


