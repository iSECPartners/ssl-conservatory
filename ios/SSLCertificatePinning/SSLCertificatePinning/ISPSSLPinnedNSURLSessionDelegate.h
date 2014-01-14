//
//  ISPSSLPinnedNSURLSessionDelegate.h
//  SSLCertificatePinning
//
//  Created by Alban Diquet on 1/14/14.
//  Copyright (c) 2014 iSEC Partners. All rights reserved.
//

#import <Foundation/Foundation.h>


/** Convenience class to automatically perform certificate pinning for NSURLSession.
 
 ISPSSLPinnedNSURLSessionDelegate is designed to be subclassed in order to
 implement an NSURLSession class. The
 URLSession:didReceiveChallenge:completionHandler: method it implements
 will automatically validate that at least one the certificates pinned to the domain the
 connection is accessing is part of the server's certificate chain.
 
 */
@interface ISPSSLPinnedNSURLSessionDelegate : NSObject

- (void)URLSession:(NSURLSession *)session didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition disposition, NSURLCredential *credential))completionHandler;

@end
