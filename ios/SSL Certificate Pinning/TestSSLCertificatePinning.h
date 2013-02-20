
#import <Foundation/Foundation.h>
#import "SSLCertificatePinning.h"


#pragma mark Test Cases
@interface TestSSLCertificatePinning : NSObject

+ (void)startTest;

@end


#pragma mark Delegate Class
/**
 Our NSURLConnectionDelegate test class
 
 We subclass SSLPinnedNSURLConnectionDelegate so that our test delegate automatically performs certificate pinning.
 
 */
@interface NSURLConnectionDelegateTest : SSLPinnedNSURLConnectionDelegate <NSURLConnectionDelegate>

- (void)connectionDidFinishLoading:(NSURLConnection *)connection;
- (void)connection:(NSURLConnection *)connection didReceiveData:(NSData *)data;
- (void)connection:(NSURLConnection *)connection didFailWithError:(NSError *)error;
- (NSCachedURLResponse *)connection:(NSURLConnection *)connection willCacheResponse:(NSCachedURLResponse *)cachedResponse;
- (void)connection:(NSURLConnection *)connection didReceiveResponse:(NSURLResponse *)response;
- (NSURLRequest *)connection:(NSURLConnection *)connection willSendRequest:(NSURLRequest *)request redirectResponse:(NSURLResponse *)redirectResponse;

@end