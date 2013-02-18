
#import <Foundation/Foundation.h>



/** This class implements certificate pinning utility functions.
 
 First, the certificates and domains to pin should be loaded using
 loadSSLPinsFromDERCertificates:. This method will store them in
 ""~/Library/SSLPins.plist".
 
 Then, the verifyPinnedCertificateForTrust:andDomain: method can be
 used to validate that the certificate pinned to a specific domain is in
 the server's certificate chain when connecting to it.
 This method should be used in the
 connection:willSendRequestForAuthenticationChallenge: method of the
 NSURLConnectionDelegate object that is used to perform the connection.
 
 Alternatively, the SSLPinnedNSURLConnectionDelegate class can be
 used instead as the connection delegate.
 
 */
@interface SSLCertificatePinning : NSObject


/**
 Certificate pinning loading method
 
 Takes a dictionary with domain names as keys and DER-encoded certificates as values
 and stores them in a pre-defined location on the filesystem.
 
 @param certificates a dictionnary with domain names as keys and DER-encoded certificates as values
 @return BOOL successfully loaded the public keys and domains
 
 */
+ (BOOL)loadSSLPinsFromDERCertificates:(NSDictionary*)certificates;


/**
 Certificate pinning validation method
 
 Accesses the certificates previously loaded using the loadSSLPinsFromDERCertificates: method
 and looks in the trust object's certificate chain for a certificate pinned to the given domain.
 
 @param trust the trust object whose certificate chain must contain the certificate previously pinned to the given domain
 @param domain the domain we're trying to connect to
 @return BOOL found the domain's pinned certificate in the trust object's certificate chain
 
 */
+ (BOOL)verifyPinnedCertificateForTrust:(SecTrustRef)trust andDomain:(NSString*)domain;

@end


/** Convenience class to automatically perform certificate pinning.
 
 SSLPinnedNSURLConnectionDelegate is designed to be subclassed in order to
 implement an NSURLConnectionDelegate class. The
 connection:willSendRequestForAuthenticationChallenge: method it implements
 will automatically validate that the certificate pinned to the domain the
 connection is accessing is part of the server's certificate chain.
 
 */
@interface SSLPinnedNSURLConnectionDelegate : NSObject

- (void)connection:(NSURLConnection *)connection willSendRequestForAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge;

@end