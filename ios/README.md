The SSL Conservatory: iOS Certificate Pinning
=============================================


### SSL pinning

When an iOS app only needs to communicate to a well-defined set of servers
over SSL, the security of the app's network communications can be improved
through SSL pinning. By requiring a specific certificate to be part of the
server's certificate chain, the threat of a rogue CA or a CA compromise is
significantly reduced.

The following blog post provides more information regarding SSL pinning on
iOS: https://www.isecpartners.com/news-events/news/2013/february/ssl-pinning-on-ios.aspx


### The SSLCertificatePinning class

This implementation allows a developer to pin a certificate for any number of
domains the application needs to connect to. Specifically, developers can
whitelist a certificate that will have to be part of the certificate chain
sent back by the server during the SSL handshake. This gives additional
flexibility as developers can decide to pin the CA/anchor certificate, the
server/leaf certificate, or any intermediate certificate for a given domain.
Each option has different advantages and limitations; for example, pinning the
server/leaf certificate provides the best security but the certificate is
going to change more often than the CA/anchor certificate. 
A change in the certificate (for example because it expired) will result in
the app being unable to connect to the server. When that happens, the new
certificate can be pushed to users by releasing a new version of the iOS app.

The SSLCertificatePinning API exposes two methods and a convenience class:

* +(BOOL)loadSSLPinsFromDERCertificates:(NSDictionary*)certificates
This method takes a dictionary with domain names as keys and DER-encoded
certificates as values and stores them in a pre-defined location on the
filesystem.

* +(BOOL)verifyPinnedCertificateForTrust:(SecTrustRef)trust andDomain:(NSString*)domain
This method accesses the certificates previously loaded using the
loadSSLPinsFromDERCertificates: method and looks in the trust object's
certificate chain for a certificate pinned to the given domain.
SecTrustEvaluate() should always be called before this method to ensure that
the certificate chain is valid.

* The SSLPinnedNSURLConnectionDelegate class is designed to be subclassed and
extended to implement the NSURLConnectionDelegate protocol and be used as a
delegate for NSURLConnection objects. This class implements the
connection:willSendRequestForAuthenticationChallenge: method so that it
automatically validates that the certificate pinned to the domain the
NSURLConnection object is accessing is part of the server's certificate chain.


### Author

Alban Diquet - https://github.com/nabla-c0d3
