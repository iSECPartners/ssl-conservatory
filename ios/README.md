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

#### Description

This implementation allows a developer to pin certificates for any number of
domains the application needs to connect to. Specifically, developers can
whitelist a certificate that will be required to be part of the server's
certificate chain, when connecting to the server using SSL or HTTPS.

As any certificate in the certificate chain can be pinned, developers can
decide to pin the CA/anchor certificate, the server/leaf certificate, or any
intermediate certificate for a given domain. Each option has different
advantages and limitations; for example, pinning the server/leaf certificate
provides the best security but this certificate is going to change more often
than the CA/anchor certificate.

A change in the certificate presented by the server (for example because the
previous certificate expired) will result in the application being unable to
connect to the server until its pinned certificate has been updated as well.
To address this scenario, multiple certificates can be pinned to a single
domain. This gives developers the ability to transition from an expiring
certificate to a new one by releasing a new version of their application that
pins both certificates to the server's domain.


#### API

The SSLCertificatePinning API exposes two methods and a convenience class:

* +(BOOL)loadSSLPinsFromDERCertificates:(NSDictionary*)certificates
This method takes a dictionary with domain names as keys and arrays of DER-
encoded certificates as values, and stores them in a pre-defined location on
the filesystem. The ability to specify multiple certificates for a single
domain is useful when transitioning from an expiring certificate to a new one.

* +(BOOL)verifyPinnedCertificateForTrust:(SecTrustRef)trust andDomain:(NSString*)domain
This method accesses the certificates previously loaded using the
loadSSLPinsFromDERCertificates: method and inspects the trust object's
certificate chain in order to find at least one certificate pinned to the
given domain. SecTrustEvaluate() should always be called before this method to
ensure that the certificate chain is valid.

* The SSLPinnedNSURLConnectionDelegate class is designed to be subclassed and
extended to implement the NSURLConnectionDelegate protocol and be used as a
delegate for NSURLConnection objects. This class implements the
connection:willSendRequestForAuthenticationChallenge: method so that it
automatically validates that at least one of the certificates pinned to the
domain the NSURLConnection object is accessing is part of the server's
certificate chain.


### Changelog

* v2: Added the ability to pin multiple certificates to a single domain.
* v1: Initial release.


### License

See ../LICENSE.


### Author

Alban Diquet - https://github.com/nabla-c0d3
