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


### The ISPCertificatePinning class

#### Description

This class allows developers to whitelist a list of certificates for a given
domain in order to require at least one these "pinned" certificates to be part
of the server's certificate chain received when connecting to the domain over
SSL or HTTPS.

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

The ISPCertificatePinning API exposes two methods:

* _+(BOOL)setupSSLPinsUsingDictionnary:(NSDictionary*)domainsAndCertificates_
This method takes a dictionary with domain names as keys and arrays of DER-
encoded certificates as values, and stores them in a pre-defined location on
the filesystem. The ability to specify multiple certificates for a single
domain is useful when transitioning from an expiring certificate to a new one

* +(BOOL)verifyPinnedCertificateForTrust:(SecTrustRef)trust andDomain:(NSString*)domain
This method accesses the certificates previously loaded using the
setupSSLPinsUsingDictionnary: method and inspects the trust object's
certificate chain in order to find at least one certificate pinned to the
given domain. SecTrustEvaluate() should always be called before this method to
ensure that the certificate chain is valid.


### Convenience delegate classes

This library also provides convenience classes for connections relying on
NSURLConnection and NSURLSession.

The ISPPinnedNSURLConnectionDelegate and ISPPinnedNSURLSessionDelegate
implement the connection authentication methods within respectively the
the NSURLConnectionDelegate and NSURLSessionDelegate protocols, in order to
automatically validate the server's certificate based on SSL pins configured
using the setupSSLPinsUsingDictionnary: method.

To implement certificate pinning in their Apps, developers should simply extend
these classes when creating their own connection delegates.


### Changelog

* v3: Turned the Xcode project into a static library.
      Added certificate pinning delegate class for NSURLSession connections.
* v2: Added the ability to pin multiple certificates to a single domain.
* v1: Initial release.


### License

See ../LICENSE.


### Author

Alban Diquet - https://github.com/nabla-c0d3
