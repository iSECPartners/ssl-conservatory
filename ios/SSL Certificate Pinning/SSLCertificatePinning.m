
#import "SSLCertificatePinning.h"

// All the pinned certificate are stored in this plist on the filesystem
#define PINNED_KEYS_FILE_PATH "~/Library/SSLPins.plist"


@implementation SSLCertificatePinning


+ (BOOL)loadSSLPinsFromDERCertificates:(NSDictionary*)certificates {
    if (certificates == nil) {
        return NO;
    }
    
    // Serialize the dictionary to a plist
    NSError *error;
    NSData *plistData = [NSPropertyListSerialization dataWithPropertyList:certificates
                                                                   format:NSPropertyListXMLFormat_v1_0
                                                                  options:0
                                                                    error:&error];
    if (plistData == nil) {
        NSLog(@"Error serializing plist: %@", error);
        return NO;
    }
    
    // Write the plist to a pre-defined location on the filesystem
    NSError *writeError;
    if ([plistData writeToFile:[@PINNED_KEYS_FILE_PATH stringByExpandingTildeInPath]
                       options:NSDataWritingAtomic
                         error:&writeError] == NO) {
        NSLog(@"Error saving plist to the filesystem: %@", writeError);
        return NO;
    }
    
    return YES;
}


+ (BOOL)verifyPinnedCertificateForTrust:(SecTrustRef)trust andDomain:(NSString*)domain {
    if ((trust == NULL) || (domain == nil)) {
        return NO;
    }
    
    // Deserialize the plist that contains our SSL pins
    NSDictionary *SSLPinsDict = [NSDictionary dictionaryWithContentsOfFile:[@PINNED_KEYS_FILE_PATH stringByExpandingTildeInPath]];
    if (SSLPinsDict == nil) {
        NSLog(@"Error accessing the SSL Pins plist at %@", @PINNED_KEYS_FILE_PATH);
        return NO;
    }
    
    // Do we have a certificate pinned for that domain ?
    NSData *pinnedCertificate = [SSLPinsDict objectForKey:domain];
    if (pinnedCertificate == nil) {
        return NO;
    }
    
    // Check each certificate in the trust object
    // Unfortunately the anchor/CA certificate cannot be accessed this way
    CFIndex certsNb = SecTrustGetCertificateCount(trust);
    for(int i=0;i<certsNb;i++) {
        
        // Extract the certificate
        SecCertificateRef certificate = SecTrustGetCertificateAtIndex(trust, i);
        NSData* DERCertificate = (__bridge NSData*) SecCertificateCopyData(certificate);
        
        // Compare the two certificates
        if ([pinnedCertificate isEqualToData:DERCertificate]) {
            return YES;
        }
    }
    
    // Check the anchor/CA certificate separately
    SecCertificateRef anchorCertificate = SecCertificateCreateWithData(NULL, (__bridge CFDataRef)(pinnedCertificate));
    if (anchorCertificate == NULL) {
        return NO;
    }

    NSArray *anchorArray = [NSArray arrayWithObject:(__bridge id)(anchorCertificate)];
    if (SecTrustSetAnchorCertificates(trust, (__bridge CFArrayRef)(anchorArray)) != 0) {
        CFRelease(anchorCertificate);
        return NO;
    }
    
    SecTrustResultType trustResult;
    SecTrustEvaluate(trust, &trustResult);
    if (trustResult == kSecTrustResultUnspecified) {
        // The anchor certificate was pinned
        CFRelease(anchorCertificate);
        return YES;
    }
    CFRelease(anchorCertificate);
    
    // If we get here, we didn't find any matching certificate in the chain
    return NO;
}


@end



@implementation SSLPinnedNSURLConnectionDelegate

- (void)connection:(NSURLConnection *)connection willSendRequestForAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge {
    
    if([challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust]) {
        
        SecTrustRef serverTrust = [[challenge protectionSpace] serverTrust];
        NSString *domain = [[challenge protectionSpace] host];
        SecTrustResultType trustResult;
        
        // Validate the certificate chain with the device's trust store anyway
        // This *might* give use revocation checking
        SecTrustEvaluate(serverTrust, &trustResult);
        if (trustResult == kSecTrustResultUnspecified) {
            
            // Look for a pinned public key in the server's certificate chain
            if ([SSLCertificatePinning verifyPinnedCertificateForTrust:serverTrust andDomain:domain]) {

                // Found the certificate; continue connecting
                [challenge.sender useCredential:[NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust]
                     forAuthenticationChallenge:challenge];
            }
            else {
                // The certificate wasn't found in the certificate chain; cancel the connection
                [[challenge sender] cancelAuthenticationChallenge: challenge];
            }
        }
        else {
            // Certificate chain validation failed; cancel the connection
            [[challenge sender] cancelAuthenticationChallenge: challenge];
        }
    }
}
@end