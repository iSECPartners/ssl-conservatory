#include <openssl/x509v3.h>
#include <openssl/ssl.h>

#include "openssl_hostname_validation.h"


#define HOSTNAME_MAX_SIZE 255

/**
* Tries to find a match for hostname in the certificate's Common Name field.
*
* Returns HOSTNAME_VALIDATION_MATCH_OK if a match was found.
* Returns HOSTNAME_VALIDATION_MATCH_FAILED if no matches were found.
* Returns HOSTNAME_VALIDATION_ERR if the Common Name could not be extracted.
*/
static int matches_common_name(char *hostname, X509 *server_cert) {
	int common_name_loc = -1;
	int hostname_matched = HOSTNAME_VALIDATION_ERR;
	X509_NAME_ENTRY *common_name_entry = NULL;
	ASN1_STRING *common_name_asn1 = NULL;
	char *common_name_str = NULL;

	// Find the position of the CN field in the Subject field of the certificate
	common_name_loc = X509_NAME_get_index_by_NID(X509_get_subject_name(server_cert), NID_commonName, -1);
	if (common_name_loc < 0) {
		goto error;
	}

	// Extract the CN field
	common_name_entry = X509_NAME_get_entry(X509_get_subject_name(server_cert), common_name_loc);
	if (common_name_entry == NULL) {
		goto error;
	}

	// Convert the CN field to a C string
	common_name_asn1 = X509_NAME_ENTRY_get_data(common_name_entry);
	if (common_name_asn1 == NULL) {
		goto error;
	}			
	common_name_str = (char *) ASN1_STRING_data(common_name_asn1);

	// Make sure there isn't an embedded null character in the CN
	if (ASN1_STRING_length(common_name_asn1) != strlen(common_name_str)) {
		goto error;
	}

	// Compare expected hostname with the CN
	if (strcasecmp(hostname, common_name_str) == 0) {
		hostname_matched = HOSTNAME_VALIDATION_MATCH_OK;
	}
	else {
		hostname_matched = HOSTNAME_VALIDATION_MATCH_FAILED;
	}

error:
	return hostname_matched;
}


/**
* Tries to find a match for hostname in the certificate's Subject Alternative Name extension.
*
* Returns HOSTNAME_VALIDATION_MATCH_OK if a match was found.
* Returns HOSTNAME_VALIDATION_MATCH_FAILED if no matches were found.
* Returns HOSTNAME_VALIDATION_ERR if the SAN extension was not present in the certificate.
*/
static int matches_subject_alternative_name(char *hostname, X509 *server_cert) {
	int hostname_matched = HOSTNAME_VALIDATION_ERR;
	int i;
	int san_names_nb = -1;
	STACK_OF(GENERAL_NAME) *san_names = NULL;

	// Try to extract the names within the SAN extension from the certificate
	san_names = X509_get_ext_d2i(server_cert, NID_subject_alt_name, NULL, NULL);
	if (san_names == NULL) {
		goto error;
	}
	san_names_nb = sk_GENERAL_NAME_num(san_names);
	hostname_matched = HOSTNAME_VALIDATION_MATCH_FAILED;

	// Check each name within the extension
	for(i=0; i<san_names_nb; i++) {
		const GENERAL_NAME * current_name = sk_GENERAL_NAME_value(san_names, i);

		if (current_name->type == GEN_DNS) {
			// Current name is a DNS name, let's check it
			char * dns_name = (char *) ASN1_STRING_data(current_name->d.dNSName);

			// Make sure there isn't an embedded null character in the DNS name
			if (ASN1_STRING_length(current_name->d.dNSName) == strlen(dns_name)) {

				// Compare expected hostname with the DNS name
				if (strcasecmp(hostname, dns_name) == 0) {
					hostname_matched = HOSTNAME_VALIDATION_MATCH_OK;
					break;
				}
			}
		}
	}

error:
	return hostname_matched;
}


/**
* Validates the server's identity by looking for the expected hostname in the
* server's certificate. As described in RFC 6125, it first tries to find a match
* in the Subject Alternative Name extension. If the extension is not present in
* the certificate, it checks the Common Name instead.
*
* Returns HOSTNAME_VALIDATION_MATCH_OK if a match was found.
* Returns HOSTNAME_VALIDATION_MATCH_FAILED if no matches were found.
* Returns HOSTNAME_VALIDATION_ERR if there was an error.
*/
int validate_hostname(char *hostname, X509 *server_cert) {
	int hostname_matched = HOSTNAME_VALIDATION_ERR;

	if((hostname == NULL) || (server_cert == NULL))
		goto error;

	// First try the Subject Alternative Names extension
	hostname_matched = matches_subject_alternative_name(hostname, server_cert);
	if (hostname_matched == HOSTNAME_VALIDATION_ERR) {
		// Extension was not found: try the Common Name
		hostname_matched = matches_common_name(hostname, server_cert);
	}

error:
	return hostname_matched;
}
