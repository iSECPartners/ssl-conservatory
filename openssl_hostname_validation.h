
typedef enum {
	MatchFound,
	MatchNotFound,
	NoSANPresent,
	MalformedCertificate,
	Error
} HostnameValidationResult;

HostnameValidationResult validate_hostname(const char *hostname, const X509 *server_cert);
