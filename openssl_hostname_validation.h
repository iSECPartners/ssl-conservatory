
#define HOSTNAME_VALIDATION_MATCH_OK 1
#define HOSTNAME_VALIDATION_MATCH_FAILED -1
#define HOSTNAME_VALIDATION_ERR -2

int validate_hostname(char *hostname, X509 *server_cert);