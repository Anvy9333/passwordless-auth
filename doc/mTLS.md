# Mutual TLS (mTLS)

Mutual TLS requires both:

- Server authentication (standard TLS)
- Client authentication (client certificate)

For doctor accounts:

- Each doctor possesses a client certificate
- The server verifies the certificate during TLS handshake
- Access is only granted to trusted certificate holders

This provides strong identity binding and device-level trust. 

If you want to issue a certificate for a doctor, you need to generate it from a PKI and replace all the needed cryptography materials in the server.