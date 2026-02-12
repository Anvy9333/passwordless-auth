# WebAuthn Flow 

WebAuthn is one of the most secure passwordless authentication based on asymmetric cryptography.

## Registration

1. The server generates a challenge.
2. The browser asks the authenticator (e.g. security key).
3. The authenticator generates a key pair.
4. The public key is sent to the server.
5. The private key remains on the device.

## Authentication

1. Server sends a challenge.
2. Client signs it using the private key.
3. Server verifies the signature with the stored public key.
4. If valid, access is granted.
