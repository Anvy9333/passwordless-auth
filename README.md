# passwordless-auth
Passwordless authentification using WebAuthn, mTLS, JWT 


## Overview

This project implements a passwordless authentication system
with strong cryptographic guarantees and role-based separation.

It combines:

- WebAuthn for phishing-resistant authentication
- JWT for session management
- Mutual TLS (mTLS) for strong client authentication
- MongoDB for credential storage
- React frontend + Node.js backend

Two roles are supported:

- **Patient** → WebAuthn + JWT
- **Doctor** → WebAuthn + mTLS + JWT

---


## Architecture

Frontend: React  
Backend: Node.js (Express)  
Database: MongoDB  

### Patient authentication
- WebAuthn registration & login
- Credential public key stored server-side
- JWT issued after successful authentication

### Doctor authentication
- WebAuthn identity verification
- Client certificate authentication via mTLS
- Strong device binding through PKI

---

## Security Design Highlights

- No passwords stored
- Private keys never leave the client device
- Phishing-resistant authentication
- Certificate-based identity for high-privilege roles

---

## Context

Academic project – Master 1 Cybersecurity  
Université libre de Bruxelles (ULB)

This repository contains a cleaned and partial version
for demonstration and portfolio purposes without any secret, to launch the app you need to regenerate the keys/certificates.
