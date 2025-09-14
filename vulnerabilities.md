# Security Vulnerabilities Report

This document outlines the critical security vulnerabilities discovered in the NSA application.

## 1. Hardcoded Database Credentials (Critical)
**Location**: `docker-compose.yaml` lines 34-36
**Description**: Database credentials are hardcoded in the configuration file.
```yaml
- POSTGRES_USER=dbuser
- POSTGRES_DB=vulndb
- POSTGRES_PASSWORD=superSecret
```
**Impact**: Anyone with access to the repository can see the database credentials.
**Risk Level**: Critical

## 2. Weak Default User Passwords (Critical)  
**Location**: `store2/src/main/java/com/nsa/datagen/DataGenerationBean.java` lines 36-61
**Description**: All default users use the same weak bcrypt hash corresponding to password "password".
```java
// Hash: $2a$12$12ch2GaRW20Biug.PZ/LPOm9iUfQoz7KdhfQVxuY0.ZmwpkQL.j1i = "password"
nullptr.password = "$2a$12$12ch2GaRW20Biug.PZ/LPOm9iUfQoz7KdhfQVxuY0.ZmwpkQL.j1i";
```
**Impact**: Attackers can login as any default user with password "password".
**Risk Level**: Critical

## 3. Insecure RSA Implementation (High)
**Location**: `web/crypto_utils.py` lines 7-27
**Description**: Custom RSA implementation with small key sizes and weak prime generation.
```python
p = random.randint(100_000, 200_000)  # Way too small for RSA
q = random.randint(100_000, 200_000)
```
**Impact**: RSA keys can be easily factored, allowing decryption of chat data.
**Risk Level**: High

## 4. Server-Side Request Forgery (SSRF) (High)
**Location**: `store2/src/main/java/com/nsa/endpoint/AccountResource.java` lines 211-233
**Description**: The fetchImageFromUrl method has inadequate SSRF protection that can be bypassed.
```java
boolean isLocalHost = isThisMyIpAddress(InetAddress.getByName(request.uri().getHost()));
```
**Impact**: Attackers can access internal services and scan internal networks.
**Risk Level**: High

## 5. Authorization Bypass in Subordinates Endpoint (High)
**Location**: `store2/src/main/java/com/nsa/endpoint/AccountResource.java` lines 141-152
**Description**: The subordinates query allows users to see accounts with equal or lower permission levels.
```java
var query = Account.find("from Account where permissionLevel <= ?1", Sort.by("username"), account.permissionLevel);
```
**Impact**: Users can access information about accounts they shouldn't see.
**Risk Level**: High

## 6. SQL Injection Potential (Medium)
**Location**: `store2/src/main/java/com/nsa/endpoint/AccountResource.java` line 146
**Description**: While using parameterized queries, the HQL structure could be vulnerable to advanced injection.
**Impact**: Potential database compromise.
**Risk Level**: Medium

## 7. Exposed Test/Debug Endpoints (Critical)
**Location**: `store2/src/main/java/com/nsa/endpoint/TestResource.java` lines 30-38
**Description**: Debug endpoint allows privilege escalation to super admin from localhost.
```java
@POST
@Path("{username}/superAdmin")
public void superAdmin(@PathParam("username") String username) {
    checkIsLocalhost(); // Can be bypassed
    account.permissionLevel = Account.SUPER_ADMIN_PERMISSION_LEVEL;
}
```
**Impact**: Privilege escalation to super admin if localhost check is bypassed.
**Risk Level**: Critical

## 8. Weak Session Management (Medium)
**Location**: `web/server.py` line 43
**Description**: Session secret key is regenerated on each restart, invalidating all sessions.
```python
app.secret_key = secrets.token_urlsafe()
```
**Impact**: Poor user experience and potential session fixation.
**Risk Level**: Medium

## 9. Information Disclosure (Low)
**Location**: `web/keys/keys.json`
**Description**: Hardcoded RSA keys are exposed in the repository.
**Impact**: Cryptographic operations can be compromised.
**Risk Level**: Low

## 10. Debug Mode Enabled (Medium)
**Location**: `web/server.py` line 475
**Description**: Flask debug mode is enabled in production.
```python
app.run(port=1337, debug=True)
```
**Impact**: Exposes sensitive debugging information and allows code execution.
**Risk Level**: Medium

## Summary
- 4 Critical vulnerabilities
- 3 High vulnerabilities  
- 3 Medium/Low vulnerabilities

All vulnerabilities require immediate attention to secure the application.