# NSA Application - Security Hardened

This NSA application has been security hardened to address critical vulnerabilities. 

## Security Fixes Applied

### Critical Vulnerabilities Fixed:
1. **Hardcoded Database Credentials** - Now uses environment variables
2. **Weak Default Passwords** - Default users now have secure unique passwords
3. **Exposed Test Endpoints** - Test endpoints now require special environment variable
4. **Server-Side Request Forgery (SSRF)** - Enhanced URL validation and blocking

### High Priority Vulnerabilities Fixed:
5. **Insecure RSA Implementation** - Replaced with proper cryptographic library
6. **Authorization Bypass** - Fixed subordinates query to prevent lateral access
7. **Weak Session Management** - Session keys now persistent via environment variables

### Additional Security Improvements:
8. **Input Validation** - Added validation to all user inputs
9. **Rate Limiting** - Basic rate limiting for login attempts  
10. **Secure Cookies** - HTTPOnly, Secure, and SameSite flags added
11. **Error Handling** - Improved error handling without information disclosure
12. **Debug Mode** - Debug mode disabled in production

## Setup Instructions

1. Copy environment file:
   ```bash
   cp .env.example .env
   ```

2. Generate secure values and update .env:
   ```bash
   # Generate database password
   openssl rand -base64 32
   
   # Generate Flask secret key
   python -c "import secrets; print(secrets.token_urlsafe(32))"
   ```

3. Update your .env file with the generated secure values

4. Deploy with Docker Compose:
   ```bash
   docker compose up -d --build
   ```

## Default Account Credentials

**IMPORTANT**: Default accounts now use secure passwords. Update these immediately after first deployment:

- `nullptr`: `nptr_S3cur3P@ss_2024!`
- `wheatley`: `whtly_S3cur3P@ss_2024!`
- `pchung`: `pchng_S3cur3P@ss_2024!`
- `superadmin`: `supr_S3cur3P@ss_2024!`

## Security Recommendations

1. **Change default passwords immediately** after first login
2. **Use strong environment variables** as shown in .env.example
3. **Disable test endpoints** in production by not setting NSA_ADMIN_ESCALATION_KEY
4. **Monitor logs** for security events
5. **Regular security updates** for dependencies
6. **Use HTTPS** in production with proper TLS certificates
7. **Implement additional monitoring** and alerting

## Files Modified for Security

- `docker-compose.yaml` - Environment variable usage
- `store2/src/main/java/com/nsa/datagen/DataGenerationBean.java` - Secure passwords
- `store2/src/main/java/com/nsa/endpoint/AccountResource.java` - SSRF protection, authorization fixes
- `store2/src/main/java/com/nsa/endpoint/TestResource.java` - Enhanced test endpoint security
- `web/crypto_utils.py` - Proper RSA implementation
- `web/server.py` - Session management, input validation, rate limiting
- `web/keys/keys.json` - Removed hardcoded keys

## Vulnerability Documentation

See:
- `vulnerabilities.md` - Detailed vulnerability analysis
- `exploits.md` - Exploit commands for testing and rule creation

## Testing Security Fixes

The exploits.md file contains curl commands that can be used to verify the security fixes are working properly and to create WAF/IDS rules.