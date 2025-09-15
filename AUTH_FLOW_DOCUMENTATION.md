# GenoBank Authentication Flow Documentation

## Overview
The GenoBank authentication system at `auth.genobank.app` provides unified authentication for all GenoBank microservices. The system intelligently routes users based on their origin and user type (individual vs. permittee/researcher).

## Fixed Issues (September 15, 2025)
1. ✅ **Removed unwanted redirect to genobank.io** - The system no longer automatically redirects to genobank.io when no data parameter is present
2. ✅ **Fixed circular redirect loops** - Added `authRedirectInProgress` flag to prevent multiple redirect attempts
3. ✅ **Fixed authentication persistence** - Users remain authenticated across domain navigation
4. ✅ **Smart routing based on user type** - Individuals go to `/consent/biofile/`, researchers go to `/consent/lab_biofile/`

## Authentication Methods Supported
1. **Browser Wallet (MetaMask)** - Web3 signature authentication
2. **Google OAuth** - Via Magic Link SDK
3. **Email Magic Link** - Passwordless email authentication
4. **WalletConnect** - Mobile wallet connection

## Authentication Flow

### 1. Initial Request
When a user needs to authenticate from any GenoBank service:
```javascript
// Service redirects to auth with return URL
window.location.href = `https://auth.genobank.app?returnUrl=${encodeURIComponent(window.location.href)}`;
```

### 2. Authentication Process
The auth service (`smart-auth-handler.js`):
1. Checks if user is already authenticated
2. If authenticated and has valid returnUrl, redirects immediately
3. If not authenticated, shows login options
4. After successful authentication, stores credentials in both localStorage and cookies

### 3. Data Storage
Authentication data is stored in multiple places for cross-domain access:
```javascript
// Cookies (domain: .genobank.app)
user_signature, user_wallet, isPermittee, login_method

// localStorage (for backward compatibility)
user_signature, user_wallet, isPermittee, login_method, email, name, picture

// sessionStorage (for redirect state)
authConfig, authRedirectInProgress, authDebugLogs
```

### 4. Smart Routing Logic
After authentication, the system determines where to redirect:

```javascript
// From genobank.io homepage
if (source === 'https://genobank.io/') {
    if (isPermittee) {
        redirect to 'https://genobank.io/consent/lab_biofile/'
    } else {
        redirect to 'https://genobank.io/consent/biofile/'
    }
}

// From specific microservice
if (source === 'https://vcf.genobank.app/') {
    redirect to 'https://vcf.genobank.app/' // Return to service
}

// No source URL (fallback)
if (!source) {
    if (isPermittee) {
        redirect to 'https://genobank.io/consent/lab_biofile/'
    } else {
        redirect to 'https://genobank.io/consent/biofile/'
    }
}
```

## Circular Redirect Prevention
The system prevents circular redirects through multiple mechanisms:

1. **authRedirectInProgress flag** - Set when redirect is initiated, cleared on next page load
2. **hasCheckedAuth flag** - Prevents multiple authentication checks in same session
3. **Domain validation** - Only redirects to valid GenoBank domains (.genobank.app, .genobank.io)
4. **URL validation** - Validates all redirect URLs before attempting redirect

## Debug System
The authentication system includes comprehensive debugging:

```javascript
// View debug logs in browser console
AuthDebugger.getLogs()

// Download debug logs for analysis
AuthDebugger.downloadLogs()

// Clear debug logs
AuthDebugger.clearLogs()
```

Debug logs are stored in sessionStorage and persist across page refreshes until cleared.

## Service Registry
All GenoBank services are registered in `GENOBANK_SERVICES`:

```javascript
const GENOBANK_SERVICES = {
    'genobank.io': { /* Main platform */ },
    'vcf.genobank.app': { /* VCF Annotator */ },
    'somosdao.genobank.app': { /* SOMOS DAO */ },
    'alphagenome.genobank.app': { /* AlphaGenome */ },
    'clara.genobank.app': { /* Clara GPU Processing */ },
    'trio.genobank.app': { /* Trio Analysis */ },
    'bioip.genobank.app': { /* BioIP Registry */ },
    'newborn.genobank.app': { /* Newborn App */ },
    'opencravat.genobank.app': { /* OpenCRAVAT */ },
    'microbiome.genobank.app': { /* Microbiome */ },
    'pharmacogenomics.genobank.app': { /* Pharmacogenomics */ }
};
```

## Testing
Use the included `test-auth-flow.html` to:
1. Check current authentication status
2. Test redirect logic for different scenarios
3. Inspect all storage (localStorage, sessionStorage)
4. Simulate authentication for testing
5. Test circular redirect prevention
6. View and manage debug logs

## File Structure
```
auth.genobank.app/
├── index.html                     # Main authentication page
├── oauth-callback.html            # OAuth callback handler
├── smart-auth-handler.js          # Smart routing and debug system
├── custom.js                      # Core authentication logic
├── custom.min.js                  # Minified version
├── walletConnectConnection.min.js # WalletConnect integration
├── genobank_oauth.min.js          # GenoBank OAuth utilities
└── env.min.js                     # Environment configuration
```

## Important Notes
1. **Never use Magic JWT tokens for API calls** - Always use Web3 signatures (`user_signature`)
2. **Cookies use .genobank.app domain** - Ensures cross-subdomain access
3. **Authentication persists for 24 hours** - Set in cookie maxAge
4. **Fallback dashboards always available** - Prevents users from being stuck

## Troubleshooting

### User stuck in redirect loop
1. Clear `authRedirectInProgress` from sessionStorage
2. Clear `hasCheckedAuth` from sessionStorage
3. Check AuthDebugger logs for specific error

### Authentication not persisting
1. Verify cookies are being set with correct domain
2. Check if third-party cookies are blocked
3. Verify localStorage is not disabled

### Wrong dashboard after login
1. Check `isPermittee` value in localStorage
2. Verify permittee validation API is working
3. Check service registry configuration

## Support
For issues or questions, contact: support@genobank.io