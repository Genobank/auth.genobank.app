// GenoBank Smart Authentication Handler with Debug Logging
// Intelligently routes users based on source application and user type

// Persistent debug logger
const AuthDebugger = {
    logs: [],
    maxLogs: 100,

    log(message, data = null) {
        const timestamp = new Date().toISOString();
        const logEntry = {
            timestamp,
            message,
            data,
            url: window.location.href
        };

        this.logs.push(logEntry);
        if (this.logs.length > this.maxLogs) {
            this.logs.shift();
        }

        // Store in sessionStorage for persistence
        sessionStorage.setItem('authDebugLogs', JSON.stringify(this.logs));

        // Console output
        console.log(`[AUTH ${timestamp}] ${message}`, data || '');
    },

    getLogs() {
        const stored = sessionStorage.getItem('authDebugLogs');
        if (stored) {
            try {
                this.logs = JSON.parse(stored);
            } catch (e) {
                console.error('Failed to parse stored logs:', e);
            }
        }
        return this.logs;
    },

    clearLogs() {
        this.logs = [];
        sessionStorage.removeItem('authDebugLogs');
    },

    downloadLogs() {
        const logsText = JSON.stringify(this.logs, null, 2);
        const blob = new Blob([logsText], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `auth-debug-${Date.now()}.json`;
        a.click();
    }
};

// Make debugger globally available
window.AuthDebugger = AuthDebugger;

const GENOBANK_SERVICES = {
    // Main Services
    'genobank.io': {
        default: 'https://genobank.io/consent/biofile/',
        permittee: 'https://genobank.io/consent/lab_biofile/',
        paths: {
            '/': 'https://genobank.io/',  // Return to homepage
            '/consent/biofile': 'https://genobank.io/consent/biofile/',
            '/consent/biofile/': 'https://genobank.io/consent/biofile/',
            '/consent/lab_biofile': 'https://genobank.io/consent/lab_biofile/',
            '/consent/lab_biofile/': 'https://genobank.io/consent/lab_biofile/',
            '/entry-point': 'https://genobank.io/entry-point/',
            '/entry-point/': 'https://genobank.io/entry-point/',
            '/login': 'https://genobank.io/login/',
            '/login/': 'https://genobank.io/login/'
        }
    },

    // Microservices
    'vcf.genobank.app': {
        default: 'https://vcf.genobank.app/',
        permittee: 'https://vcf.genobank.app/',
        requiresAuth: true
    },

    'somosdao.genobank.app': {
        default: 'https://somosdao.genobank.app/',
        permittee: 'https://somosdao.genobank.app/',
        requiresAuth: true
    },

    'alphagenome.genobank.app': {
        default: 'https://alphagenome.genobank.app/',
        permittee: 'https://alphagenome.genobank.app/',
        requiresAuth: true
    },

    'clara.genobank.app': {
        default: 'https://clara.genobank.app/',
        permittee: 'https://clara.genobank.app/',
        requiresAuth: true
    },

    'trio.genobank.app': {
        default: 'https://trio.genobank.app/',
        permittee: 'https://trio.genobank.app/',
        requiresAuth: true
    },

    'newborn.genobank.app': {
        default: 'https://newborn.genobank.app/',
        permittee: 'https://newborn.genobank.app/',
        requiresAuth: true
    },

    'bioip.genobank.app': {
        default: 'https://bioip.genobank.app/',
        permittee: 'https://bioip.genobank.app/',
        requiresAuth: true
    },

    'bioinformatics.genobank.app': {
        default: 'https://bioinformatics.genobank.app/',
        permittee: 'https://bioinformatics.genobank.app/',
        requiresAuth: true
    },

    'opencravat.genobank.app': {
        default: 'https://opencravat.genobank.app/',
        permittee: 'https://opencravat.genobank.app/',
        requiresAuth: true
    },

    'claude.genobank.app': {
        default: 'https://claude.genobank.app/',
        permittee: 'https://claude.genobank.app/',
        requiresAuth: true
    },

    'pharmacogenomics.genobank.app': {
        default: 'https://pharmacogenomics.genobank.app/',
        permittee: 'https://pharmacogenomics.genobank.app/',
        requiresAuth: true
    },

    'microbiome.genobank.app': {
        default: 'https://microbiome.genobank.app/',
        permittee: 'https://microbiome.genobank.app/',
        requiresAuth: true
    },

    'synbio.genobank.app': {
        default: 'https://synbio.genobank.app/',
        permittee: 'https://synbio.genobank.app/',
        requiresAuth: true
    },

    'patentdna.genobank.app': {
        default: 'https://patentdna.genobank.app/',
        permittee: 'https://patentdna.genobank.app/',
        requiresAuth: true
    },

    'docs.genobank.app': {
        default: 'https://docs.genobank.app/',
        permittee: 'https://docs.genobank.app/',
        requiresAuth: false
    }
};

// Cookie utilities
const AUTH_COOKIE_CONFIG = {
    domain: '.genobank.app',
    maxAge: 86400, // 24 hours
    secure: true,
    sameSite: 'lax', // Use 'lax' for cross-site navigation
    path: '/'
};

function setAuthCookie(name, value, maxAge = AUTH_COOKIE_CONFIG.maxAge) {
    if (!value) return;

    let cookieString = `${name}=${encodeURIComponent(value)}; ` +
        `domain=${AUTH_COOKIE_CONFIG.domain}; ` +
        `path=${AUTH_COOKIE_CONFIG.path}; ` +
        `max-age=${maxAge}; ` +
        `samesite=${AUTH_COOKIE_CONFIG.sameSite}`;

    // Only add secure flag if on HTTPS
    if (window.location.protocol === 'https:') {
        cookieString += '; secure';
    }

    document.cookie = cookieString;
    AuthDebugger.log(`Set cookie: ${name}`, value.substring(0, 20) + '...');
}

function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) {
        return decodeURIComponent(parts.pop().split(';').shift());
    }
    return null;
}

function setAuthData(authData) {
    AuthDebugger.log('Setting auth data', {
        hasSignature: !!authData.user_signature,
        hasWallet: !!authData.user_wallet,
        isPermittee: authData.isPermittee,
        method: authData.login_method
    });

    const {
        user_signature,
        user_wallet,
        magic_token,
        login_method,
        isPermittee,
        email,
        name,
        picture
    } = authData;

    // Set cookies for cross-domain access
    if (user_signature) setAuthCookie('user_signature', user_signature);
    if (user_wallet) setAuthCookie('user_wallet', user_wallet);
    if (magic_token) setAuthCookie('magic_token', magic_token);
    if (login_method) setAuthCookie('login_method', login_method);
    if (isPermittee !== undefined) setAuthCookie('isPermittee', isPermittee.toString());
    if (email) setAuthCookie('email', email);
    if (name) setAuthCookie('name', name);
    if (picture) setAuthCookie('picture', picture);

    // Also set localStorage for backward compatibility
    if (user_signature) {
        localStorage.setItem('user_signature', user_signature);
        localStorage.setItem('user_sign', user_signature); // Legacy support
    }
    if (user_wallet) localStorage.setItem('user_wallet', user_wallet);
    if (magic_token) localStorage.setItem('magic_token', magic_token);
    if (login_method) localStorage.setItem('login_method', login_method);
    if (isPermittee !== undefined) localStorage.setItem('isPermittee', isPermittee.toString());
    if (email) localStorage.setItem('email', email);
    if (name) localStorage.setItem('name', name);
    if (picture) localStorage.setItem('picture', picture);
}

// Determine where to redirect based on source and user type
function determineRedirectUrl(sourceUrl, isPermittee) {
    AuthDebugger.log('Determining redirect URL', { sourceUrl, isPermittee });

    if (!sourceUrl) {
        // No source URL - use fallback based on user type
        const fallback = isPermittee
            ? 'https://genobank.io/consent/lab_biofile/'
            : 'https://genobank.io/consent/biofile/';
        AuthDebugger.log('No source URL, using fallback', fallback);
        return fallback;
    }

    try {
        const url = new URL(sourceUrl);
        const hostname = url.hostname;
        const pathname = url.pathname;

        // Check if it's a known service
        const service = GENOBANK_SERVICES[hostname];

        if (service) {
            // Check if there's a specific path handler
            if (service.paths && service.paths[pathname]) {
                AuthDebugger.log('Using specific path handler', service.paths[pathname]);
                return service.paths[pathname];
            }

            // If coming from genobank.io homepage, route based on user type
            if (hostname === 'genobank.io' && pathname === '/') {
                const dashboardUrl = isPermittee
                    ? 'https://genobank.io/consent/lab_biofile/'
                    : 'https://genobank.io/consent/biofile/';
                AuthDebugger.log('From homepage, routing to dashboard', dashboardUrl);
                return dashboardUrl;
            }

            // Use the service's default based on user type
            const redirectUrl = isPermittee && service.permittee
                ? service.permittee
                : service.default || sourceUrl;

            AuthDebugger.log('Using service default', redirectUrl);
            return redirectUrl;
        }

        // Unknown service - return to source
        AuthDebugger.log('Unknown service, returning to source', sourceUrl);
        return sourceUrl;

    } catch (error) {
        AuthDebugger.log('Invalid source URL', { sourceUrl, error: error.message });
        // Fallback to default dashboards
        return isPermittee
            ? 'https://genobank.io/consent/lab_biofile/'
            : 'https://genobank.io/consent/biofile/';
    }
}

// Enhanced finishing login process
async function smartFinishingLoginProcess(loginData) {
    AuthDebugger.log('Smart finishing login process started', {
        hasSignature: !!loginData.user_signature,
        isPermittee: loginData.isPermittee,
        method: loginData.login_method
    });

    // Store authentication data
    setAuthData(loginData);

    const config = getConfig();
    AuthDebugger.log('Config loaded', config);

    // Get the return URL from various sources
    const urlParams = new URLSearchParams(window.location.search);
    let returnUrl = urlParams.get('returnUrl') ||
                    urlParams.get('return_url') ||
                    urlParams.get('redirect') ||
                    config?.source;

    // Check referrer as last resort
    if (!returnUrl && document.referrer) {
        try {
            const referrerUrl = new URL(document.referrer);
            // Only use referrer if it's from a GenoBank domain
            if (referrerUrl.hostname.endsWith('genobank.app') ||
                referrerUrl.hostname.endsWith('genobank.io')) {
                returnUrl = document.referrer;
                AuthDebugger.log('Using referrer as return URL', returnUrl);
            }
        } catch (e) {
            AuthDebugger.log('Invalid referrer', document.referrer);
        }
    }

    AuthDebugger.log('Return URL determined', returnUrl);

    // Handle popup mode
    if (config?.isPopup) {
        AuthDebugger.log('Popup mode - sending to parent');
        sendToParent(config?.source, loginData);
        return;
    }

    // Generate JWT for authentication
    AuthDebugger.log('Generating JWT');
    const authJWT = await generateAuthJWT(loginData);
    if (!authJWT?.jwt) {
        AuthDebugger.log('Failed to generate JWT - continuing without it');
    } else {
        AuthDebugger.log('JWT generated successfully');
    }

    // Determine the final redirect URL
    const finalUrl = determineRedirectUrl(returnUrl, loginData.isPermittee);
    AuthDebugger.log('Final redirect URL', finalUrl);

    // Add auth data to URL if JWT exists
    if (authJWT?.jwt) {
        const separator = finalUrl.includes('?') ? '&' : '?';
        const redirectUrl = finalUrl + separator + 'data=' + btoa(authJWT.jwt);
        AuthDebugger.log('Redirecting with JWT', redirectUrl);
        window.location.href = redirectUrl;
    } else {
        // Redirect without JWT - cookies should handle auth
        AuthDebugger.log('Redirecting without JWT (using cookies)', finalUrl);
        window.location.href = finalUrl;
    }
}

// Check if user is already authenticated - WITH REDIRECT PREVENTION
let hasCheckedAuth = false;

function checkExistingAuth() {
    // Prevent multiple checks
    if (hasCheckedAuth) {
        AuthDebugger.log('Already checked auth, skipping');
        return false;
    }
    hasCheckedAuth = true;

    const userSignature = getCookie('user_signature') || localStorage.getItem('user_signature');
    const userWallet = getCookie('user_wallet') || localStorage.getItem('user_wallet');
    const isPermittee = getCookie('isPermittee') || localStorage.getItem('isPermittee');

    AuthDebugger.log('Checking existing auth', {
        hasSignature: !!userSignature,
        hasWallet: !!userWallet,
        isPermittee: isPermittee
    });

    if (userSignature && userWallet) {
        AuthDebugger.log('User already authenticated');

        // Get return URL from parameters
        const urlParams = new URLSearchParams(window.location.search);
        let returnUrl = urlParams.get('returnUrl') ||
                       urlParams.get('return_url') ||
                       urlParams.get('redirect');

        // Also check if we have a stored config with source
        const authConfig = sessionStorage.getItem('authConfig');
        let configSource = null;
        if (authConfig) {
            try {
                const config = JSON.parse(authConfig);
                configSource = config.source;
                AuthDebugger.log('Found stored config source', configSource);
            } catch (e) {
                AuthDebugger.log('Could not parse authConfig', e);
            }
        }

        // Determine where to redirect - prioritize URL params, then config, then referrer
        let redirectTo = returnUrl || configSource;

        // If still no redirect URL but we have a GenoBank referrer, use it
        if (!redirectTo && document.referrer) {
            try {
                const referrerUrl = new URL(document.referrer);
                if (referrerUrl.hostname.endsWith('genobank.app') ||
                    referrerUrl.hostname.endsWith('genobank.io')) {
                    redirectTo = document.referrer;
                    AuthDebugger.log('Using referrer as redirect URL for authenticated user', redirectTo);
                }
            } catch (e) {
                AuthDebugger.log('Could not parse referrer', e);
            }
        }

        if (redirectTo) {
            // Check if the redirect is coming from a GenoBank domain
            try {
                const redirectUrl = new URL(redirectTo);
                if (redirectUrl.hostname.endsWith('genobank.app') ||
                    redirectUrl.hostname.endsWith('genobank.io')) {

                    const finalUrl = determineRedirectUrl(redirectTo, isPermittee === 'true');
                    AuthDebugger.log('Redirecting authenticated user to', finalUrl);

                    // Set a flag to prevent re-checking
                    sessionStorage.setItem('authRedirectInProgress', 'true');
                    window.location.href = finalUrl;
                    return true;
                }
            } catch (e) {
                AuthDebugger.log('Invalid redirect URL', { redirectTo, error: e.message });
            }
        } else {
            // No redirect URL found, but user is authenticated - send to default dashboard
            AuthDebugger.log('User authenticated, no redirect URL - sending to default dashboard');
            const defaultDashboard = isPermittee === 'true'
                ? 'https://genobank.io/consent/lab_biofile/'
                : 'https://genobank.io/consent/biofile/';

            sessionStorage.setItem('authRedirectInProgress', 'true');
            window.location.href = defaultDashboard;
            return true;
        }

        AuthDebugger.log('User authenticated but unable to determine redirect destination');
    } else {
        AuthDebugger.log('User not authenticated');
    }

    return false;
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
    AuthDebugger.log('=== Auth Service Initialized v2.1 ===');
    AuthDebugger.log('Current URL', window.location.href);
    AuthDebugger.log('Referrer', document.referrer);

    // Reset the hasCheckedAuth flag on new page load
    hasCheckedAuth = false;

    // Check if redirect is already in progress
    if (sessionStorage.getItem('authRedirectInProgress') === 'true') {
        AuthDebugger.log('Redirect in progress, clearing flag');
        sessionStorage.removeItem('authRedirectInProgress');
        hasCheckedAuth = true; // Don't check again
        return;
    }

    // Store return URL information FIRST if we have a referrer from GenoBank
    const urlParams = new URLSearchParams(window.location.search);
    let returnUrl = urlParams.get('returnUrl') ||
                   urlParams.get('return_url') ||
                   urlParams.get('redirect');

    // Only use referrer if no explicit returnUrl and referrer is from GenoBank
    if (!returnUrl && document.referrer) {
        try {
            const referrerUrl = new URL(document.referrer);
            if (referrerUrl.hostname.endsWith('genobank.app') ||
                referrerUrl.hostname.endsWith('genobank.io')) {
                returnUrl = document.referrer;
                AuthDebugger.log('Using GenoBank referrer as return URL', returnUrl);
            }
        } catch (e) {
            AuthDebugger.log('Invalid referrer', document.referrer);
        }
    }

    if (returnUrl) {
        AuthDebugger.log('Storing return URL', returnUrl);
        const configData = {
            source: returnUrl,
            isPopup: false
        };
        // Save for later use
        sessionStorage.setItem('authConfig', JSON.stringify(configData));
    }

    // Check if user is already authenticated (only on non-callback pages)
    if (!window.location.pathname.includes('oauth-callback')) {
        if (checkExistingAuth()) {
            return; // User is being redirected
        }
    }

    // Add debug console helper
    console.log('🔍 Auth Debugger Available - Use AuthDebugger.getLogs() to view logs, AuthDebugger.downloadLogs() to save');
});

// Export for use in custom.js
window.smartFinishingLoginProcess = smartFinishingLoginProcess;
window.determineRedirectUrl = determineRedirectUrl;
window.setAuthData = setAuthData;
window.checkExistingAuth = checkExistingAuth;