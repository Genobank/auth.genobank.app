// GenoBank Authentication Custom Script
// Smart authentication handler for all GenoBank services

const genobank = new GenoBankLogin();
genobank.init();

let prevButtons = {};

function startLoadingButton(buttonId) {
    $('#' + buttonId).attr('disabled', true);
    prevButtons[buttonId] = {
        'prevContent': $('#' + buttonId).html()
    };
    $('#' + buttonId).html(`
        <span class="spinner-grow spinner-grow-sm" aria-hidden="true"></span>
        <span role="status" class="h6">Loading...</span>
    `);
}

function stopLoadingButton(buttonId) {
    $('#' + buttonId).attr('disabled', false);
    $('#' + buttonId).html(prevButtons[buttonId]?.prevContent);
}

function showErrorToast(message) {
    $('.toast .toast-body').text(message);
    let toastEl = $('.toast');
    new bootstrap.Toast(toastEl).show();
}

function magicConstructor() {
    return new Magic(window.MAGIC_API_KEY, {
        'extensions': [new MagicOAuthExtension()],
        'network': {
            'rpcUrl': window.RPC_NETWORK,
            'chainId': window.CHAIN_ID
        }
    });
}

async function loginUsingMetamask() {
    startLoadingButton('id-metamask-button');
    try {
        const metamaskSpinner = $('#metamaskLoginSpiner');
        if (typeof window.ethereum === 'undefined') {
            showErrorToast('MetaMask is not detected. Please install MetaMask and try again.');
            metamaskSpinner.hide();
            return;
        }

        let provider = new ethers.providers.Web3Provider(window.ethereum);
        const loginResult = await metamaskLogin(provider, window.MESSAGE_TO_SIGN);
        await finishingLoginProcess(loginResult);
    } catch (error) {
        stopLoadingButton('id-metamask-button');
        showErrorToast('Error: ' + error.message);
    }
}

async function metamaskLogin(provider, messageToSign) {
    await window.ethereum.request({ 'method': 'eth_requestAccounts' });
    let signature = await provider.getSigner().signMessage(messageToSign);
    let userWallet = await provider.getSigner().getAddress();

    // Check permittee status
    let isPermittee = false;
    try {
        isPermittee = !!(await genobank.getValidatePermittee(userWallet));
    } catch (e) {
        console.warn('Could not validate permittee status:', e);
    }

    return {
        'userSignature': signature,
        'user_signature': signature, // Include both formats
        'userWallet': userWallet,
        'user_wallet': userWallet,
        'isPermittee': isPermittee,
        'loginMethod': 'metamask',
        'login_method': 'metamask'
    };
}

async function loginUsingGoogle() {
    startLoadingButton('id-google-button');
    try {
        let magic = magicConstructor();
        await magic.oauth.loginWithRedirect({
            'provider': 'google',
            'redirectURI': window.location.protocol + '//' + getCurrentDomainWithPort() + '/oauth-callback.html'
        });
    } catch (error) {
        stopLoadingButton('id-google-button');
        showErrorToast('Error: ' + error.message);
    }
}

async function handleOAuthResult() {
    try {
        let magic = magicConstructor();
        $('#id-oauth-loading-text').html('Getting user data...');

        const result = await magic.oauth.getRedirectResult();

        let isPermittee = false;
        try {
            isPermittee = await genobank.getValidatePermittee(result?.magic?.userMetadata?.publicAddress);
        } catch (e) {
            console.warn('Could not validate permittee status:', e);
        }

        $('#id-oauth-loading-text').html('Generating signature...');

        const loginData = {
            'userSignature': await signAndVerify(MESSAGE_TO_SIGN, result?.magic?.userMetadata?.publicAddress),
            'user_signature': await signAndVerify(MESSAGE_TO_SIGN, result?.magic?.userMetadata?.publicAddress),
            'userWallet': result?.magic?.userMetadata?.publicAddress,
            'user_wallet': result?.magic?.userMetadata?.publicAddress,
            'isPermittee': isPermittee,
            'loginMethod': 'magic',
            'login_method': 'magic',
            'magicToken': result?.magic?.idToken,
            'magic_token': result?.magic?.idToken,
            'email': result?.oauth?.userInfo?.email,
            'name': result?.oauth?.userInfo?.name,
            'picture': result?.oauth?.userInfo?.picture
        };

        $('#id-oauth-loading-text').html('Finishing...');
        await finishingLoginProcess(loginData);
    } catch (error) {
        console.error('OAuth error:', error);
        showErrorToast('Authentication failed. Please try again.');
    }
}

async function loginUsingEmailHandler() {
    startLoadingButton('id-email-button');
    try {
        const email = $('#emailInput').val();
        if (!email) {
            showErrorToast('Please enter your email address');
            return;
        }
        await loginUsingEmail(email);
    } catch (error) {
        console.error('Error in loginUsingEmailHandler:', error);
        showErrorToast('Error: ' + error.message);
    } finally {
        stopLoadingButton('id-email-button');
    }
}

async function loginUsingEmail(email) {
    try {
        const magic = magicConstructor();
        const token = await magic.auth.loginWithMagicLink({ 'email': email });
        const userInfo = await magic.user.getInfo();

        let isPermittee = false;
        try {
            isPermittee = await genobank.getValidatePermittee(userInfo?.publicAddress);
        } catch (e) {
            console.warn('Could not validate permittee status:', e);
        }

        const loginData = {
            'userSignature': await signAndVerify(window.MESSAGE_TO_SIGN, userInfo?.publicAddress),
            'user_signature': await signAndVerify(window.MESSAGE_TO_SIGN, userInfo?.publicAddress),
            'userWallet': userInfo?.publicAddress,
            'user_wallet': userInfo?.publicAddress,
            'isPermittee': isPermittee,
            'loginMethod': 'magic_email',
            'login_method': 'magic_email',
            'magicToken': token,
            'magic_token': token,
            'email': userInfo?.email
        };

        await finishingLoginProcess(loginData);
    } catch (error) {
        console.error('Email login error:', error);
        throw error;
    }
}

async function signAndVerify(message, publicAddress) {
    try {
        if (!publicAddress) throw new Error('No account found.');
        const magic = magicConstructor();
        const web3 = new Web3(magic.rpcProvider);
        if (!(await magic.user.isLoggedIn())) throw new Error('User is not logged in with Magic.');
        return await web3.eth.personal.sign(message, publicAddress, '');
    } catch (error) {
        console.error('Error signing the message:', error);
        throw error;
    }
}

async function finishingLoginProcess(loginData) {
    // Use smart handler if available
    if (window.smartFinishingLoginProcess) {
        return await window.smartFinishingLoginProcess(loginData);
    }

    // Fallback to basic handler
    const config = getConfig();
    console.log('Auth config:', config);

    if (config.isPopup) {
        sendToParent(config?.source, loginData);
    } else {
        // Determine the correct redirect URL
        const urlParams = new URLSearchParams(window.location.search);
        const returnUrl = urlParams.get('returnUrl') ||
                         urlParams.get('return_url') ||
                         config?.source;

        let finalRedirectUrl;

        if (returnUrl) {
            // Check if returnUrl is just the homepage
            try {
                const url = new URL(returnUrl);
                if (url.hostname === 'genobank.io' && url.pathname === '/') {
                    // User came from homepage, redirect to appropriate dashboard
                    finalRedirectUrl = loginData.isPermittee
                        ? 'https://genobank.io/consent/lab_biofile/'
                        : 'https://genobank.io/consent/biofile/';
                } else {
                    // Use the specific return URL
                    finalRedirectUrl = returnUrl;
                }
            } catch (e) {
                // Invalid URL, use fallback
                finalRedirectUrl = loginData.isPermittee
                    ? 'https://genobank.io/consent/lab_biofile/'
                    : 'https://genobank.io/consent/biofile/';
            }
        } else {
            // No return URL, use default dashboards
            finalRedirectUrl = loginData.isPermittee
                ? 'https://genobank.io/consent/lab_biofile/'
                : 'https://genobank.io/consent/biofile/';
        }

        // Check login method to determine if we need JWT
        if (loginData.login_method === 'magic' || loginData.login_method === 'magic_email') {
            // Magic Link methods may need JWT for additional data
            const authJWT = await generateAuthJWT(loginData);
            const separator = finalRedirectUrl.includes('?') ? '&' : '?';
            window.location.href = finalRedirectUrl + separator + 'data=' + btoa(authJWT?.jwt || '');
        } else {
            // For MetaMask and WalletConnect, authentication is done via cookies/localStorage
            // The user_signature is already stored, just redirect
            window.location.href = finalRedirectUrl;
        }
    }
}

function sendToParent(source, loginData) {
    const message = { 'genobankLogin': loginData };
    window.opener.postMessage(message, source);
    window.close();
}

async function generateAuthJWT(loginData) {
    try {
        const url = new URL('https://genobank.app/generate_jwt');
        const response = await fetch(url, {
            'method': 'POST',
            'headers': { 'Content-Type': 'application/json' },
            'body': JSON.stringify(loginData)
        });
        return await response.json();
    } catch (error) {
        console.error('Error generating JWT:', error);
        return null;
    }
}

function getCurrentDomainWithPort() {
    const location = window.location;
    let domain = location.hostname;
    if (location.port && location.port !== '80' && location.port !== '443') {
        domain += ':' + location.port;
    }
    return domain;
}

function saveConfig(data) {
    sessionStorage.setItem('data', data);
}

function getConfig(key = false) {
    // First check new storage
    const authConfig = sessionStorage.getItem('authConfig');
    if (authConfig) {
        try {
            const config = JSON.parse(authConfig);
            return key !== false ? config[key] : config;
        } catch (e) {
            console.warn('Could not parse authConfig:', e);
        }
    }

    // Fallback to old storage
    const encodedData = sessionStorage.getItem('data');
    if (!encodedData) {
        return {};
    }

    try {
        const decoded = atob(encodedData).replace(/'/g, '"');
        const config = JSON.parse(decoded);
        return key !== false ? config[key] : config;
    } catch (e) {
        console.warn('Could not parse data:', e);
        return {};
    }
}

// Initialize - handle URL parameters properly
(function() {
    try {
        const urlParams = new URLSearchParams(window.location.search);
        const dataParam = urlParams.get('data');
        const returnUrl = urlParams.get('returnUrl') ||
                         urlParams.get('return_url') ||
                         urlParams.get('redirect');

        // Save configuration
        if (returnUrl) {
            const configData = {
                source: returnUrl,
                isPopup: false
            };
            sessionStorage.setItem('authConfig', JSON.stringify(configData));

            // Also save in old format for compatibility
            saveConfig(btoa(JSON.stringify(configData).replace(/"/g, "'")));
        } else if (dataParam) {
            saveConfig(dataParam);
        }

    } catch (error) {
        console.error('Error in initialization:', error);
    }
})();

// Handle OAuth callback
document.addEventListener('DOMContentLoaded', function() {
    // Check if already authenticated
    if (window.checkExistingAuth) {
        if (window.checkExistingAuth()) {
            return; // User is being redirected
        }
    }

    // Handle OAuth callback
    if (window.location.pathname === '/oauth-callback.html') {
        handleOAuthResult();
    }
});

// Export for external use
window.finishingLoginProcess = finishingLoginProcess;
window.loginUsingMetamask = loginUsingMetamask;
window.loginUsingGoogle = loginUsingGoogle;
window.loginUsingEmailHandler = loginUsingEmailHandler;