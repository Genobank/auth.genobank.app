// GenoBank Authentication Custom Script
// Unminified version to fix redirect issue

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
    return {
        'userSignature': signature,
        'userWallet': userWallet,
        'isPermittee': !!(await genobank.getValidatePermittee(userWallet)),
        'loginMethod': 'metamask'
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
        let isPermittee = await genobank.getValidatePermittee(result?.magic?.userMetadata?.publicAddress);
        $('#id-oauth-loading-text').html('Generating signature...');
        const loginData = {
            'userSignature': await signAndVerify(MESSAGE_TO_SIGN, result?.magic?.userMetadata?.publicAddress),
            'userWallet': result?.magic?.userMetadata?.publicAddress,
            'isPermittee': isPermittee,
            'loginMethod': 'magic',
            'magicToken': result?.magic?.idToken,
            'email': result?.oauth?.userInfo?.email,
            'name': result?.oauth?.userInfo?.name,
            'picture': result?.oauth?.userInfo?.picture
        };
        $('#id-oauth-loading-text').html('Finishing...');
        await finishingLoginProcess(loginData);
    } catch (error) {
        console.error(error);
    }
}

async function loginUsingEmailHandler() {
    startLoadingButton('id-email-button');
    try {
        const email = $('#emailInput').val();
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
        let isPermittee = await genobank.getValidatePermittee(token?.magic?.userMetadata?.publicAddress);
        const loginData = {
            'userSignature': await signAndVerify(window.MESSAGE_TO_SIGN, userInfo?.publicAddress),
            'userWallet': userInfo?.publicAddress,
            'isPermittee': !!isPermittee,
            'loginMethod': 'magic_email',
            'magicToken': token,
            'email': userInfo?.email
        };
        await finishingLoginProcess(loginData);
    } catch (error) {
        console.error(error);
    }
}

async function signAndVerify(message, publicAddress) {
    try {
        if (!publicAddress) throw new Error('No account found in localStorage.');
        const magic = magicConstructor();
        const web3 = new Web3(magic.rpcProvider);
        if (!(await magic.user.isLoggedIn())) throw new Error('User is not logged in with Magic.');
        return await web3.eth.personal.sign(message, publicAddress, '');
    } catch (error) {
        console.error('Error signing the message:', error);
    }
}

async function finishingLoginProcess(loginData) {
    const config = getConfig();
    console.log(config);

    if (config.isPopup) {
        sendToParent(config?.source, loginData);
    } else {
        const authJWT = await generateAuthJWT(loginData);
        // Check if we have a returnUrl parameter
        const urlParams = new URLSearchParams(window.location.search);
        const returnUrl = urlParams.get('returnUrl') || config?.source;

        if (returnUrl) {
            // Redirect to the returnUrl with the auth data
            const separator = returnUrl.includes('?') ? '&' : '?';
            window.location.href = returnUrl + separator + 'data=' + btoa(authJWT?.jwt);
        } else {
            // Default redirect to consent page based on permittee status
            if (loginData.isPermittee) {
                window.location.href = 'https://genobank.io/consent/lab_biofile/?data=' + btoa(authJWT?.jwt);
            } else {
                window.location.href = 'https://genobank.io/consent/biofile/?data=' + btoa(authJWT?.jwt);
            }
        }
    }
}

function sendToParent(source, loginData) {
    const message = { 'genobankLogin': loginData };
    window.opener.postMessage(message, source);
    window.close();
}

async function generateAuthJWT(loginData) {
    const url = new URL('https://genobank.app/generate_jwt');
    return fetch(url, {
        'method': 'POST',
        'headers': { 'Content-Type': 'application/json' },
        'body': JSON.stringify(loginData)
    })
    .then(response => response.json())
    .catch(error => console.error('Error:', error));
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
    const encodedData = sessionStorage.getItem('data');
    if (!encodedData) {
        return {};
    }
    const decoded = atob(encodedData).replace(/'/g, '"');
    const config = JSON.parse(decoded);
    return key !== false ? config[key] : config;
}

// Initialize - handle URL parameters properly
(function() {
    try {
        const urlParams = new URLSearchParams(window.location.search);
        const dataParam = urlParams.get('data');
        const returnUrl = urlParams.get('returnUrl');

        // If we have a returnUrl, save it for later use
        if (returnUrl) {
            const configData = {
                source: returnUrl,
                isPopup: false
            };
            saveConfig(btoa(JSON.stringify(configData).replace(/"/g, "'")));
        } else if (dataParam) {
            // Save data parameter if present
            saveConfig(dataParam);
        }

        // Don't redirect away - let the user authenticate
        // The redirect to genobank.io was removed from here

    } catch (error) {
        console.error('Error in initialization:', error);
    }
})();

// Handle OAuth callback
document.addEventListener('DOMContentLoaded', function() {
    if (window.location.pathname === '/oauth-callback.html') {
        handleOAuthResult();
    }
});

// Export function for external use
window.finishingLoginProcess = finishingLoginProcess;