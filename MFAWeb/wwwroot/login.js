/**
 * @license
 * Copyright (c) 2026 Pacific Northwest Software, Inc.
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

function b64urlToBuffer(b64url) {
    const pad = '='.repeat((4 - b64url.length % 4) % 4);
    const b64 = (b64url + pad).replace(/-/g, '+').replace(/_/g, '/');
    const raw = atob(b64);
    return Uint8Array.from(raw, c => c.charCodeAt(0)).buffer;
}

function bufferToB64url(buf) {
    return btoa(String.fromCharCode(...new Uint8Array(buf)))
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function toggleTotp() {
    const section = document.getElementById('totpSection');
    const visible = section.style.display === 'block';
    section.style.display = visible ? 'none' : 'block';
    if (!visible) {
        const email = document.getElementById('usernameField').value.trim();
        const totpField = document.getElementById('totpUsernameField');
        if (email && !totpField.value) totpField.value = email;
        totpField.focus();
    }
}

// Helper to manage UI state colors and messages
function showStatus(msg, isError = false) {
    const el = document.getElementById('passkeyError');
    el.textContent = msg;
    // Red for errors, accent blue for informational status updates
    el.style.color = isError ? '#ff6b6b' : '#007acc';
    el.style.display = 'block';
}

async function signInWithPasskey() {
    const btn = document.getElementById('passkeyBtn');

    const username = document.getElementById('usernameField').value.trim();
    if (!username) {
        showStatus('Enter your email address first.', true);
        return;
    }

    // Disable button to prevent double-clicks during the async flow
    btn.disabled = true;

    try {
        // Step 1: Fetch Challenge
        showStatus('Requesting secure challenge...');
        const challengeRes = await fetch('/passkey/challenge', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username })
        });

        if (!challengeRes.ok) {
            showStatus(await challengeRes.text() || 'No passkey registered for this account.', true);
            btn.disabled = false;
            return;
        }

        const payload = await challengeRes.json();
        const options = payload.options;
        options.challenge = b64urlToBuffer(options.challenge);
        if (options.allowCredentials) {
            options.allowCredentials = options.allowCredentials.map(c => ({ ...c, id: b64urlToBuffer(c.id) }));
        }

        // Step 2: WebAuthn Prompt
        showStatus('Waiting for biometric/PIN verification...');
        const assertion = await navigator.credentials.get({ publicKey: options });

        const assertionJSON = {
            id: assertion.id,
            rawId: bufferToB64url(assertion.rawId),
            type: assertion.type,
            response: {
                authenticatorData: bufferToB64url(assertion.response.authenticatorData),
                clientDataJSON: bufferToB64url(assertion.response.clientDataJSON),
                signature: bufferToB64url(assertion.response.signature),
                userHandle: assertion.response.userHandle ? bufferToB64url(assertion.response.userHandle) : null
            }
        };

        // Step 3: Verify and Firewall IPC
        showStatus('Verifying passkey and opening firewall...');
        const verifyRes = await fetch('/passkey/verify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, challengeKey: payload.challengeKey, assertion: assertionJSON })
        });

        if (verifyRes.ok) {
            showStatus('Success! Redirecting...', false);
            window.location.href = '/access-granted';
        } else {
            showStatus(await verifyRes.text() || 'Passkey verification failed.', true);
            btn.disabled = false;
        }
    } catch (e) {
        const msg = e.name === 'NotAllowedError' ? 'Passkey prompt was cancelled.' : 'Error: ' + e.message;
        showStatus(msg, true);
        btn.disabled = false;
    }
}

function handleTotpSubmit(e) {
    // We allow the standard form POST to proceed, but we lock the UI.
    // This prevents the user from clicking the button multiple times while 
    // the backend is waiting on the IpcFirewallClient.OpenPortAsync response.
    const btn = e.target.querySelector('button[type="submit"]');
    if (btn) {
        btn.disabled = true;
        btn.textContent = 'Authorizing...';
        btn.style.cursor = 'wait';
        btn.style.backgroundColor = '#005999'; // Switch to hover color to indicate active state
    }
}

document.addEventListener('DOMContentLoaded', function () {
    document.getElementById('passkeyBtn').addEventListener('click', signInWithPasskey);
    document.getElementById('toggleTotpBtn').addEventListener('click', toggleTotp);

    const authForm = document.getElementById('authForm');
    if (authForm) {
        authForm.addEventListener('submit', handleTotpSubmit);
    }
});