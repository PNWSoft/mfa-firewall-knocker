/**
 * @license
 * Copyright (c) 2026 Pacific Northwest Software, Inc.
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

function b64urlToBuffer(b) {
    const pad = '='.repeat((4 - b.length % 4) % 4);
    const s = (b + pad).replace(/-/g, '+').replace(/_/g, '/');
    const r = atob(s);
    return Uint8Array.from(r, c => c.charCodeAt(0)).buffer;
}
function bufferToB64url(buf) {
    return btoa(String.fromCharCode(...new Uint8Array(buf)))
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}
async function registerPasskey() {
    const btn = document.getElementById('registerBtn');
    const st = document.getElementById('status');
    const TOKEN = btn.dataset.token;
    btn.disabled = true;
    st.className = ''; st.textContent = 'Requesting options...';
    try {
        const beginRes = await fetch('/passkey/register/begin', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token: TOKEN })
        });
        if (!beginRes.ok) { st.className = 'error'; st.textContent = await beginRes.text(); btn.disabled = false; return; }
        const { challengeKey, options } = await beginRes.json();
        options.challenge = b64urlToBuffer(options.challenge);
        options.user.id = b64urlToBuffer(options.user.id);
        if (options.excludeCredentials)
            options.excludeCredentials = options.excludeCredentials.map(c => ({ ...c, id: b64urlToBuffer(c.id) }));
        st.textContent = 'Waiting for biometric/PIN...';
        const cred = await navigator.credentials.create({ publicKey: options });
        const attestation = {
            id: cred.id, rawId: bufferToB64url(cred.rawId), type: cred.type,
            response: {
                attestationObject: bufferToB64url(cred.response.attestationObject),
                clientDataJSON: bufferToB64url(cred.response.clientDataJSON)
            }
        };
        const completeRes = await fetch('/passkey/register/complete', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token: TOKEN, challengeKey, attestation })
        });
        if (completeRes.ok) {
            st.className = 'success'; st.textContent = 'Passkey registered! You can now sign in with your fingerprint or PIN.';
            setTimeout(() => window.location.href = '/', 120000);
        } else {
            st.className = 'error'; st.textContent = await completeRes.text(); btn.disabled = false;
        }
    } catch (e) {
        st.className = 'error';
        st.textContent = e.name === 'NotAllowedError' ? 'Cancelled.' : 'Error: ' + e.message;
        btn.disabled = false;
    }
}
document.addEventListener('DOMContentLoaded', function () {
    document.getElementById('registerBtn').addEventListener('click', registerPasskey);
});
