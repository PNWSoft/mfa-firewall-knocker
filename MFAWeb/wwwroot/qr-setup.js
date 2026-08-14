/**
 * @license
 * Copyright (c) 2026 Pacific Northwest Software, Inc.
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

document.addEventListener('DOMContentLoaded', function () {
    var canvas = document.getElementById('qr');
    new QRious({
        element: canvas,
        value: canvas.dataset.uri,
        size: 250,
        background: 'white',
        foreground: 'black'
    });
});
