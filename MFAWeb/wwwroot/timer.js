/**
 * @license
 * Copyright (c) 2026 Pacific Northwest Software, Inc.
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

document.addEventListener('DOMContentLoaded', function () {
    var timeLeft = 60;
    var timerEl = document.getElementById('timer');
    var iv = setInterval(function () {
        timerEl.innerText = --timeLeft;
        if (timeLeft <= 0) { clearInterval(iv); window.location.href = '/'; }
    }, 1000);
});
