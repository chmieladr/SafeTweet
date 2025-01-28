function calculatePasswordSafety(password) {
    if (!password)
        return "N/A";

    // Character set sizes
    const LOWERCASE = 26;
    const UPPERCASE = 26;
    const DIGITS = 10;
    const SYMBOLS = 32;

    // Determine the character set used
    let charsetSize = 0;
    if (/[a-z]/.test(password))
        charsetSize += LOWERCASE;
    if (/[A-Z]/.test(password))
        charsetSize += UPPERCASE;
    if (/\d/.test(password))
        charsetSize += DIGITS;
    if (/[\W_]/.test(password))
        charsetSize += SYMBOLS;

    const pseudoentropy = password.length * Math.log2(charsetSize);

    let safety;
    if (pseudoentropy < 48)
        safety = "Weak";
    else if (pseudoentropy < 72)
        safety = "Moderate";
    else if (pseudoentropy < 96)
        safety = "Strong";
    else
        safety = "Very Strong";

    return safety;
}

// noinspection JSUnusedGlobalSymbols
function updateStrengthBar(elementId) {
    const password = document.getElementById(elementId).value;
    const strengthBar = document.getElementById('strength-bar').firstElementChild;
    const passwordSafety = document.getElementById('password-safety');

    const safety = calculatePasswordSafety(password);

    switch (safety) {
        case "N/A":
            strengthBar.className = '';
            break;
        case "Weak":
            strengthBar.className = 'pwd-weak';
            break;
        case "Moderate":
            strengthBar.className = 'pwd-moderate';
            break;
        case "Strong":
            strengthBar.className = 'pwd-strong';
            break;
        case "Very Strong":
            strengthBar.className = 'pwd-very-strong';
            break;
    }

    passwordSafety.textContent = safety;
}

function goToTop() {
    window.scrollTo({top: 0, behavior: 'smooth'});
}