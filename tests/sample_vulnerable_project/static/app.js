// Sample vulnerable JavaScript for testing

// HIGH: DOM XSS via innerHTML
function displayUserInput() {
    const userInput = document.getElementById('input').value;
    document.getElementById('output').innerHTML = userInput;
}

// HIGH: document.write usage
function writeContent(content) {
    document.write(content);
}

// CRITICAL: eval usage
function calculate(expression) {
    return eval(expression);
}

// HIGH: localStorage token storage
function storeToken(token) {
    localStorage.setItem('auth_token', token);
    localStorage.setItem('user_id', '12345');
}

// CRITICAL: Exposed API key (TEST VALUES ONLY - NOT REAL)
const API_KEY = 'sk_test_FAKEKEY1234567890ABCDEFGHIJKLMNO';
const config = {
    apiKey: 'TEST_API_KEY_12345FAKE67890',
    secret: 'test-secret-password-fake'
};


// MEDIUM: Inline event handler (would be in HTML)
// <button onclick="handleClick()">Click me</button>

// MEDIUM: JSONP usage
function loadData(callback) {
    const script = document.createElement('script');
    script.src = 'https://api.example.com/data?callback=' + callback;
    document.head.appendChild(script);
}

// HIGH: CORS wildcard
const corsConfig = {
    'Access-Control-Allow-Origin': '*'
};

// LOW: Missing integrity check on external script
function loadExternalScript() {
    const script = document.createElement('script');
    script.src = 'https://cdn.example.com/library.js';
    document.head.appendChild(script);
}
