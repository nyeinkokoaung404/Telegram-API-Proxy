// ==========================================
// Telegram Bot API Proxy - Cloudflare Worker
// ==========================================

// ========== CONSTANTS & CONFIGURATION ==========
const URL_PATH_REGEX = /^\/bot(?<bot_token>[^/]+)\/(?<api_method>[a-zA-Z0-9_]+)/i;

const RATE_LIMITS = {
    IP: { max: 100, window: 60000 },
    TOKEN: { max: 200, window: 60000 },
    GLOBAL: { max: 5000, window: 60000 },
    BURST: { max: 10, window: 1000 }
};

const CIRCUIT_BREAKER = {
    FAILURE_THRESHOLD: 5,
    TIMEOUT: 30000,
    HALF_OPEN_MAX_CALLS: 3
};

const RETRY_CONFIG = {
    MAX_RETRIES: 3,
    INITIAL_DELAY: 1000,
    MAX_DELAY: 8000,
    BACKOFF_FACTOR: 2
};

const CACHE_CONFIGS = {
    getMe: { ttl: 3600, edge: true },
    getChat: { ttl: 600, edge: true },
    getChatMember: { ttl: 300, edge: true },
    getChatAdministrators: { ttl: 1800, edge: true },
    default: { ttl: 0, edge: false }
};

// ========== SECURITY RULES ==========
const ALLOWED_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'];
const MAX_BODY_SIZE = 50 * 1024 * 1024; // 50MB
const MAX_TOKEN_LENGTH = 200;
const CACHE_TTL = 300000; // 5 minutes
const SUSPICIOUS_THRESHOLD = 10;
const MAX_CACHE_SIZE = 10000;

const ALLOWED_USER_AGENTS = /telegram|bot|curl|wget|postman|httpie|axios|fetch|python-requests|java|okhttp|go-http-client|ruby/i;
const BLOCKED_USER_AGENTS = /scanner|crawler|spider|bot.*attack|sqlmap|nikto|nmap|masscan|zgrab|httpx|nuclei/i;

const MALICIOUS_PATTERNS = [
    /(\.\.\/|\.\.\\|%2e%2e|%252e%252e)/i,
    /<script[^>]*>.*?<\/script>/is,
    /javascript:/gi,
    /vbscript:/gi,
    /on(load|error|click|mouseover)\s*=/gi,
    /eval\s*\(/gi,
    /union\s+select\s+/gi,
    /(\bor\b|\band\b)\s+\d+\s*=\s*\d+/gi,
    /(\bselect\b.*\bfrom\b|\bdrop\b.*\btable\b)/gi,
    /(\bexec\b|\bxp_cmdshell\b|\bwget\b|\bcurl\b)/gi
];

const FILE_UPLOAD_METHODS = new Set([
    'sendPhoto', 'sendDocument', 'sendVideo', 'sendAudio',
    'sendVoice', 'sendAnimation', 'sendSticker', 'sendVideoNote',
    'sendMediaGroup', 'setChatPhoto', 'uploadStickerFile',
    'createNewStickerSet', 'addStickerToSet', 'setStickerSetThumb'
]);

const TELEGRAM_ENDPOINTS = [
    'api.telegram.org',
    '149.154.167.198',
    '149.154.167.199',
    '149.154.167.200'
];

// ========== GLOBAL STATE ==========
let requestCounters = {
    ip: new Map(),
    token: new Map(),
    burst: new Map(),
    global: { count: 0, resetTime: Date.now() + RATE_LIMITS.GLOBAL.window }
};

let circuitBreakers = new Map();
let tokenValidationCache = new Map();
let suspiciousIPs = new Map();

let requestStats = {
    total: 0,
    errors: 0,
    rateLimited: 0,
    blocked: 0,
    retries: 0,
    lastReset: Date.now(),
    avgResponseTime: 0
};

// ========== MAIN ENTRY POINT ==========
export default {
    async fetch(request, env, ctx) {
        const startTime = Date.now();
        
        try {
            // Pre-processing
            await cleanupExpiredData();
            
            // Security checks
            const securityCheck = await performAdvancedSecurityChecks(request, env);
            if (securityCheck.blocked) {
                requestStats.blocked++;
                return createErrorResponse(securityCheck.reason, securityCheck.status);
            }
            
            // CORS preflight
            if (request.method === 'OPTIONS') {
                return handleCorsPreflight();
            }
            
            // Parse request
            const requestInfo = await parseRequest(request);
            if (!requestInfo.valid) {
                return createErrorResponse('Invalid request format. Expected: /bot{token}/{method}', 400);
            }
            
            // Circuit breaker check
            const circuitState = checkCircuitBreaker(requestInfo.clientIP);
            if (circuitState === 'OPEN') {
                return createErrorResponse('Service temporarily unavailable due to failures', 503);
            }
            
            // Rate limiting
            const rateLimitResult = await checkAdvancedRateLimit(requestInfo.clientIP, requestInfo.botToken);
            if (rateLimitResult.limited) {
                requestStats.rateLimited++;
                return createRateLimitResponse(rateLimitResult.retryAfter);
            }
            
            // Token validation (with real API call)
            const tokenValid = await validateBotTokenAdvanced(requestInfo.botToken, env);
            if (!tokenValid) {
                await recordSuspiciousActivity(requestInfo.clientIP, 'invalid_token');
                return createErrorResponse('Invalid bot token', 401);
            }
            
            // Proxy request
            const response = await proxyToTelegramWithRetry(request, requestInfo, ctx);
            
            // Update stats
            updateCircuitBreaker(requestInfo.clientIP, response.ok);
            updateStats(startTime, response.ok);
            
            return response;
            
        } catch (error) {
            console.error('Proxy error:', error);
            requestStats.errors++;
            updateCircuitBreaker(getClientIP(request), false);
            return handleProxyError(error);
        }
    }
};

// ========== CLEANUP FUNCTIONS ==========
async function cleanupExpiredData() {
    const now = Date.now();
    
    // Clean token cache
    if (tokenValidationCache.size > MAX_CACHE_SIZE) {
        const toDelete = tokenValidationCache.size - MAX_CACHE_SIZE;
        const iterator = tokenValidationCache.keys();
        for (let i = 0; i < toDelete; i++) {
            tokenValidationCache.delete(iterator.next().value);
        }
    }
    
    for (const [token, data] of tokenValidationCache.entries()) {
        if (now >= data.expires) {
            tokenValidationCache.delete(token);
        }
    }
    
    // Clean suspicious IPs
    for (const [ip, data] of suspiciousIPs.entries()) {
        if (now >= data.expires) {
            suspiciousIPs.delete(ip);
        }
    }
    
    // Clean circuit breakers
    for (const [key, breaker] of circuitBreakers.entries()) {
        if (now - breaker.lastFailureTime > CIRCUIT_BREAKER.TIMEOUT && breaker.state === 'OPEN') {
            breaker.state = 'CLOSED';
            breaker.failureCount = 0;
        }
    }
    
    // Reset stats hourly
    if (now - requestStats.lastReset > 3600000) {
        requestStats = {
            total: 0,
            errors: 0,
            rateLimited: 0,
            blocked: 0,
            retries: 0,
            lastReset: now,
            avgResponseTime: 0
        };
    }
}

// ========== SECURITY FUNCTIONS ==========
async function performAdvancedSecurityChecks(request, env) {
    const clientIP = getClientIP(request);
    const userAgent = request.headers.get('user-agent') || '';
    const contentType = request.headers.get('content-type') || '';
    const contentLength = request.headers.get('content-length');
    
    // Method validation
    if (!ALLOWED_METHODS.includes(request.method)) {
        return { blocked: true, reason: 'Method not allowed', status: 405 };
    }
    
    // Size validation
    if (contentLength && parseInt(contentLength) > MAX_BODY_SIZE) {
        return { blocked: true, reason: 'Request too large', status: 413 };
    }
    
    // User agent validation
    if (BLOCKED_USER_AGENTS.test(userAgent)) {
        await recordSuspiciousActivity(clientIP, 'blocked_user_agent');
        return { blocked: true, reason: 'Blocked user agent', status: 403 };
    }
    
    // Strict user agent check for non-legit clients
    if (!ALLOWED_USER_AGENTS.test(userAgent) && userAgent.length > 0 && userAgent.length < 20) {
        await recordSuspiciousActivity(clientIP, 'suspicious_user_agent');
        return { blocked: true, reason: 'Invalid user agent', status: 403 };
    }
    
    // Suspicious IP check
    const suspicious = suspiciousIPs.get(clientIP);
    if (suspicious && suspicious.count >= SUSPICIOUS_THRESHOLD) {
        return { blocked: true, reason: 'IP temporarily blocked due to suspicious activity', status: 429 };
    }
    
    // Malicious pattern detection
    const url = new URL(request.url);
    const fullPath = url.pathname + url.search;
    
    for (const pattern of MALICIOUS_PATTERNS) {
        if (pattern.test(fullPath)) {
            await recordSuspiciousActivity(clientIP, 'malicious_pattern');
            return { blocked: true, reason: 'Malicious request detected', status: 400 };
        }
    }
    
    // Multipart validation
    if (request.method === 'POST' && contentType.includes('multipart/form-data')) {
        const boundary = contentType.split('boundary=')[1];
        if (!boundary || boundary.length > 200 || boundary.length < 10) {
            return { blocked: true, reason: 'Invalid multipart boundary', status: 400 };
        }
    }
    
    return { blocked: false };
}

async function recordSuspiciousActivity(ip, type) {
    const now = Date.now();
    const existing = suspiciousIPs.get(ip);
    
    if (existing) {
        existing.count++;
        existing.types.add(type);
        existing.lastActivity = now;
        suspiciousIPs.set(ip, existing);
    } else {
        suspiciousIPs.set(ip, {
            count: 1,
            types: new Set([type]),
            expires: now + 3600000,
            lastActivity: now
        });
    }
}

// ========== REQUEST PARSING ==========
async function parseRequest(request) {
    const url = new URL(request.url);
    let path = url.pathname;
    
    // Remove /api prefix if present
    if (path.startsWith('/api')) {
        path = path.substring(4);
    }
    
    const clientIP = getClientIP(request);
    
    if (!URL_PATH_REGEX.test(path)) {
        return { valid: false };
    }
    
    const match = path.match(URL_PATH_REGEX);
    const botToken = match?.groups?.bot_token || '';
    const apiMethod = match?.groups?.api_method || '';
    
    // Validate token format
    if (botToken.length > MAX_TOKEN_LENGTH || botToken.length < 40) {
        return { valid: false };
    }
    
    if (!botToken.includes(':')) {
        return { valid: false };
    }
    
    // Validate method name
    if (!/^[a-zA-Z][a-zA-Z0-9_]{0,49}$/.test(apiMethod)) {
        return { valid: false };
    }
    
    return {
        valid: true,
        clientIP,
        botToken,
        apiMethod,
        path,
        url
    };
}

function getClientIP(request) {
    // Cloudflare IP
    const cfIP = request.headers.get('cf-connecting-ip');
    if (cfIP && isValidIP(cfIP)) return cfIP;
    
    // X-Forwarded-For
    const xff = request.headers.get('x-forwarded-for');
    if (xff) {
        const ips = xff.split(',').map(ip => ip.trim());
        for (const ip of ips) {
            if (isValidIP(ip)) return ip;
        }
    }
    
    // X-Real-IP
    const realIP = request.headers.get('x-real-ip');
    if (realIP && isValidIP(realIP)) return realIP;
    
    return 'unknown';
}

function isValidIP(ip) {
    // IPv4
    const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    // IPv6 (simplified)
    const ipv6Regex = /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/;
    
    return ipv4Regex.test(ip) || ipv6Regex.test(ip);
}

// ========== RATE LIMITING ==========
async function checkAdvancedRateLimit(clientIP, botToken) {
    const now = Date.now();
    
    // Cleanup old counters
    for (const [key, data] of requestCounters.ip.entries()) {
        if (now >= data.resetTime) requestCounters.ip.delete(key);
    }
    for (const [key, data] of requestCounters.token.entries()) {
        if (now >= data.resetTime) requestCounters.token.delete(key);
    }
    for (const [key, data] of requestCounters.burst.entries()) {
        if (now >= data.resetTime) requestCounters.burst.delete(key);
    }
    
    // Global limit
    if (now >= requestCounters.global.resetTime) {
        requestCounters.global.count = 0;
        requestCounters.global.resetTime = now + RATE_LIMITS.GLOBAL.window;
    }
    
    if (requestCounters.global.count >= RATE_LIMITS.GLOBAL.max) {
        const retryAfter = Math.ceil((requestCounters.global.resetTime - now) / 1000);
        return { limited: true, retryAfter: Math.min(retryAfter, 60) };
    }
    
    // Burst limit (per second)
    const burstKey = `burst_${clientIP}`;
    let burstData = requestCounters.burst.get(burstKey);
    if (!burstData || now >= burstData.resetTime) {
        burstData = { count: 0, resetTime: now + RATE_LIMITS.BURST.window };
        requestCounters.burst.set(burstKey, burstData);
    }
    
    if (burstData.count >= RATE_LIMITS.BURST.max) {
        return { limited: true, retryAfter: 1 };
    }
    burstData.count++;
    
    // IP limit
    const ipKey = `ip_${clientIP}`;
    let ipData = requestCounters.ip.get(ipKey);
    if (!ipData || now >= ipData.resetTime) {
        ipData = { count: 0, resetTime: now + RATE_LIMITS.IP.window };
        requestCounters.ip.set(ipKey, ipData);
    }
    
    if (ipData.count >= RATE_LIMITS.IP.max) {
        const retryAfter = Math.ceil((ipData.resetTime - now) / 1000);
        return { limited: true, retryAfter: Math.min(retryAfter, 60) };
    }
    ipData.count++;
    
    // Token limit
    const tokenKey = `token_${botToken}`;
    let tokenData = requestCounters.token.get(tokenKey);
    if (!tokenData || now >= tokenData.resetTime) {
        tokenData = { count: 0, resetTime: now + RATE_LIMITS.TOKEN.window };
        requestCounters.token.set(tokenKey, tokenData);
    }
    
    if (tokenData.count >= RATE_LIMITS.TOKEN.max) {
        const retryAfter = Math.ceil((tokenData.resetTime - now) / 1000);
        return { limited: true, retryAfter: Math.min(retryAfter, 60) };
    }
    tokenData.count++;
    
    // Increment global counter
    requestCounters.global.count++;
    
    return { limited: false };
}

// ========== CIRCUIT BREAKER ==========
function checkCircuitBreaker(clientIP) {
    const breaker = circuitBreakers.get(clientIP);
    if (!breaker) return 'CLOSED';
    
    const now = Date.now();
    
    if (breaker.state === 'OPEN') {
        if (now - breaker.lastFailureTime >= CIRCUIT_BREAKER.TIMEOUT) {
            breaker.state = 'HALF_OPEN';
            breaker.halfOpenAttempts = 0;
            return 'HALF_OPEN';
        }
        return 'OPEN';
    }
    
    return breaker.state;
}

function updateCircuitBreaker(clientIP, success) {
    let breaker = circuitBreakers.get(clientIP);
    
    if (!breaker) {
        breaker = {
            state: 'CLOSED',
            failureCount: 0,
            lastFailureTime: 0,
            halfOpenAttempts: 0
        };
        circuitBreakers.set(clientIP, breaker);
    }
    
    if (success) {
        if (breaker.state === 'HALF_OPEN') {
            breaker.state = 'CLOSED';
            breaker.failureCount = 0;
        } else if (breaker.state === 'CLOSED') {
            breaker.failureCount = Math.max(0, breaker.failureCount - 1);
        }
    } else {
        breaker.failureCount++;
        breaker.lastFailureTime = Date.now();
        
        if (breaker.failureCount >= CIRCUIT_BREAKER.FAILURE_THRESHOLD) {
            breaker.state = 'OPEN';
        }
    }
}

// ========== TOKEN VALIDATION ==========
async function validateBotTokenAdvanced(token, env) {
    // Check cache
    const cached = tokenValidationCache.get(token);
    if (cached && Date.now() < cached.expires) {
        return cached.valid;
    }
    
    // Basic format validation
    if (!token || token.length < 40 || token.length > MAX_TOKEN_LENGTH || !token.includes(':')) {
        setTokenCache(token, false, 60000); // Cache invalid for 1 minute
        return false;
    }
    
    const [botId, botHash] = token.split(':');
    if (!botId || !botHash || !/^\d+$/.test(botId) || !/^[A-Za-z0-9_-]{30,}$/.test(botHash)) {
        setTokenCache(token, false, 60000);
        return false;
    }
    
    // Real validation with Telegram API
    try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 5000);
        
        const response = await fetch(`https://api.telegram.org/bot${token}/getMe`, {
            signal: controller.signal
        });
        
        clearTimeout(timeout);
        
        if (response.ok) {
            const data = await response.json();
            const isValid = data.ok === true;
            setTokenCache(token, isValid, isValid ? CACHE_TTL : 60000);
            return isValid;
        }
        
        setTokenCache(token, false, 60000);
        return false;
        
    } catch (error) {
        console.error('Token validation error:', error);
        setTokenCache(token, false, 30000); // Cache error for 30 seconds
        return false;
    }
}

function setTokenCache(token, valid, ttl) {
    // Prevent cache from growing too large
    if (tokenValidationCache.size >= MAX_CACHE_SIZE) {
        const firstKey = tokenValidationCache.keys().next().value;
        tokenValidationCache.delete(firstKey);
    }
    
    tokenValidationCache.set(token, {
        valid: valid,
        expires: Date.now() + ttl
    });
}

// ========== PROXY WITH RETRY ==========
async function proxyToTelegramWithRetry(request, requestInfo, ctx) {
    let lastError;
    
    for (let attempt = 0; attempt <= RETRY_CONFIG.MAX_RETRIES; attempt++) {
        try {
            if (attempt > 0) {
                requestStats.retries++;
                const delay = Math.min(
                    RETRY_CONFIG.INITIAL_DELAY * Math.pow(RETRY_CONFIG.BACKOFF_FACTOR, attempt - 1),
                    RETRY_CONFIG.MAX_DELAY
                );
                await new Promise(resolve => setTimeout(resolve, delay));
            }
            
            const response = await proxyToTelegram(request, requestInfo, attempt);
            
            // Don't retry client errors (4xx)
            if (response.status < 500 || response.status === 429) {
                return response;
            }
            
            lastError = new Error(`HTTP ${response.status}: ${response.statusText}`);
            
        } catch (error) {
            lastError = error;
            
            // Don't retry on certain errors
            if (error.message.includes('Invalid token') || error.message.includes('401')) {
                throw error;
            }
            
            if (attempt === RETRY_CONFIG.MAX_RETRIES) {
                throw error;
            }
        }
    }
    
    throw lastError || new Error('Max retries exceeded');
}

async function proxyToTelegram(request, requestInfo, attempt = 0) {
    const { botToken, apiMethod, path } = requestInfo;
    
    // Rotate endpoints for load balancing
    const endpointIndex = attempt % TELEGRAM_ENDPOINTS.length;
    const endpoint = TELEGRAM_ENDPOINTS[endpointIndex];
    
    const newUrl = new URL(request.url);
    newUrl.hostname = endpoint.split(':')[0];
    newUrl.port = endpoint.includes(':') ? endpoint.split(':')[1] : (endpoint === 'api.telegram.org' ? '' : '443');
    newUrl.pathname = path;
    newUrl.protocol = 'https:';
    
    // Prepare headers
    const requestHeaders = new Headers(request.headers);
    sanitizeHeaders(requestHeaders);
    
    requestHeaders.set('User-Agent', 'Cloudflare-Worker-Telegram-Proxy/2.0');
    requestHeaders.set('Accept-Encoding', 'gzip, deflate, br');
    requestHeaders.set('Connection', 'keep-alive');
    
    // Prepare body
    let requestBody;
    let contentType = request.headers.get('content-type') || '';
    
    if (request.method !== 'GET' && request.method !== 'HEAD') {
        try {
            if (contentType.includes('multipart/form-data') && FILE_UPLOAD_METHODS.has(apiMethod)) {
                requestBody = await request.formData();
                requestHeaders.delete('content-type'); // Let fetch set it with boundary
            } else {
                requestBody = await request.arrayBuffer();
                if (contentType) {
                    requestHeaders.set('Content-Type', contentType);
                }
            }
        } catch (error) {
            throw new Error('Failed to read request body: ' + error.message);
        }
    }
    
    // Set timeout based on operation type
    const timeoutDuration = FILE_UPLOAD_METHODS.has(apiMethod) ? 120000 : 30000;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutDuration);
    
    try {
        const cacheConfig = CACHE_CONFIGS[apiMethod] || CACHE_CONFIGS.default;
        
        const fetchOptions = {
            method: request.method,
            headers: requestHeaders,
            signal: controller.signal,
            redirect: 'follow'
        };
        
        if (requestBody !== undefined) {
            fetchOptions.body = requestBody;
        }
        
        // Cloudflare specific optimizations
        if (typeof ctx !== 'undefined' && ctx.passThroughOnException) {
            ctx.passThroughOnException();
        }
        
        const response = await fetch(newUrl.toString(), fetchOptions);
        
        if (!response.ok && response.status >= 500 && response.status < 600) {
            throw new Error(`Server error: ${response.status}`);
        }
        
        // Process response
        const responseHeaders = new Headers(response.headers);
        addAdvancedSecurityHeaders(responseHeaders);
        
        const responseBody = await response.arrayBuffer();
        
        return new Response(responseBody, {
            status: response.status,
            statusText: response.statusText,
            headers: getCorsHeaders(responseHeaders)
        });
        
    } finally {
        clearTimeout(timeout);
    }
}

function sanitizeHeaders(headers) {
    const forbiddenHeaders = [
        'cf-connecting-ip', 'cf-ipcountry', 'cf-ray', 'cf-visitor',
        'x-forwarded-for', 'x-real-ip', 'x-forwarded-proto',
        'host', 'origin', 'referer', 'cookie', 'authorization',
        'proxy-authorization', 'proxy-connection'
    ];
    
    forbiddenHeaders.forEach(header => headers.delete(header));
    
    // Remove any Cloudflare or proxy headers
    for (const [key] of headers) {
        const lowerKey = key.toLowerCase();
        if (lowerKey.startsWith('cf-') || 
            lowerKey.startsWith('x-forwarded-') ||
            lowerKey.startsWith('sec-') ||
            lowerKey.includes('proxy')) {
            headers.delete(key);
        }
    }
}

// ========== RESPONSE HANDLING ==========
function addAdvancedSecurityHeaders(headers) {
    headers.set('X-Content-Type-Options', 'nosniff');
    headers.set('X-Frame-Options', 'DENY');
    headers.set('X-XSS-Protection', '1; mode=block');
    headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
    headers.set('Content-Security-Policy', "default-src 'none'; script-src 'none'; object-src 'none'");
    headers.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
    headers.set('X-Permitted-Cross-Domain-Policies', 'none');
    headers.set('X-Download-Options', 'noopen');
    headers.set('X-DNS-Prefetch-Control', 'off');
    headers.set('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
}

function getCorsHeaders(headers = new Headers()) {
    const corsHeaders = new Headers(headers);
    corsHeaders.set('Access-Control-Allow-Origin', '*');
    corsHeaders.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    corsHeaders.set('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With, X-Request-ID');
    corsHeaders.set('Access-Control-Expose-Headers', 'X-RateLimit-Remaining, X-RateLimit-Reset, X-Response-Time, Retry-After');
    corsHeaders.set('Access-Control-Max-Age', '86400');
    corsHeaders.set('Vary', 'Origin, Access-Control-Request-Method, Access-Control-Request-Headers');
    
    return corsHeaders;
}

function handleCorsPreflight() {
    return new Response(null, {
        status: 204,
        headers: getCorsHeaders()
    });
}

function createErrorResponse(message, status = 400) {
    const headers = getCorsHeaders();
    headers.set('Content-Type', 'application/json');
    headers.set('Cache-Control', 'no-store, no-cache, must-revalidate');
    
    return new Response(JSON.stringify({
        ok: false,
        error_code: status,
        description: message,
        timestamp: new Date().toISOString(),
        request_id: generateRequestId()
    }), {
        status,
        headers
    });
}

function createRateLimitResponse(retryAfter) {
    const headers = getCorsHeaders();
    headers.set('Content-Type', 'application/json');
    headers.set('Retry-After', retryAfter.toString());
    headers.set('X-RateLimit-Remaining', '0');
    headers.set('X-RateLimit-Reset', (Date.now() + (retryAfter * 1000)).toString());
    headers.set('Cache-Control', 'no-store, no-cache, must-revalidate');
    
    return new Response(JSON.stringify({
        ok: false,
        error_code: 429,
        description: 'Too many requests. Please try again later.',
        parameters: { retry_after: retryAfter },
        timestamp: new Date().toISOString(),
        request_id: generateRequestId()
    }), {
        status: 429,
        headers
    });
}

function handleProxyError(error) {
    const errorMessage = error.message || 'Unknown error occurred';
    const isTimeout = error.name === 'AbortError' || errorMessage.includes('timeout');
    const status = isTimeout ? 504 : 502;
    
    const headers = getCorsHeaders();
    headers.set('Content-Type', 'application/json');
    
    return new Response(JSON.stringify({
        ok: false,
        error_code: status,
        description: isTimeout ? 'Gateway Timeout' : 'Bad Gateway',
        details: errorMessage.substring(0, 200),
        timestamp: new Date().toISOString(),
        request_id: generateRequestId()
    }), {
        status,
        headers
    });
}

function updateStats(startTime, success) {
    const responseTime = Date.now() - startTime;
    requestStats.total++;
    
    if (!success) {
        requestStats.errors++;
    }
    
    // Update average response time (moving average)
    requestStats.avgResponseTime = requestStats.avgResponseTime === 0
        ? responseTime
        : (requestStats.avgResponseTime * 0.9) + (responseTime * 0.1);
}

function generateRequestId() {
    return `${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 8)}`;
}
