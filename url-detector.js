// URL Detector Module
const urlDetector = (function () {
    const maliciousDomains = new Set();
    const maliciousPaths = new Set();
    const phishingKeywords = ['login', 'account', 'verify', 'secure', 'banking', 'paypal', 'ebay', 'amazon'];
    const suspiciousTlds = ['.tk', '.gq', '.ml', '.cf', '.ga', '.xyz', '.top', '.icu'];
    const safeDomains = new Set(['youtube.com', 'facebook.com', 'instagram.com', 'google.com', 'amazon.com']);

    async function init() {
        try {
            const response = await fetch('malicious-urls.json');
            const data = await response.json();
            data.domains.forEach(domain => maliciousDomains.add(domain));
            data.paths.forEach(path => maliciousPaths.add(path));
            console.log('URL Detector initialized with', maliciousDomains.size, 'malicious domains');
        } catch (error) {
            console.error('Error loading malicious URLs dataset:', error);
            loadFallbackDataset();
        }
    }

    function loadFallbackDataset() {
        const fallbackDomains = ['evil.com', 'phishing-site.net', 'malware-distribution.org', 'fake-login-page.com', 'scam-website.xyz', 'bank-impersonator.tk'];
        const fallbackPaths = ['/login.php', '/account/verify', '/secure/banking', '/paypal/update', '/amazon/security'];
        fallbackDomains.forEach(domain => maliciousDomains.add(domain));
        fallbackPaths.forEach(path => maliciousPaths.add(path));
    }

    async function analyzeUrl(url) {
        const parsedUrl = parseUrl(url);
        if (!parsedUrl.valid) {
            return {
                isSafe: false,
                url,
                risks: [{ type: 'invalid', message: 'Invalid URL format', severity: 'high' }]
            };
        }

        const normalizedDomain = parsedUrl.hostname.replace(/^www\./, '').toLowerCase();
        const domainAnalysis = analyzeDomain(parsedUrl, normalizedDomain);

        const exactMatch = maliciousDomains.has(normalizedDomain) || maliciousPaths.has(parsedUrl.pathname);
        const suspiciousPatterns = checkSuspiciousPatterns(parsedUrl);
        const isSafe = !exactMatch && suspiciousPatterns.length === 0 && domainAnalysis.isSafe;

        const risks = [];
        if (exactMatch) {
            risks.push({ type: 'known-threat', message: 'URL matches known malicious site', severity: 'high' });
        }
        risks.push(...suspiciousPatterns);
        risks.push(...domainAnalysis.risks);

        return {
            isSafe,
            url,
            domain: normalizedDomain,
            hasSSL: parsedUrl.protocol === 'https:',
            domainTrust: domainAnalysis.trustLevel,
            risks
        };
    }

    function parseUrl(url) {
        try {
            if (!url.startsWith('http://') && !url.startsWith('https://')) {
                url = 'http://' + url;
            }
            const parsed = new URL(url);
            return {
                valid: true,
                protocol: parsed.protocol,
                hostname: parsed.hostname,
                pathname: parsed.pathname,
                search: parsed.search
            };
        } catch {
            return { valid: false };
        }
    }

    function checkSuspiciousPatterns(parsedUrl) {
        const risks = [];
        const lowerUrl = parsedUrl.hostname + parsedUrl.pathname;

        phishingKeywords.forEach(keyword => {
            if (lowerUrl.includes(keyword)) {
                risks.push({
                    type: 'phishing-keyword',
                    message: `Suspicious keyword "${keyword}" detected`,
                    severity: 'medium'
                });
            }
        });

        suspiciousTlds.forEach(tld => {
            if (parsedUrl.hostname.endsWith(tld)) {
                risks.push({
                    type: 'suspicious-tld',
                    message: `Suspicious TLD "${tld}" detected`,
                    severity: 'medium'
                });
            }
        });

        if (/^\d{1,3}(\.\d{1,3}){3}$/.test(parsedUrl.hostname)) {
            risks.push({
                type: 'ip-address',
                message: 'URL uses IP address instead of domain',
                severity: 'medium'
            });
        }

        if (parsedUrl.hostname.length > 30) {
            risks.push({
                type: 'long-domain',
                message: 'Unusually long domain (possible obfuscation)',
                severity: 'low'
            });
        }

        const subdomainCount = parsedUrl.hostname.split('.').length - 1;
        if (subdomainCount > 3) {
            risks.push({
                type: 'subdomain-nesting',
                message: 'Deep subdomain nesting (possible phishing)',
                severity: 'low'
            });
        }

        return risks;
    }

    function analyzeDomain(parsedUrl, domainName) {
        const risks = [];
        let isSafe = true;
        let trustLevel = 'unknown';

        if (safeDomains.has(domainName)) {
            trustLevel = 'trusted';
            return { isSafe: true, trustLevel, risks };
        }

        const popularBrands = ['google', 'facebook', 'amazon', 'apple', 'microsoft', 'paypal', 'ebay'];
        for (const brand of popularBrands) {
            if (domainName.includes(brand) && domainName !== `${brand}.com`) {
                risks.push({
                    type: 'brand-impersonation',
                    message: `Possible impersonation of ${brand}`,
                    severity: 'high'
                });
                isSafe = false;
                trustLevel = 'impersonator';
            }
        }

        if (trustLevel === 'unknown') {
            trustLevel = 'unverified';
        }

        return { isSafe, trustLevel, risks };
    }

    return {
        init,
        analyzeUrl
    };
})();
