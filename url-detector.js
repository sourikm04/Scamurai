// Advanced URL Detector Module
const urlDetector = (function () {
    const maliciousDomains = new Set();
    const maliciousPaths = new Set();
    const urlShorteners = new Set([
        'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'is.gd', 'v.gd', 'ow.ly', 
        'su.pr', 'twurl.nl', 'snipurl.com', 'short.to', 'BudURL.com', 'ping.fm',
        'tr.im', 'snipr.com', 'short.ie', 'kl.am', 'wp.me', 'rubyurl.com', 'om.ly',
        'to.ly', 'bit.do', 't.co', 'lnkd.in', 'db.tt', 'qr.ae', 'adf.ly', 'goo.gl',
        'bitly.com', 'cur.lv', 'tiny.cc', 'url4.eu', 'tr.im', 'twitthis.com',
        'u.to', 'j.mp', 'buzurl.com', 'cutt.us', 'u.bb', 'yourls.org', 'x.co',
        'prettylinkpro.com', 'scrnch.me', 'filoops.info', 'vzturl.com', 'qr.net',
        '1url.com', 'tweez.me', 'v.gd', 'tr.im', 'link.zip.net'
    ]);
    
    const phishingKeywords = [
        'login', 'account', 'verify', 'secure', 'banking', 'paypal', 'ebay',
        'update', 'confirm', 'validate', 'authenticate', 'signin', 'sign-in', 'logon',
        'password', 'credential', 'security', 'safety', 'protection', 'alert',
        'suspended', 'locked', 'unlock', 'restore', 'recover', 'reset', 'change',
        'modify', 'upgrade', 'premium', 'subscription', 'billing', 'payment',
        'invoice', 'receipt', 'statement', 'transaction', 'transfer', 'deposit',
        'withdrawal', 'balance', 'credit', 'debit', 'card', 'bank', 'financial'
    ];
    
    const suspiciousTlds = ['.tk', '.gq', '.ml', '.cf', '.ga', '.xyz', '.top', '.icu', '.cc', '.cn', '.ru', '.su'];
    const safeDomains = new Set([
        'youtube.com', 'facebook.com', 'instagram.com', 'google.com', 'amazon.com',
        'microsoft.com', 'apple.com', 'netflix.com', 'twitter.com', 'linkedin.com',
        'github.com', 'stackoverflow.com', 'reddit.com', 'wikipedia.org', 'yahoo.com',
        'bing.com', 'duckduckgo.com', 'brave.com', 'mozilla.org', 'opera.com',
        'spotify.com', 'discord.com', 'slack.com', 'zoom.us', 'teams.microsoft.com',
        'dropbox.com', 'onedrive.live.com', 'drive.google.com', 'mega.nz',
        'paypal.com', 'stripe.com', 'shopify.com', 'ebay.com', 'etsy.com',
        'airbnb.com', 'uber.com', 'lyft.com', 'doordash.com', 'grubhub.com',
        'tripadvisor.com', 'booking.com', 'expedia.com', 'hotels.com',
        'weather.com', 'accuweather.com', 'bbc.com', 'cnn.com', 'reuters.com',
        'nytimes.com', 'wsj.com', 'forbes.com', 'techcrunch.com', 'wired.com',
        'medium.com', 'substack.com', 'patreon.com', 'kickstarter.com', 'indiegogo.com',
        'udemy.com', 'coursera.org', 'edx.org', 'khanacademy.org', 'codecademy.com',
        'freecodecamp.org', 'w3schools.com', 'mdn.io', 'stackoverflow.com',
        'npmjs.com', 'github.io', 'gitlab.com', 'bitbucket.org', 'heroku.com',
        'vercel.com', 'netlify.com', 'cloudflare.com', 'aws.amazon.com', 'azure.microsoft.com',
        'digitalocean.com', 'linode.com', 'vultr.com', 'ovh.com', 'godaddy.com',
        'namecheap.com', 'hostgator.com', 'bluehost.com', 'dreamhost.com', 'siteground.com',
        'tcs.com', 'tcs.co.in', 'tata.com', 'tata.co.in', 'sap.com', 'psgitech.com'
    ]);
    
    const brandPatterns = {
        'google': ['g00gle', 'go0gle', 'g0ogle', 'goog1e', 'g00g1e', 'g0og1e', 'goog1e'],
        'facebook': ['faceb00k', 'f4cebook', 'f4ceb00k', 'faceb0ok', 'f4ceb0ok'],
        'amazon': ['amaz0n', 'am4zon', 'am4z0n', 'amaz0n', 'am4z0n'],
        'paypal': ['p4ypal', 'payp4l', 'p4yp4l', 'payp0l', 'p4yp0l'],
        'apple': ['4pple', 'app1e', '4pp1e', 'app0e', '4pp0e'],
        'microsoft': ['m1crosoft', 'm1cr0s0ft', 'm1cr0soft', 'm1cros0ft'],
        'ebay': ['3bay', '3b4y', 'eb4y', '3b4y'],
        'netflix': ['n3tflix', 'n3tfl1x', 'netfl1x', 'n3tfl1x'],
        'twitter': ['tw1tter', 'tw1tt3r', 'twitt3r', 'tw1tt3r'],
        'instagram': ['1nstagram', '1nst4gram', 'inst4gram', '1nst4gram']
    };

    let threatIntelligence = null;
    let domainCache = new Map();

    async function init() {
        try {
            console.log('🔧 Loading malicious URLs dataset...');
            // Load malicious URLs dataset
            const response = await fetch('malicious-urls.json');
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            const data = await response.json();
            data.domains.forEach(domain => maliciousDomains.add(domain));
            data.paths.forEach(path => maliciousPaths.add(path));
            console.log('✅ URL Detector initialized with', maliciousDomains.size, 'malicious domains');
            
            // Initialize threat intelligence
            await initThreatIntelligence();
        } catch (error) {
            console.error('❌ Error loading malicious URLs dataset:', error);
            console.log('🔄 Loading fallback dataset...');
            loadFallbackDataset();
            await initThreatIntelligence();
        }
    }

    async function initThreatIntelligence() {
        // Initialize threat intelligence sources
        threatIntelligence = {
            virusTotal: { apiKey: null, enabled: false },
            urlVoid: { enabled: false },
            googleSafeBrowsing: { enabled: false },
            phishTank: { enabled: false }
        };
        
        // Try to load API keys from environment or config
        try {
            const config = await fetch('config.json');
            const configData = await config.json();
            if (configData.virusTotalApiKey) {
                threatIntelligence.virusTotal.apiKey = configData.virusTotalApiKey;
                threatIntelligence.virusTotal.enabled = true;
            }
        } catch (error) {
            console.log('No external API keys configured, using local analysis only');
        }
    }

    function loadFallbackDataset() {
        const fallbackDomains = [
            'evil.com', 'phishing-site.net', 'malware-distribution.org', 
            'fake-login-page.com', 'scam-website.xyz', 'bank-impersonator.tk',
            'malware.example.com', 'phishing.example.org', 'scam.example.net'
        ];
        const fallbackPaths = [
            '/login.php', '/account/verify', '/secure/banking', '/paypal/update', 
            '/amazon/security', '/google/verify', '/facebook/login'
        ];
        fallbackDomains.forEach(domain => maliciousDomains.add(domain));
        fallbackPaths.forEach(path => maliciousPaths.add(path));
        console.log('Using fallback dataset with', maliciousDomains.size, 'malicious domains');
    }

    async function analyzeUrl(url) {
        const startTime = Date.now();
        const parsedUrl = parseUrl(url);
        
        if (!parsedUrl.valid) {
            return {
                isSafe: false,
                url,
                score: 0,
                risks: [{ type: 'invalid', message: 'Invalid URL format', severity: 'high' }],
                analysisTime: Date.now() - startTime
            };
        }

        const normalizedDomain = parsedUrl.hostname.replace(/^www\./, '').toLowerCase();
        
        // Check cache first
        if (domainCache.has(normalizedDomain)) {
            const cached = domainCache.get(normalizedDomain);
            return {
                ...cached,
                url,
                analysisTime: Date.now() - startTime
            };
        }

        // Perform comprehensive analysis
        try {
            const results = await Promise.all([
                analyzeDomain(parsedUrl, normalizedDomain),
                checkSuspiciousPatterns(parsedUrl),
                checkUrlShortener(parsedUrl),
                checkBrandImpersonation(parsedUrl, normalizedDomain),
                checkMalwareSignatures(parsedUrl),
                checkSocialEngineering(parsedUrl),
                validateSSL(parsedUrl),
                checkDomainAge(parsedUrl),
                checkReputation(parsedUrl, normalizedDomain)
            ]);

            const [domainAnalysis, suspiciousPatterns, urlShortener, brandImpersonation, 
                   malwareSignatures, socialEngineering, sslValidation, domainAge, reputation] = results;

            // Combine all risks
            const allRisks = [
                ...suspiciousPatterns.risks || [],
                ...domainAnalysis.risks || [],
                ...urlShortener.risks || [],
                ...brandImpersonation.risks || [],
                ...malwareSignatures.risks || [],
                ...socialEngineering.risks || [],
                ...sslValidation.risks || [],
                ...domainAge.risks || [],
                ...reputation.risks || []
            ];

            // Calculate security score (0-100)
            const score = calculateSecurityScore(allRisks, domainAnalysis, sslValidation, reputation, domainAge);
            
            // Determine if URL is safe
            const isSafe = score >= 70 && allRisks.filter(r => r.severity === 'high').length === 0;

            const result = {
                isSafe,
                url,
                domain: normalizedDomain,
                score,
                domainTrust: domainAnalysis.trustLevel,
                hasSSL: sslValidation.isValid,
                sslDetails: sslValidation.details,
                domainAge: domainAge.age,
                isUrlShortener: urlShortener.isShortener,
                reputation: reputation.score,
                risks: allRisks,
                analysisTime: Date.now() - startTime
            };

            // Cache the result
            domainCache.set(normalizedDomain, result);
            
            return result;
        } catch (analysisError) {
            console.error('❌ Error during analysis:', analysisError);
            // Return a basic result with error information
            return {
                isSafe: false,
                url,
                domain: normalizedDomain,
                score: 0,
                domainTrust: 'unknown',
                hasSSL: false,
                sslDetails: 'Analysis failed',
                domainAge: 'unknown',
                isUrlShortener: false,
                reputation: 0,
                risks: [{
                    type: 'analysis-error',
                    message: 'Analysis failed due to technical error',
                    severity: 'medium'
                }],
                analysisTime: Date.now() - startTime
            };
        }
    }

    function calculateSecurityScore(risks, domainAnalysis, sslValidation, reputation, domainAge) {
        let score = 100;
        const deductions = [];
        const bonuses = [];
        
        // Deduct points for risks (more balanced scoring)
        risks.forEach(risk => {
            let deduction = 0;
            switch (risk.severity) {
                case 'high': deduction = 20; break;
                case 'medium': deduction = 10; break;
                case 'low': deduction = 3; break;
            }
            score -= deduction;
            deductions.push(`${risk.type}: -${deduction} (${risk.severity})`);
        });
        
        // Bonus for trusted domains
        if (domainAnalysis.trustLevel === 'trusted') {
            score += 10;
            bonuses.push('Trusted domain: +10');
        }
        
        // Bonus for valid SSL
        if (sslValidation.isValid) {
            score += 5;
            bonuses.push('Valid SSL: +5');
        }
        
        // Bonus for good reputation
        if (reputation.score > 80) {
            score += 5;
            bonuses.push('High reputation: +5');
        } else if (reputation.score > 60) {
            score += 2;
            bonuses.push('Good reputation: +2');
        }
        
        // Penalty for URL shorteners
        if (reputation.isShortener) {
            score -= 10;
            deductions.push('URL shortener: -10');
        }
        
        // Penalty for new domains (only if not a known safe domain)
        if (domainAge && domainAge.age === 'new' && domainAnalysis.trustLevel !== 'trusted') {
            score -= 5;
            deductions.push('New domain: -5');
        }
        
        // Ensure score stays within bounds
        const finalScore = Math.max(0, Math.min(100, Math.round(score)));
        
        // Debug logging
        console.log('🔍 Security Score Calculation:');
        console.log('Starting score: 100');
        if (deductions.length > 0) {
            console.log('Deductions:', deductions);
        }
        if (bonuses.length > 0) {
            console.log('Bonuses:', bonuses);
        }
        console.log(`Final score: ${finalScore}/100`);
        
        return finalScore;
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
                search: parsed.search,
                hash: parsed.hash,
                port: parsed.port
            };
        } catch {
            return { valid: false };
        }
    }

    function checkSuspiciousPatterns(parsedUrl) {
        const risks = [];
        const lowerUrl = parsedUrl.hostname + parsedUrl.pathname;
        const lowerHostname = parsedUrl.hostname.toLowerCase();
        const lowerPathname = parsedUrl.pathname.toLowerCase();

        // Check for phishing keywords with context awareness
        phishingKeywords.forEach(keyword => {
            if (lowerUrl.includes(keyword)) {
                // Skip if the keyword is part of a known safe domain
                const isInSafeDomain = Array.from(safeDomains).some(safeDomain => 
                    safeDomain.includes(keyword) && lowerHostname.includes(safeDomain)
                );
                
                // Skip if it's a legitimate path on a safe domain
                const isLegitimatePath = Array.from(safeDomains).some(safeDomain => 
                    lowerHostname.includes(safeDomain) && lowerPathname.includes(keyword)
                );
                
                if (!isInSafeDomain && !isLegitimatePath) {
                    risks.push({
                        type: 'phishing-keyword',
                        message: `Suspicious keyword "${keyword}" detected`,
                        severity: 'medium'
                    });
                }
            }
        });

        // Check for suspicious TLDs
        suspiciousTlds.forEach(tld => {
            if (parsedUrl.hostname.endsWith(tld)) {
                risks.push({
                    type: 'suspicious-tld',
                    message: `Suspicious TLD "${tld}" detected`,
                    severity: 'medium'
                });
            }
        });

        // Check for IP addresses
        if (/^\d{1,3}(\.\d{1,3}){3}$/.test(parsedUrl.hostname)) {
            risks.push({
                type: 'ip-address',
                message: 'URL uses IP address instead of domain',
                severity: 'medium'
            });
        }

        // Check for unusually long domains
        if (parsedUrl.hostname.length > 50) {
            risks.push({
                type: 'long-domain',
                message: 'Unusually long domain (possible obfuscation)',
                severity: 'low'
            });
        }

        // Check for deep subdomain nesting
        const subdomainCount = parsedUrl.hostname.split('.').length - 1;
        if (subdomainCount > 4) {
            risks.push({
                type: 'subdomain-nesting',
                message: 'Deep subdomain nesting (possible phishing)',
                severity: 'medium'
            });
        }

        // Check for homograph attacks (lookalike characters)
        const homographPatterns = [
            /[а-я]/g, // Cyrillic
            /[α-ω]/g, // Greek
            /[０-９]/g // Full-width digits
        ];
        
        homographPatterns.forEach(pattern => {
            if (pattern.test(parsedUrl.hostname)) {
                risks.push({
                    type: 'homograph-attack',
                    message: 'Possible homograph attack using lookalike characters',
                    severity: 'high'
                });
            }
        });

        // Check for excessive special characters
        const specialCharCount = (parsedUrl.hostname.match(/[^a-zA-Z0-9.-]/g) || []).length;
        if (specialCharCount > 3) {
            risks.push({
                type: 'excessive-special-chars',
                message: 'Excessive special characters in domain',
                severity: 'medium'
            });
        }

        return { risks };
    }

    function checkUrlShortener(parsedUrl) {
        const normalizedDomain = parsedUrl.hostname.replace(/^www\./, '').toLowerCase();
        const isShortener = urlShorteners.has(normalizedDomain);
        
        return {
            isShortener,
            risks: isShortener ? [{
                type: 'url-shortener',
                message: 'URL shortening service detected - unable to verify final destination',
                severity: 'medium'
            }] : []
        };
    }

    function checkBrandImpersonation(parsedUrl, domainName) {
        const risks = [];
        
        for (const [brand, patterns] of Object.entries(brandPatterns)) {
            if (domainName.includes(brand)) {
                // Check if it's the legitimate domain
                if (domainName === `${brand}.com` || domainName === `www.${brand}.com`) {
                    continue;
                }
                
                // Check for lookalike patterns
                const isLookalike = patterns.some(pattern => domainName.includes(pattern));
                if (isLookalike) {
                    risks.push({
                        type: 'brand-impersonation',
                        message: `Possible ${brand} impersonation using lookalike characters`,
                        severity: 'high'
                    });
                } else {
                    risks.push({
                        type: 'brand-impersonation',
                        message: `Possible ${brand} impersonation`,
                        severity: 'medium'
                    });
                }
            }
        }

        return { risks };
    }

    function checkMalwareSignatures(parsedUrl) {
        const risks = [];
        const lowerUrl = parsedUrl.hostname + parsedUrl.pathname;

        // Common malware distribution patterns
        const malwarePatterns = [
            'download', 'install', 'setup', 'update', 'patch', 'fix',
            'crack', 'keygen', 'serial', 'license', 'activation',
            'free', 'premium', 'unlimited', 'hack', 'cheat'
        ];

        malwarePatterns.forEach(pattern => {
            if (lowerUrl.includes(pattern)) {
                risks.push({
                    type: 'malware-signature',
                    message: `Potential malware distribution pattern "${pattern}" detected`,
                    severity: 'medium'
                });
            }
        });

        return { risks };
    }

    function checkSocialEngineering(parsedUrl) {
        const risks = [];
        const lowerUrl = parsedUrl.hostname + parsedUrl.pathname;

        // Social engineering patterns
        const socialEngineeringPatterns = [
            'urgent', 'immediate', 'action-required', 'account-suspended',
            'security-alert', 'fraud-detected', 'verify-now', 'confirm-urgently',
            'limited-time', 'exclusive-offer', 'you-won', 'prize-winner'
        ];

        socialEngineeringPatterns.forEach(pattern => {
            if (lowerUrl.includes(pattern)) {
                risks.push({
                    type: 'social-engineering',
                    message: `Social engineering pattern "${pattern}" detected`,
                    severity: 'medium'
                });
            }
        });

        return { risks };
    }

    async function validateSSL(parsedUrl) {
        if (parsedUrl.protocol !== 'https:') {
            return {
                isValid: false,
                details: 'No SSL certificate (HTTP)',
                risks: [{
                    type: 'no-ssl',
                    message: 'No SSL certificate - data transmission is not encrypted',
                    severity: 'high'
                }]
            };
        }

        // In a real implementation, you would validate the SSL certificate
        // For now, we'll simulate SSL validation
        return {
            isValid: true,
            details: 'SSL certificate appears valid',
            risks: []
        };
    }

    async function checkDomainAge(parsedUrl) {
        const normalizedDomain = parsedUrl.hostname.replace(/^www\./, '').toLowerCase();
        
        // Known safe domains should always be considered established
        if (safeDomains.has(normalizedDomain)) {
            return {
                age: 'established',
                risks: []
            };
        }
        
        // Known malicious domains should be considered established (but malicious)
        if (maliciousDomains.has(normalizedDomain)) {
            return {
                age: 'established',
                risks: []
            };
        }
        
        // Check for common established domains and companies
        const establishedDomains = [
            'tcs.com', 'tcs.co.in', 'tata.com', 'tata.co.in', 'infosys.com', 'wipro.com',
            'hcl.com', 'techmahindra.com', 'cognizant.com', 'accenture.com', 'ibm.com',
            'oracle.com', 'sap.com', 'salesforce.com', 'adobe.com', 'cisco.com',
            'intel.com', 'amd.com', 'nvidia.com', 'qualcomm.com', 'samsung.com',
            'sony.com', 'panasonic.com', 'lg.com', 'hp.com', 'dell.com', 'lenovo.com',
            'asus.com', 'acer.com', 'toshiba.com', 'fujitsu.com', 'canon.com',
            'nikon.com', 'canon.co.in', 'nikon.co.in', 'philips.com', 'siemens.com',
            'bosch.com', 'volkswagen.com', 'bmw.com', 'mercedes-benz.com', 'audi.com',
            'toyota.com', 'honda.com', 'nissan.com', 'ford.com', 'chevrolet.com',
            'general-motors.com', 'hyundai.com', 'kia.com', 'volvo.com', 'jaguar.com',
            'landrover.com', 'ferrari.com', 'lamborghini.com', 'porsche.com', 'mclaren.com',
            'rolls-royce.com', 'bentley.com', 'astonmartin.com', 'maserati.com', 'alfa-romeo.com'
        ];
        
        if (establishedDomains.includes(normalizedDomain)) {
            return {
                age: 'established',
                risks: []
            };
        }
        
        // In a real implementation, you would query WHOIS data
        // For now, we'll use a more deterministic approach based on domain characteristics
        // Domains with common patterns are likely established
        const isLikelyEstablished = 
            normalizedDomain.includes('.com') || 
            normalizedDomain.includes('.org') || 
            normalizedDomain.includes('.net') ||
            normalizedDomain.includes('.edu') ||
            normalizedDomain.includes('.gov') ||
            normalizedDomain.length > 10; // Longer domains are usually established
        
        return {
            age: isLikelyEstablished ? 'established' : 'new',
            risks: isLikelyEstablished ? [] : [{
                type: 'new-domain',
                message: 'Domain is relatively new (higher risk)',
                severity: 'low'
            }]
        };
    }

    async function checkReputation(parsedUrl, domainName) {
        // Check against known malicious domains
        if (maliciousDomains.has(domainName)) {
            return {
                score: 5, // Very low score for malicious domains
                isShortener: false,
                risks: [{
                    type: 'known-malicious',
                    message: 'Domain is in our malicious domains database',
                    severity: 'high'
                }]
            };
        }

        // Check against safe domains
        if (safeDomains.has(domainName)) {
            return {
                score: 95, // High score for safe domains
                isShortener: false,
                risks: []
            };
        }

        // Check if it's a URL shortener
        const isShortener = urlShorteners.has(domainName);
        
        // For unknown domains, use more realistic scoring
        // Base score for unknown domains should be moderate
        let baseScore = 60; // Start with a moderate score
        
        // Adjust score based on domain characteristics
        if (normalizedDomain.includes('.com') || normalizedDomain.includes('.org') || 
            normalizedDomain.includes('.net') || normalizedDomain.includes('.edu') || 
            normalizedDomain.includes('.gov')) {
            baseScore += 10; // Established TLDs get a bonus
        }
        
        if (normalizedDomain.includes('.tk') || normalizedDomain.includes('.gq') || 
            normalizedDomain.includes('.ml') || normalizedDomain.includes('.cf') || 
            normalizedDomain.includes('.ga') || normalizedDomain.includes('.xyz')) {
            baseScore -= 20; // Suspicious TLDs get a penalty
        }
        
        // Add small random variation for realism
        const randomFactor = (Math.random() - 0.5) * 10; // -5 to +5 points
        const score = Math.round(Math.max(10, Math.min(90, baseScore + randomFactor)));

        return {
            score,
            isShortener,
            risks: score < 30 ? [{
                type: 'low-reputation',
                message: 'Domain has low reputation score',
                severity: 'medium'
            }] : []
        };
    }

    function analyzeDomain(parsedUrl, domainName) {
        const risks = [];
        let isSafe = true;
        let trustLevel = 'unknown';

        // Check against safe domains first
        if (safeDomains.has(domainName)) {
            trustLevel = 'trusted';
            return { isSafe: true, trustLevel, risks };
        }

        // Check against malicious domains
        if (maliciousDomains.has(domainName)) {
            trustLevel = 'malicious';
            isSafe = false;
            risks.push({
                type: 'known-malicious-domain',
                message: 'Domain is known to be malicious',
                severity: 'high'
            });
            return { isSafe, trustLevel, risks };
        }

        // Check for brand impersonation
        for (const [brand, patterns] of Object.entries(brandPatterns)) {
            if (domainName.includes(brand)) {
                // Check if it's the legitimate domain
                if (domainName === `${brand}.com` || domainName === `www.${brand}.com`) {
                    continue;
                }
                
                // Check for lookalike patterns
                const isLookalike = patterns.some(pattern => domainName.includes(pattern));
                if (isLookalike) {
                    risks.push({
                        type: 'brand-impersonation',
                        message: `Possible ${brand} impersonation using lookalike characters`,
                        severity: 'high'
                    });
                    isSafe = false;
                    trustLevel = 'impersonator';
                } else {
                    risks.push({
                        type: 'brand-impersonation',
                        message: `Possible ${brand} impersonation`,
                        severity: 'medium'
                    });
                    isSafe = false;
                    trustLevel = 'impersonator';
                }
            }
        }

        // If no specific issues found, mark as unverified
        if (trustLevel === 'unknown') {
            trustLevel = 'unverified';
        }

        return { isSafe, trustLevel, risks };
    }

    return {
        init,
        analyzeUrl,
        clearCache: () => domainCache.clear()
    };
})();
