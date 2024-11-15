const express = require('express');
const axios = require('axios');
const bodyParser = require('body-parser');
const cors = require('cors');
const dotenv = require('dotenv');
const fs = require('fs');
const path = require('path');
const { parse } = require('tldts'); // Import tldts for domain parsing

dotenv.config();

const app = express();
const port = 3000; // You can change the port if needed

app.use(bodyParser.json());
app.use(cors());

// Load the Tranco list into a Set for quick lookup
const trancoDomains = new Set();

function loadTrancoList() {
    try {
        const trancoListPath = path.join(__dirname, 'tranco-list.csv');
        const data = fs.readFileSync(trancoListPath, 'utf8');
        const lines = data.split('\n');
        for (const line of lines) {
            const parts = line.trim().split(',');
            if (parts.length >= 2) {
                const domainInList = parts[1].toLowerCase();
                trancoDomains.add(domainInList);
            }
        }
        console.log(`Loaded ${trancoDomains.size} domains from Tranco list.`);
    } catch (error) {
        console.error('Error reading Tranco list:', error);
    }
}

// Load the Tranco list when the server starts
loadTrancoList();

// Endpoint to detect phishing
app.post('/api/detect-phishing', async (req, res) => {
    const emailContent = req.body.content;
    if (!emailContent) {
        return res.status(400).json({ error: 'Email content is required' });
    }

    try {
        const { isPhishing, reasons } = await detectPhishing(emailContent);
        res.json({ isPhishing, reasons });
    } catch (error) {
        console.error('Error in detect-phishing:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Phishing detection logic
async function detectPhishing(emailContent) {
    let isPhishing = false;
    let reasons = [];

    const content = emailContent.toLowerCase();

    // High Priority: Urgent or Threatening Language
    if (hasUrgentLanguage(content)) {
        isPhishing = true;
        reasons.push('Uses urgent or threatening language');
    }

    // High Priority: Requests for Personal Information
    if (requestsPersonalInfo(content)) {
        isPhishing = true;
        reasons.push('Requests personal or sensitive information');
    }

    // High Priority: Contains Public IP Address
    if (containsPublicIP(emailContent)) {
        isPhishing = true;
        reasons.push('Contains a public IP address, which is suspicious');
    }

    // Medium Priority: Suspicious URLs
    const urlRegex = /https?:\/\/[^\s]+/gi;
    const links = emailContent.match(urlRegex);
    if (links) {
        for (const link of links) {
            const { isSafe, reason } = await checkDomainReputation(link);
            if (!isSafe) {
                isPhishing = true;
                reasons.push(`Link "${link}" is suspicious: ${reason}`);
            }
        }
    }

    // Low Priority: Grammar and Spelling
    const poorGrammar = await hasPoorGrammar(emailContent);
    if (poorGrammar) {
        isPhishing = true;
        reasons.push('Contains poor grammar or spelling mistakes');
    }

    return { isPhishing, reasons };
}

// Function to check for urgent or threatening language
function hasUrgentLanguage(content) {
    const urgentPhrases = [
        'act now', 'urgent', 'immediately', 'asap', 'limited time', 'action required',
        'account suspended', 'verify your account', 'click here', 'update your information',
        'password expires', 'unauthorized login attempt'
    ];
    return urgentPhrases.some(phrase => new RegExp(`\\b${phrase}\\b`, 'i').test(content));
}

// Function to check for requests for personal information
function requestsPersonalInfo(content) {
    const personalInfoPhrases = [
        'password', 'social security number', 'credit card', 'bank account',
        'login details', 'personal information', 'ssn', 'dob', 'date of birth'
    ];
    return personalInfoPhrases.some(phrase => new RegExp(`\\b${phrase}\\b`, 'i').test(content));
}

// Function to check if the content contains a public IP address
function containsPublicIP(content) {
    const ipRegex = /(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)/g;
    const ips = content.match(ipRegex);
    if (ips) {
        for (const ip of ips) {
            if (isPublicIP(ip)) {
                return true;
            }
        }
    }
    return false;
}

// Function to check if an IP address is public
function isPublicIP(ip) {
    const parts = ip.split('.').map(Number);
    // Private IP ranges
    const privateRanges = [
        [10, 0, 0, 0, 10, 255, 255, 255],       // 10.0.0.0 - 10.255.255.255
        [172, 16, 0, 0, 172, 31, 255, 255],     // 172.16.0.0 - 172.31.255.255
        [192, 168, 0, 0, 192, 168, 255, 255],   // 192.168.0.0 - 192.168.255.255
        [127, 0, 0, 0, 127, 255, 255, 255],     // 127.0.0.0 - 127.255.255.255 (Loopback)
        [169, 254, 0, 0, 169, 254, 255, 255]    // 169.254.0.0 - 169.254.255.255 (Link-local)
    ];

    for (const range of privateRanges) {
        const [start1, start2, start3, start4, end1, end2, end3, end4] = range;
        if (
            parts[0] >= start1 && parts[0] <= end1 &&
            parts[1] >= start2 && parts[1] <= end2 &&
            parts[2] >= start3 && parts[2] <= end3 &&
            parts[3] >= start4 && parts[3] <= end4
        ) {
            return false; // It's a private IP, so not public
        }
    }
    return true; // It's a public IP
}

// Function to check domain reputation using APIs
async function checkDomainReputation(url) {
    const domain = extractDomain(url);
    if (!domain) {
        return { isSafe: false, reason: 'Invalid URL' };
    }

    // Check Google Safe Browsing API
    const isUnsafe = await checkGoogleSafeBrowsing(url);
    if (isUnsafe) {
        return { isSafe: false, reason: 'URL is flagged by Google Safe Browsing' };
    }

    // Check if domain is among top sites (e.g., using Tranco list)
    const isTopSite = await checkTrancoList(domain);
    if (!isTopSite) {
        return { isSafe: false, reason: 'Domain is not among top reputable sites' };
    }

    return { isSafe: true };
}

// Function to extract the main domain from a URL using tldts
function extractDomain(url) {
    try {
        const hostname = new URL(url).hostname;
        const parsed = parse(hostname);
        if (parsed.domain) {
            return parsed.domain;
        } else {
            return hostname;
        }
    } catch (e) {
        return null;
    }
}

// Function to check Google Safe Browsing API
async function checkGoogleSafeBrowsing(url) {
    const apiKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY;
    if (!apiKey) {
        console.warn('Google Safe Browsing API key is not set. Skipping URL safety check.');
        return false; // Assume safe if API key is not set
    }

    const apiUrl = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`;

    const data = {
        client: {
            clientId: "phishing-email-checker",
            clientVersion: "1.0.0"
        },
        threatInfo: {
            threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            platformTypes: ["ANY_PLATFORM"],
            threatEntryTypes: ["URL"],
            threatEntries: [
                { url: url }
            ]
        }
    };

    try {
        const response = await axios.post(apiUrl, data);
        if (response.data && response.data.matches && response.data.matches.length > 0) {
            return true; // URL is unsafe
        } else {
            return false; // URL is safe
        }
    } catch (error) {
        console.error('Error checking Google Safe Browsing API:', error);
        // In case of error, consider URL as unsafe
        return true;
    }
}

// Function to check if domain is among top sites using Tranco list
async function checkTrancoList(domain) {
    if (trancoDomains.size === 0) {
        console.warn('Tranco domains not loaded.');
        return false;
    }
    return trancoDomains.has(domain.toLowerCase());
}

// Function to check for poor grammar and spelling using LanguageTool API
async function hasPoorGrammar(content) {
    const apiUrl = 'https://api.languagetool.org/v2/check';
    try {
        const response = await axios.post(apiUrl, null, {
            params: {
                text: content,
                language: 'en-US'
            }
        });
        const matches = response.data.matches;
        // If there are many matches, consider it as poor grammar
        return matches.length > 5;
    } catch (error) {
        console.error('Error checking LanguageTool API:', error);
        // In case of error, do not consider it as poor grammar
        return false;
    }
}

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
