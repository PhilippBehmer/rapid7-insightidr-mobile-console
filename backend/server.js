const express = require('express');
const cors = require('cors');
const axios = require('axios');
const bodyParser = require('body-parser');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { AsyncLocalStorage } = require('async_hooks');

const app = express();
const PORT = process.env.PORT || 3000;
const SENSITIVE_FILE_MODE = 0o600;
const SUPPORTED_REGIONS = new Set(['us', 'eu', 'ca', 'ap']);
const FRONTEND_DIST_DIR = path.resolve(__dirname, '..', 'frontend', 'dist');

app.use(cors());
app.use(bodyParser.json());

const DEFAULT_CONFIG = Object.freeze({ apiKey: '', platformUserApiKey: '', region: 'us' });
const CONFIG_FILE = process.env.POCKETSOC_CONFIG_FILE
    ? path.resolve(process.env.POCKETSOC_CONFIG_FILE)
    : path.join(__dirname, 'local', 'config.json');
const SESSION_COOKIE_NAME = 'pocketsoc_session';
const SESSION_TTL_MS = 90 * 24 * 60 * 60 * 1000;
const SESSION_SECRET_FILE = process.env.POCKETSOC_SESSION_SECRET_FILE
    ? path.resolve(process.env.POCKETSOC_SESSION_SECRET_FILE)
    : path.join(path.dirname(CONFIG_FILE), 'session-secret.hex');
const requestContextStorage = new AsyncLocalStorage();
const sessionRuntimeCaches = new Map();
let mitreCatalogCache = null;
let mitreCatalogPromise = null;
const DEFAULT_UPSTREAM_TIMEOUT_MS = 20000;
const ATTACHMENT_UPLOAD_TIMEOUT_MS = 120000;
const ATTACHMENT_UPLOAD_MAX_BYTES = (() => {
    const parsed = Number(process.env.POCKETSOC_ATTACHMENT_MAX_BYTES);
    return Number.isFinite(parsed) && parsed > 0
        ? Math.floor(parsed)
        : 50 * 1000 * 1000;
})();
const ANALYST_DIRECTORY_TTL_MS = 5 * 60 * 1000;
const LOGSET_NAME_TTL_MS = 30 * 60 * 1000;
const EVENT_SOURCE_DIRECTORY_TTL_MS = 30 * 60 * 1000;
const MITRE_CATALOG_TTL_MS = 12 * 60 * 60 * 1000;
const MITRE_ATTACK_DATA_URL = 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json';
const HEALTH_METRIC_STALE_THRESHOLD_MS = 24 * 60 * 60 * 1000;
const HEALTH_METRIC_REQUEST_TIMEOUT_MS = 12000;
const HEALTH_METRIC_RESOURCE_TYPES = [
    { key: 'agent', label: 'Endpoint Agents' },
    { key: 'collectors', label: 'Collectors' },
    { key: 'network_sensors', label: 'Network Sensors' },
    { key: 'orchestrator', label: 'Orchestrator' },
    { key: 'data_exporters', label: 'Data Exporters' },
    { key: 'scan_engines', label: 'Scan Engines' },
    { key: 'honeypots', label: 'Honeypots' },
    { key: 'event_sources', label: 'Event Sources' }
];
const HEALTH_METRIC_HEALTHY_STATES = new Set(['RUNNING', 'ONLINE', 'ACTIVE', 'HEALTHY', 'OK', 'MONITORING']);

let initialSessionConfigTemplate = { ...DEFAULT_CONFIG };

function ensureDirectoryForFile(filePath) {
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
}

function applySensitiveFilePermissions(filePath) {
    if (!fs.existsSync(filePath)) return;
    fs.chmodSync(filePath, SENSITIVE_FILE_MODE);
}

function writeSensitiveFile(filePath, contents) {
    ensureDirectoryForFile(filePath);
    fs.writeFileSync(filePath, contents, {
        encoding: 'utf8',
        mode: SENSITIVE_FILE_MODE
    });
    applySensitiveFilePermissions(filePath);
}

function isSupportedRegion(region) {
    return SUPPORTED_REGIONS.has(String(region || '').trim().toLowerCase());
}

function normalizeSessionConfig(candidate = {}) {
    const requestedRegion = typeof candidate?.region === 'string'
        ? candidate.region.trim().toLowerCase()
        : '';
    const region = isSupportedRegion(requestedRegion)
        ? requestedRegion
        : DEFAULT_CONFIG.region;
    const apiKey = typeof candidate?.apiKey === 'string'
        ? candidate.apiKey.trim()
        : '';
    const platformUserApiKey = typeof candidate?.platformUserApiKey === 'string'
        ? candidate.platformUserApiKey.trim()
        : '';

    return {
        apiKey,
        platformUserApiKey,
        region
    };
}

function loadSessionEncryptionKey() {
    const configuredSecret = String(process.env.POCKETSOC_SESSION_SECRET || '').trim();
    if (configuredSecret) {
        return crypto.createHash('sha256').update(configuredSecret).digest();
    }

    ensureDirectoryForFile(SESSION_SECRET_FILE);

    let secretValue = '';
    if (fs.existsSync(SESSION_SECRET_FILE)) {
        secretValue = String(fs.readFileSync(SESSION_SECRET_FILE, 'utf8')).trim();
        applySensitiveFilePermissions(SESSION_SECRET_FILE);
    } else {
        secretValue = crypto.randomBytes(32).toString('hex');
        writeSensitiveFile(SESSION_SECRET_FILE, `${secretValue}\n`);
    }

    return crypto.createHash('sha256').update(secretValue).digest();
}

const SESSION_ENCRYPTION_KEY = loadSessionEncryptionKey();

function encryptSessionConfig(config) {
    const normalizedConfig = normalizeSessionConfig(config);
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', SESSION_ENCRYPTION_KEY, iv);
    const encrypted = Buffer.concat([
        cipher.update(JSON.stringify(normalizedConfig), 'utf8'),
        cipher.final()
    ]);

    return {
        iv: iv.toString('base64'),
        ciphertext: encrypted.toString('base64'),
        authTag: cipher.getAuthTag().toString('base64')
    };
}

function decryptSessionConfig(payload = {}) {
    const decipher = crypto.createDecipheriv(
        'aes-256-gcm',
        SESSION_ENCRYPTION_KEY,
        Buffer.from(String(payload.iv || ''), 'base64')
    );
    decipher.setAuthTag(Buffer.from(String(payload.authTag || ''), 'base64'));

    const decrypted = Buffer.concat([
        decipher.update(Buffer.from(String(payload.ciphertext || ''), 'base64')),
        decipher.final()
    ]);

    return normalizeSessionConfig(JSON.parse(decrypted.toString('utf8')));
}

function buildEmptySessionCacheBucket() {
    return {
        analystDirectoryCache: null,
        analystDirectoryPromise: null,
        logsetNameCache: new Map(),
        logsetNamePromises: new Map(),
        eventSourceDirectoryCache: null,
        eventSourceDirectoryPromise: null
    };
}

function getCurrentContext() {
    return requestContextStorage.getStore() || {
        sessionId: 'anonymous',
        config: { ...initialSessionConfigTemplate }
    };
}

function getCurrentSessionId() {
    return getCurrentContext().sessionId;
}

function getCurrentConfig() {
    return getCurrentContext().config || { ...DEFAULT_CONFIG };
}

function setCurrentConfig(config) {
    const normalizedConfig = normalizeSessionConfig(config);
    const currentContext = requestContextStorage.getStore();

    if (currentContext) {
        currentContext.config = normalizedConfig;
    }

    return normalizedConfig;
}

function persistCurrentSessionConfig(config, now = Date.now()) {
    const normalizedConfig = setCurrentConfig(config);
    persistSessionConfig(getCurrentSessionId(), normalizedConfig, now);
    return normalizedConfig;
}

function hasConfiguredApiKey() {
    return Boolean(getCurrentConfig().apiKey);
}

function getSessionCacheBucket(sessionId = getCurrentSessionId()) {
    if (!sessionRuntimeCaches.has(sessionId)) {
        sessionRuntimeCaches.set(sessionId, buildEmptySessionCacheBucket());
    }

    return sessionRuntimeCaches.get(sessionId);
}

function clearSessionRuntimeCaches(sessionId) {
    sessionRuntimeCaches.delete(sessionId);
}

// Load stored session data if it exists. Legacy single-config files are treated as
// a source of the default region only; API keys are no longer shared globally.
function loadSessionStore() {
    if (!fs.existsSync(CONFIG_FILE)) {
        return {
            version: 2,
            sessions: {}
        };
    }

    try {
        applySensitiveFilePermissions(CONFIG_FILE);
        const data = fs.readFileSync(CONFIG_FILE, 'utf8');
        const parsed = JSON.parse(data);

        if (parsed && parsed.version === 2 && parsed.sessions && typeof parsed.sessions === 'object') {
            return {
                version: 2,
                sessions: parsed.sessions
            };
        }

        if (parsed && typeof parsed === 'object') {
            const legacyConfig = normalizeSessionConfig(parsed);
            initialSessionConfigTemplate = {
                ...DEFAULT_CONFIG,
                region: legacyConfig.region
            };
        }
    } catch (err) {
        console.error('Failed to read session config file', err);
    }

    return {
        version: 2,
        sessions: {}
    };
}

let sessionStore = loadSessionStore();

function saveSessionStore() {
    writeSensitiveFile(CONFIG_FILE, JSON.stringify(sessionStore));
}

function generateSessionId() {
    return crypto.randomBytes(32).toString('hex');
}

function createStoredSessionEntry(config, now = Date.now()) {
    return {
        createdAt: now,
        lastSeenAt: now,
        expiresAt: now + SESSION_TTL_MS,
        encryptedConfig: encryptSessionConfig(config)
    };
}

function persistSessionConfig(sessionId, config, now = Date.now()) {
    const existingEntry = sessionStore.sessions[sessionId];
    sessionStore.sessions[sessionId] = {
        ...createStoredSessionEntry(config, now),
        createdAt: existingEntry?.createdAt || now
    };
    saveSessionStore();
}

function touchSession(sessionId, now = Date.now()) {
    const entry = sessionStore.sessions[sessionId];
    if (!entry) return;

    entry.lastSeenAt = now;
    entry.expiresAt = now + SESSION_TTL_MS;
    saveSessionStore();
}

function pruneExpiredSessions(now = Date.now()) {
    let didChange = false;

    Object.entries(sessionStore.sessions || {}).forEach(([sessionId, entry]) => {
        if (Number(entry?.expiresAt) > now) return;

        delete sessionStore.sessions[sessionId];
        clearSessionRuntimeCaches(sessionId);
        didChange = true;
    });

    if (didChange) {
        saveSessionStore();
    }
}

function parseCookieHeader(headerValue = '') {
    return String(headerValue || '')
        .split(';')
        .map(part => part.trim())
        .filter(Boolean)
        .reduce((cookies, part) => {
            const separatorIndex = part.indexOf('=');
            if (separatorIndex === -1) return cookies;

            const key = part.slice(0, separatorIndex).trim();
            const value = part.slice(separatorIndex + 1).trim();
            if (!key) return cookies;

            try {
                cookies[key] = decodeURIComponent(value);
            } catch (error) {
                cookies[key] = value;
            }
            return cookies;
        }, {});
}

function requestUsesHttps(req) {
    const forwardedProto = String(req.headers['x-forwarded-proto'] || '')
        .split(',')[0]
        .trim()
        .toLowerCase();

    return Boolean(req.secure || forwardedProto === 'https');
}

function setSessionCookie(req, res, sessionId, expiresAt) {
    const attributes = [
        `${SESSION_COOKIE_NAME}=${encodeURIComponent(sessionId)}`,
        'Path=/',
        'HttpOnly',
        'SameSite=Lax',
        `Max-Age=${Math.max(0, Math.floor((expiresAt - Date.now()) / 1000))}`,
        `Expires=${new Date(expiresAt).toUTCString()}`
    ];

    if (requestUsesHttps(req) || String(process.env.POCKETSOC_FORCE_SECURE_COOKIE || '').toLowerCase() === 'true') {
        attributes.push('Secure');
    }

    res.setHeader('Set-Cookie', attributes.join('; '));
}

function resolveSessionContext(req, res, next) {
    const now = Date.now();
    pruneExpiredSessions(now);

    const cookies = parseCookieHeader(req.headers.cookie);
    let sessionId = String(cookies[SESSION_COOKIE_NAME] || '').trim();
    let sessionConfig = { ...initialSessionConfigTemplate };
    let sessionEntry = sessionId ? sessionStore.sessions?.[sessionId] : null;

    if (sessionEntry) {
        try {
            sessionConfig = decryptSessionConfig(sessionEntry.encryptedConfig);
            touchSession(sessionId, now);
            sessionEntry = sessionStore.sessions?.[sessionId] || sessionEntry;
        } catch (error) {
            delete sessionStore.sessions[sessionId];
            clearSessionRuntimeCaches(sessionId);
            saveSessionStore();
            sessionEntry = null;
            sessionId = '';
        }
    }

    if (!sessionEntry) {
        sessionId = generateSessionId();
        sessionEntry = createStoredSessionEntry(sessionConfig, now);
        sessionStore.sessions[sessionId] = sessionEntry;
        saveSessionStore();
    }

    setSessionCookie(req, res, sessionId, sessionEntry.expiresAt);
    req.idrSession = {
        id: sessionId,
        config: sessionConfig
    };

    requestContextStorage.run({
        sessionId,
        config: sessionConfig
    }, next);
}

function clearAnalystDirectoryCache(sessionId = getCurrentSessionId()) {
    const cacheBucket = getSessionCacheBucket(sessionId);
    cacheBucket.analystDirectoryCache = null;
    cacheBucket.analystDirectoryPromise = null;
}

function clearLogsetNameCache(sessionId = getCurrentSessionId()) {
    const cacheBucket = getSessionCacheBucket(sessionId);
    cacheBucket.logsetNameCache = new Map();
    cacheBucket.logsetNamePromises = new Map();
}

function clearEventSourceDirectoryCache(sessionId = getCurrentSessionId()) {
    const cacheBucket = getSessionCacheBucket(sessionId);
    cacheBucket.eventSourceDirectoryCache = null;
    cacheBucket.eventSourceDirectoryPromise = null;
}

function normalizeMitreCode(code) {
    return String(code || '').trim().toUpperCase();
}

function getMitreCategory(code) {
    const normalizedCode = normalizeMitreCode(code);
    if (/^TA\d{4}$/.test(normalizedCode)) return 'tactic';
    if (/^T\d{4}(?:\.\d{3})?$/.test(normalizedCode)) return 'technique';
    return null;
}

function buildMitreUrl(code) {
    const normalizedCode = normalizeMitreCode(code);
    if (/^TA\d{4}$/.test(normalizedCode)) {
        return `https://attack.mitre.org/tactics/${normalizedCode}/`;
    }

    if (/^T\d{4}\.\d{3}$/.test(normalizedCode)) {
        const [techniqueCode, subtechniqueCode] = normalizedCode.split('.');
        return `https://attack.mitre.org/techniques/${techniqueCode}/${subtechniqueCode}/`;
    }

    if (/^T\d{4}$/.test(normalizedCode)) {
        return `https://attack.mitre.org/techniques/${normalizedCode}/`;
    }

    return `https://attack.mitre.org/search/?q=${encodeURIComponent(normalizedCode)}`;
}

async function loadMitreCatalog() {
    if (mitreCatalogCache && Date.now() - mitreCatalogCache.loadedAt < MITRE_CATALOG_TTL_MS) {
        return mitreCatalogCache.catalog;
    }

    if (!mitreCatalogPromise) {
        mitreCatalogPromise = axios.get(MITRE_ATTACK_DATA_URL, {
            headers: {
                'Accept': 'application/json'
            },
            timeout: 20000
        }).then(response => {
            const objects = Array.isArray(response.data?.objects) ? response.data.objects : [];
            const catalog = new Map();

            objects.forEach(item => {
                if (!item || item.revoked || item.x_mitre_deprecated) return;
                if (item.type !== 'x-mitre-tactic' && item.type !== 'attack-pattern') return;

                const externalReference = (item.external_references || []).find(reference => (
                    reference?.source_name === 'mitre-attack' && reference.external_id
                ));

                if (!externalReference?.external_id || !item.name) return;

                const code = normalizeMitreCode(externalReference.external_id);
                const category = item.type === 'x-mitre-tactic' ? 'tactic' : 'technique';

                catalog.set(code, {
                    code,
                    name: item.name,
                    category,
                    url: externalReference.url || buildMitreUrl(code)
                });
            });

            mitreCatalogCache = {
                loadedAt: Date.now(),
                catalog
            };

            return catalog;
        }).finally(() => {
            mitreCatalogPromise = null;
        });
    }

    return mitreCatalogPromise;
}

async function loadEventSourceDirectory() {
    const cacheBucket = getSessionCacheBucket();

    if (
        cacheBucket.eventSourceDirectoryCache
        && Date.now() - cacheBucket.eventSourceDirectoryCache.loadedAt < EVENT_SOURCE_DIRECTORY_TTL_MS
    ) {
        return cacheBucket.eventSourceDirectoryCache.directory;
    }

    if (!cacheBucket.eventSourceDirectoryPromise) {
        cacheBucket.eventSourceDirectoryPromise = (async () => {
            const client = getApiClient();
            const directory = new Map();
            const pageSize = 100;
            let index = 0;
            let totalPages = 1;

            while (index < totalPages) {
                const response = await client.get('/idr/v1/health-metrics', {
                    params: {
                        resourceTypes: 'event_sources',
                        size: pageSize,
                        index
                    }
                });
                const payload = response.data || {};
                const eventSources = Array.isArray(payload.data) ? payload.data : [];

                eventSources.forEach(eventSource => {
                    const rrn = String(eventSource?.rrn || '').trim();
                    if (!rrn) return;

                    directory.set(rrn, {
                        rrn,
                        name: getDisplayName(eventSource?.name) || rrn,
                        id: eventSource?.id || null,
                        state: eventSource?.state || null
                    });
                });

                const metadata = payload.metadata || {};
                if (Number.isInteger(metadata.total_pages) && metadata.total_pages > 0) {
                    totalPages = metadata.total_pages;
                } else if (eventSources.length < pageSize) {
                    totalPages = index + 1;
                } else {
                    totalPages = index + 2;
                }

                index += 1;
            }

            cacheBucket.eventSourceDirectoryCache = {
                loadedAt: Date.now(),
                directory
            };

            return directory;
        })().finally(() => {
            cacheBucket.eventSourceDirectoryPromise = null;
        });
    }

    return cacheBucket.eventSourceDirectoryPromise;
}

async function loadEventSourcesForLogs(logIds = []) {
    const uniqueLogIds = Array.from(new Set((logIds || []).map(id => String(id || '').trim()).filter(Boolean)));
    if (uniqueLogIds.length === 0) {
        return new Map();
    }

    const client = getLogSearchApiClient();
    const matches = new Map();

    await Promise.all(uniqueLogIds.map(async logId => {
        const response = await client.get(`/management/logs/${encodeURIComponent(logId)}/event-sources`);
        const eventSources = Array.isArray(response.data?.['event-sources'])
            ? response.data['event-sources']
            : [];

        eventSources.forEach(eventSource => {
            const rrn = String(eventSource?.rrn || '').trim();
            if (!rrn) return;

            matches.set(rrn, {
                rrn,
                id: eventSource?.id || null,
                name: getDisplayName(eventSource?.name) || rrn,
                state: eventSource?.state || null,
                type: eventSource?.type || null,
                source: 'log'
            });
        });
    }));

    return matches;
}

// Ensure base URL based on region
function getBaseUrl() {
    const region = getCurrentConfig().region || 'us';
    return `https://${region}.api.insight.rapid7.com`;
}

function getLogSearchBaseUrl() {
    const region = getCurrentConfig().region || 'us';
    return `https://${region}.rest.logs.insight.rapid7.com`;
}

// Axios instance factory to inject the current API key dynamically
function getApiClient() {
    const currentConfig = getCurrentConfig();
    return axios.create({
        baseURL: getBaseUrl(),
        timeout: DEFAULT_UPSTREAM_TIMEOUT_MS,
        headers: {
            'X-Api-Key': currentConfig.apiKey,
            'Content-Type': 'application/json',
            'Accept': 'application/json',
        }
    });
}

function getPlatformUserApiClient() {
    const currentConfig = getCurrentConfig();
    const platformKey = currentConfig.platformUserApiKey || currentConfig.apiKey;
    return axios.create({
        baseURL: getBaseUrl(),
        timeout: DEFAULT_UPSTREAM_TIMEOUT_MS,
        headers: {
            'X-Api-Key': platformKey,
            'Accept': 'application/json',
        }
    });
}

function getLogSearchApiClient() {
    const currentConfig = getCurrentConfig();
    return axios.create({
        baseURL: getLogSearchBaseUrl(),
        timeout: DEFAULT_UPSTREAM_TIMEOUT_MS,
        headers: {
            'X-Api-Key': currentConfig.apiKey,
            'Accept': 'application/json',
        }
    });
}

function getAlertSearchWindow(rangeKey = '7d') {
    const now = new Date();
    const endTime = now.toISOString();
    const start = new Date(now);

    switch (rangeKey) {
        case 'today':
            start.setUTCHours(0, 0, 0, 0);
            break;
        case '28d':
            start.setUTCDate(start.getUTCDate() - 28);
            break;
        case '3m':
            start.setUTCMonth(start.getUTCMonth() - 3);
            break;
        case '6m':
            start.setUTCMonth(start.getUTCMonth() - 6);
            break;
        case '7d':
        default:
            start.setUTCDate(start.getUTCDate() - 7);
            break;
    }

    return {
        startTime: start.toISOString(),
        endTime
    };
}

function isWithinTimeRange(isoValue, startTime, endTime) {
    const timestamp = Date.parse(isoValue || '');
    if (Number.isNaN(timestamp)) return false;

    return timestamp >= Date.parse(startTime) && timestamp <= Date.parse(endTime);
}

function getErrorStatus(error) {
    if (error?.code === 'ERR_FR_MAX_BODY_LENGTH_EXCEEDED') {
        return 413;
    }

    if (error?.code === 'ECONNABORTED') {
        return 504;
    }

    return error.response ? error.response.status : 500;
}

function getErrorBody(error) {
    if (error?.code === 'ERR_FR_MAX_BODY_LENGTH_EXCEEDED') {
        return {
            error: `Attachment upload exceeds the ${ATTACHMENT_UPLOAD_MAX_BYTES}-byte limit`
        };
    }

    if (error?.code === 'ECONNABORTED') {
        return {
            error: 'Upstream request timed out'
        };
    }

    return error.response?.data || { error: error.message };
}

async function readStreamErrorBody(stream, maxBytes = 32768) {
    return new Promise(resolve => {
        if (!stream || typeof stream.on !== 'function') {
            resolve('');
            return;
        }

        const chunks = [];
        let totalBytes = 0;
        let settled = false;

        const settle = value => {
            if (settled) return;
            settled = true;
            resolve(value);
        };

        stream.on('data', chunk => {
            if (settled) return;

            const bufferChunk = Buffer.isBuffer(chunk)
                ? chunk
                : Buffer.from(String(chunk));
            const remainingBytes = maxBytes - totalBytes;

            if (remainingBytes > 0) {
                chunks.push(bufferChunk.subarray(0, remainingBytes));
            }

            totalBytes += bufferChunk.length;

            if (totalBytes >= maxBytes) {
                if (typeof stream.destroy === 'function') {
                    stream.destroy();
                }
                settle(Buffer.concat(chunks).toString('utf8').trim());
            }
        });

        stream.on('end', () => {
            settle(Buffer.concat(chunks).toString('utf8').trim());
        });

        stream.on('error', () => {
            settle(Buffer.concat(chunks).toString('utf8').trim());
        });
    });
}

async function getAttachmentDownloadErrorBody(error) {
    if (error?.code === 'ECONNABORTED') {
        return getErrorBody(error);
    }

    const responseData = error?.response?.data;
    if (!responseData || typeof responseData === 'string' || Buffer.isBuffer(responseData)) {
        return getErrorBody(error);
    }

    if (typeof responseData.on === 'function' && typeof responseData.pipe === 'function') {
        const bodyText = await readStreamErrorBody(responseData);
        if (!bodyText) {
            return {
                error: error.message || 'Attachment download failed'
            };
        }

        try {
            return JSON.parse(bodyText);
        } catch (parseError) {
            return { error: bodyText };
        }
    }

    return getErrorBody(error);
}

function getDisplayName(value) {
    if (typeof value === 'string') return value.trim();
    if (value && typeof value === 'object') {
        return String(value.name || value.value || value.text || '').trim();
    }
    return '';
}

app.use(resolveSessionContext);

function normalizeActor(actor = {}) {
    const name = actor.display_name || actor.name || actor.label || actor.id || actor.rrn || 'Unknown Actor';
    return {
        rrn: actor.rrn || null,
        id: actor.id || actor.rrn || name,
        type: actor.type || actor.actor_type || 'UNKNOWN',
        name,
        domain: actor.domain || actor.domain_name || '',
        source: actor.source || actor.alert_source || '',
        raw: actor
    };
}

function isRrn(value) {
    return String(value || '').trim().startsWith('rrn:');
}

async function settleWithConcurrency(items, mapper, concurrency = 6) {
    const normalizedItems = Array.isArray(items) ? items : [];
    const settledResults = new Array(normalizedItems.length);
    let nextIndex = 0;

    async function worker() {
        while (nextIndex < normalizedItems.length) {
            const currentIndex = nextIndex;
            nextIndex += 1;

            try {
                settledResults[currentIndex] = {
                    status: 'fulfilled',
                    value: await mapper(normalizedItems[currentIndex], currentIndex)
                };
            } catch (error) {
                settledResults[currentIndex] = {
                    status: 'rejected',
                    reason: error
                };
            }
        }
    }

    const workerCount = Math.min(Math.max(1, concurrency), normalizedItems.length || 1);
    await Promise.all(Array.from({ length: workerCount }, () => worker()));
    return settledResults;
}

function getAlertRrn(alert = {}) {
    const candidates = [
        alert?.rrn,
        alert?.alert_rrn,
        alert?.alertRrn,
        alert?.alert?.rrn,
        alert?.id
    ];

    for (const candidate of candidates) {
        const normalizedValue = String(candidate || '').trim();
        if (isRrn(normalizedValue)) {
            return normalizedValue;
        }
    }

    return '';
}

function extractActorItems(payload) {
    if (Array.isArray(payload)) return payload;
    if (Array.isArray(payload?.data)) return payload.data;
    if (Array.isArray(payload?.actors)) return payload.actors;
    return [];
}

async function fetchAlert(client, alertRrn) {
    const response = await client.get(`/idr/at/alerts/${encodeURIComponent(alertRrn)}`);
    return response.data || {};
}

async function fetchAlertActors(client, alertRrn) {
    const pageSize = 100;
    let index = 0;
    let isLastIndex = false;
    const allActors = [];

    while (!isLastIndex) {
        const response = await client.get(`/idr/at/alerts/${encodeURIComponent(alertRrn)}/actors`, {
            params: {
                index,
                size: pageSize
            }
        });
        const payload = response.data || {};
        allActors.push(...extractActorItems(payload));

        const metadata = payload.metadata || {};
        if (typeof metadata.is_last_index === 'boolean') {
            isLastIndex = metadata.is_last_index;
        } else if (Array.isArray(payload.actors) || Array.isArray(payload.data)) {
            isLastIndex = true;
        } else {
            isLastIndex = true;
        }

        index += 1;
    }

    return allActors;
}

async function fetchAlertsByRrns(client, rrns, options = {}) {
    const {
        batchSize = 100,
        fieldIds = []
    } = options;
    const uniqueRrns = Array.from(new Set((rrns || []).filter(Boolean)));
    const allAlerts = [];

    for (let startIndex = 0; startIndex < uniqueRrns.length; startIndex += batchSize) {
        const requestBody = {
            rrns: uniqueRrns.slice(startIndex, startIndex + batchSize)
        };

        if (fieldIds.length > 0) {
            requestBody.field_ids = fieldIds;
        }

        const response = await client.post('/idr/at/alerts/ops/rrns', requestBody);
        const alerts = Array.isArray(response.data?.alerts) ? response.data.alerts : [];
        allAlerts.push(...alerts);
    }

    return allAlerts;
}

async function fetchInvestigationAlerts(client, id) {
    const pageSize = 100;
    let pageIndex = 0;
    let totalPages = 1;
    const allAlerts = [];

    while (pageIndex < totalPages) {
        const response = await client.get(`/idr/v2/investigations/${encodeURIComponent(id)}/alerts`, {
            params: {
                index: pageIndex,
                size: pageSize
            }
        });

        const payload = response.data || {};
        const alerts = Array.isArray(payload.data) ? payload.data : [];
        allAlerts.push(...alerts);

        totalPages = payload.metadata?.total_pages || 1;
        pageIndex += 1;
    }

    return allAlerts;
}

async function fetchInvestigation(client, id) {
    const response = await client.get(`/idr/v2/investigations/${encodeURIComponent(id)}`);
    return response.data || {};
}

async function resolveInvestigationApiId(client, id) {
    const normalizedId = String(id || '').trim();
    if (!normalizedId) {
        return normalizedId;
    }

    if (!normalizedId.startsWith('rrn:')) {
        return normalizedId;
    }

    const investigation = await fetchInvestigation(client, normalizedId);
    return String(investigation?.id || normalizedId).trim();
}

async function resolveInvestigationTarget(client, id) {
    const normalizedId = String(id || '').trim();
    if (normalizedId.startsWith('rrn:')) {
        return normalizedId;
    }

    const investigation = await fetchInvestigation(client, normalizedId);
    return investigation?.rrn || normalizedId;
}

async function fetchInvestigationActors(client, id) {
    const response = await client.get(`/idr/v2/investigations/${encodeURIComponent(id)}/actors`);
    return extractActorItems(response.data || {});
}

async function fetchPagedCollection(client, urlPath, options = {}) {
    const {
        params = {},
        pageSize = 100,
        dataKey = 'data'
    } = options;
    let index = 0;
    let totalPages = 1;
    const allItems = [];
    let latestMetadata = null;

    while (index < totalPages) {
        const response = await client.get(urlPath, {
            params: {
                ...params,
                index,
                size: pageSize
            }
        });
        const payload = response.data || {};
        const pageItems = Array.isArray(payload?.[dataKey]) ? payload[dataKey] : [];

        allItems.push(...pageItems);
        latestMetadata = payload.metadata || latestMetadata;

        if (Number.isInteger(payload.metadata?.total_pages) && payload.metadata.total_pages > 0) {
            totalPages = payload.metadata.total_pages;
        } else if (pageItems.length < pageSize) {
            totalPages = index + 1;
        } else {
            totalPages = index + 2;
        }

        index += 1;
    }

    return {
        data: allItems,
        metadata: latestMetadata || {
            index: 0,
            size: pageSize,
            total_pages: allItems.length > 0 ? 1 : 0,
            total_data: allItems.length
        }
    };
}

async function fetchCommentsByTarget(client, target) {
    return fetchPagedCollection(client, '/idr/v1/comments', {
        params: { target },
        dataKey: 'data'
    });
}

async function fetchAttachmentsByTarget(client, target) {
    return fetchPagedCollection(client, '/idr/v1/attachments', {
        params: { target },
        dataKey: 'data'
    });
}

async function fetchAlertProcessTrees(client, alertRrn, options = {}) {
    const {
        index = 0,
        size = 20,
        forceRefresh = false,
        branch = null
    } = options;
    const params = {
        index,
        size
    };

    if (forceRefresh) {
        params.force_refresh = true;
    }

    if (branch !== null && branch !== undefined && branch !== '') {
        params.branch = branch;
    }

    const response = await client.post(
        `/idr/at/alerts/${encodeURIComponent(alertRrn)}/process_trees/latest`,
        null,
        { params }
    );

    return response.data || {};
}

function mergeInvestigationAlert(alertSummary = {}, triageAlert = {}) {
    const detectionRule = alertSummary.detection_rule_rrn || {};
    const triageRule = triageAlert.rule || {};
    const alertRrn = getAlertRrn(triageAlert) || getAlertRrn(alertSummary) || null;
    const rule = {
        ...triageRule,
        rrn: triageRule.rrn || detectionRule.rule_rrn || detectionRule.rrn || null,
        name: triageRule.name || detectionRule.rule_name || detectionRule.name || null,
        version_rrn: triageRule.version_rrn || detectionRule.rule_rrn || detectionRule.version_rrn || null
    };

    return {
        ...alertSummary,
        ...triageAlert,
        id: triageAlert.id || alertSummary.id || alertRrn,
        rrn: alertRrn,
        created_at: triageAlert.created_at || alertSummary.created_time || null,
        created_time: alertSummary.created_time || triageAlert.created_at || null,
        alerted_at: triageAlert.alerted_at || alertSummary.latest_event_time || null,
        external_source: triageAlert.external_source || alertSummary.alert_source || null,
        alert_source: alertSummary.alert_source || triageAlert.external_source || null,
        alert_type: alertSummary.alert_type || triageAlert.type || null,
        alert_type_description: alertSummary.alert_type_description || triageAlert.type || null,
        rule,
        detection_rule_rrn: Object.keys(detectionRule).length > 0
            ? detectionRule
            : (rule?.rrn ? { rule_rrn: rule.rrn, rule_name: rule.name || null } : null)
    };
}

// ==========================================
// CONFIG ENDPOINTS
// ==========================================

app.get('/api/config', (req, res) => {
    const currentConfig = getCurrentConfig();
    // Only return whether we have a key and the region, don't return the raw key for security
    res.json({
        hasApiKey: !!currentConfig.apiKey,
        hasPlatformUserApiKey: !!currentConfig.platformUserApiKey,
        region: currentConfig.region
    });
});

app.post('/api/config', (req, res) => {
    const { apiKey, platformUserApiKey, region } = req.body;
    const currentConfig = getCurrentConfig();
    const nextConfig = { ...currentConfig };
    const normalizedApiKey = typeof apiKey === 'string' ? apiKey.trim() : '';
    const normalizedPlatformUserApiKey = typeof platformUserApiKey === 'string'
        ? platformUserApiKey.trim()
        : '';

    if (region !== undefined && !isSupportedRegion(region)) {
        return res.status(400).json({
            error: `Region must be one of: ${Array.from(SUPPORTED_REGIONS).join(', ')}`
        });
    }

    if (apiKey !== undefined && normalizedApiKey !== '') nextConfig.apiKey = normalizedApiKey;
    if (platformUserApiKey !== undefined && normalizedPlatformUserApiKey !== '') {
        nextConfig.platformUserApiKey = normalizedPlatformUserApiKey;
    }
    if (region !== undefined) nextConfig.region = region;

    persistCurrentSessionConfig(nextConfig);
    clearAnalystDirectoryCache();
    clearLogsetNameCache();
    clearEventSourceDirectoryCache();
    res.json({ success: true });
});

app.post('/api/config/clear', (req, res) => {
    const currentConfig = getCurrentConfig();
    persistCurrentSessionConfig({
        ...currentConfig,
        apiKey: '',
        platformUserApiKey: ''
    });
    clearAnalystDirectoryCache();
    clearLogsetNameCache();
    clearEventSourceDirectoryCache();
    res.json({ success: true });
});

app.get('/api/health-metrics/overview', async (req, res) => {
    if (!hasConfiguredApiKey()) {
        return res.status(401).json({ error: 'API key not configured' });
    }

    try {
        const orgId = typeof req.query.orgId === 'string' && req.query.orgId.trim()
            ? req.query.orgId.trim()
            : null;
        const overview = await buildHealthMetricsOverview({ orgId });
        res.json({ data: overview });
    } catch (error) {
        console.error('Error loading health metrics overview:', error.response?.data || error.message);
        const status = error.response ? error.response.status : 500;
        res.status(status).json(error.response?.data || { error: error.message });
    }
});

// ==========================================
// PROXY ENDPOINTS (Simulated / Proxied)
// ==========================================

// Helper to handle proxy requests
async function proxyRequest(req, res, method, urlPath, data = null) {
    if (!hasConfiguredApiKey()) {
        return res.status(401).json({ error: 'API key not configured' });
    }

    try {
        const client = getApiClient();
        const configAxios = {
            method,
            url: urlPath,
            ...(data && { data }),
            params: req.query
        };

        const response = await client(configAxios);
        res.json(response.data);
    } catch (error) {
        console.error(`Error proxying ${method} ${urlPath}:`, error.response?.data || error.message);
        const status = error.response ? error.response.status : 500;
        res.status(status).json(error.response?.data || { error: error.message });
    }
}

// --- ALERTS ---

async function fetchPagedSearchResults(client, urlPath, options = {}) {
    const {
        sortField = null,
        search = [],
        maxItems = 250,
        pageSize = 200
    } = options;
    let pageIndex = 0;
    let totalPages = 1;
    const allResults = [];
    const requestBody = {
        search,
        sort: sortField ? [{ field: sortField, order: 'ASC' }] : []
    };

    while (pageIndex < totalPages && allResults.length < maxItems) {
        const response = await client.post(urlPath, requestBody, {
            params: {
                index: pageIndex,
                size: Math.min(pageSize, maxItems - allResults.length || pageSize)
            }
        });
        const payload = response.data || {};
        const items = Array.isArray(payload.data) ? payload.data : [];
        allResults.push(...items);
        totalPages = payload.metadata?.total_pages || 1;
        pageIndex += 1;
    }

    return allResults;
}

function toFiniteNumber(value) {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : null;
}

function buildHealthMetricStateMap(items = []) {
    return items.reduce((counts, item) => {
        const state = String(item?.state || '').trim().toUpperCase();
        if (!state) return counts;

        counts[state] = (counts[state] || 0) + 1;
        return counts;
    }, {});
}

function formatHealthMetricStateCounts(counts = {}) {
    return Object.entries(counts)
        .map(([state, count]) => ({ state, count }))
        .sort((a, b) => {
            if (b.count !== a.count) return b.count - a.count;
            return a.state.localeCompare(b.state);
        });
}

function normalizeHealthMetricIssue(issue) {
    if (!issue) return null;

    if (typeof issue === 'string') {
        const normalized = issue.trim();
        return normalized || null;
    }

    if (typeof issue === 'object') {
        const severity = String(issue.severity || '').trim();
        const message = String(issue.message || issue.error || '').trim();
        const eventTime = String(issue.event_time || issue.last_seen || '').trim();
        const parts = [];

        if (severity) parts.push(severity);
        if (message) parts.push(message);
        if (eventTime) parts.push(`at ${eventTime}`);

        return parts.join(': ') || null;
    }

    const normalized = String(issue).trim();
    return normalized || null;
}

function getHealthMetricAttentionReasons(item, now = Date.now()) {
    const reasons = [];
    const normalizedState = String(item?.state || '').trim().toUpperCase();
    const issue = normalizeHealthMetricIssue(item?.issue);
    const lastActive = String(item?.last_active || '').trim();
    const dropRate = toFiniteNumber(item?.drop_rate);
    const eventSourcesUsed = toFiniteNumber(item?.event_sources_used);
    const maxEventSources = toFiniteNumber(item?.max_event_sources);

    if (normalizedState && !HEALTH_METRIC_HEALTHY_STATES.has(normalizedState)) {
        reasons.push(`state:${normalizedState}`);
    }

    if (issue) {
        reasons.push(`issue:${issue}`);
    }

    if (lastActive) {
        const lastActiveMs = Date.parse(lastActive);
        if (!Number.isNaN(lastActiveMs) && now - lastActiveMs > HEALTH_METRIC_STALE_THRESHOLD_MS) {
            reasons.push('last_active:stale');
        }
    }

    if (dropRate !== null && dropRate > 0) {
        reasons.push('drop_rate:nonzero');
    }

    if (
        eventSourcesUsed !== null
        && maxEventSources !== null
        && maxEventSources > 0
        && eventSourcesUsed / maxEventSources >= 0.85
    ) {
        reasons.push('capacity:high');
    }

    return reasons;
}

function normalizeHealthMetricItem(resourceType, item, now = Date.now()) {
    const name = getDisplayName(item?.name) || item?.id || item?.rrn || resourceType;
    const issue = normalizeHealthMetricIssue(item?.issue);
    const eventSourcesUsed = toFiniteNumber(item?.event_sources_used);
    const maxEventSources = toFiniteNumber(item?.max_event_sources);
    const memoryUsed = toFiniteNumber(item?.memory_used);
    const maxMemory = toFiniteNumber(item?.max_memory);
    const storageUsed = toFiniteNumber(item?.storage_used);
    const maxStorage = toFiniteNumber(item?.max_storage);
    const dropRate = toFiniteNumber(item?.drop_rate);
    const percentCpuUsed = toFiniteNumber(item?.percent_cpu_used);
    const cpuUsed = toFiniteNumber(item?.cpu_used);
    const attentionReasons = getHealthMetricAttentionReasons(item, now);

    return {
        name,
        id: item?.id || null,
        rrn: item?.rrn || null,
        state: item?.state || null,
        last_active: item?.last_active || null,
        issue,
        health_status: Array.isArray(item?.health_status) ? item.health_status : [],
        event_sources_used: eventSourcesUsed,
        max_event_sources: maxEventSources,
        capacity_pct: eventSourcesUsed !== null && maxEventSources
            ? Number(((eventSourcesUsed / maxEventSources) * 100).toFixed(1))
            : null,
        memory_used: memoryUsed,
        max_memory: maxMemory,
        memory_pct: memoryUsed !== null && maxMemory
            ? Number(((memoryUsed / maxMemory) * 100).toFixed(1))
            : null,
        storage_used: storageUsed,
        max_storage: maxStorage,
        storage_pct: storageUsed !== null && maxStorage
            ? Number(((storageUsed / maxStorage) * 100).toFixed(1))
            : null,
        percent_cpu_used: percentCpuUsed,
        cpu_used: cpuUsed,
        drop_rate: dropRate,
        attention: attentionReasons.length > 0,
        attention_reasons: attentionReasons
    };
}

async function fetchAllHealthMetricsForType(client, resourceType, options = {}) {
    const {
        orgId = null
    } = options;
    const pageSize = 100;
    const allItems = [];
    let index = 0;
    let totalPages = 1;
    let lastMetadata = {};

    while (index < totalPages) {
        const response = await client.get('/idr/v1/health-metrics', {
            timeout: HEALTH_METRIC_REQUEST_TIMEOUT_MS,
            params: {
                resourceTypes: resourceType,
                size: pageSize,
                index,
                ...(orgId ? { orgId } : {})
            }
        });
        const payload = response.data || {};
        const items = Array.isArray(payload.data) ? payload.data : [];
        const metadata = payload.metadata || {};
        const unlicensedTypes = Array.isArray(metadata.unlicensed_resource_types) ? metadata.unlicensed_resource_types : [];
        const failedToLoad = Array.isArray(metadata.failed_to_load) ? metadata.failed_to_load : [];
        const totalData = Number(metadata.total_data);

        lastMetadata = metadata;
        allItems.push(...items);

        if (
            unlicensedTypes.includes(String(resourceType || '').toUpperCase())
            || failedToLoad.includes(String(resourceType || '').toUpperCase())
        ) {
            break;
        }

        // Some Health Metrics families report inflated page counts even when there is no data.
        // Stop immediately on empty result sets so the overview stays responsive.
        if ((Number.isFinite(totalData) && totalData === 0) || items.length === 0) {
            break;
        }

        if (Number.isInteger(metadata.total_pages) && metadata.total_pages > 0) {
            totalPages = metadata.total_pages;
        } else if (items.length < pageSize) {
            totalPages = index + 1;
        } else {
            totalPages = index + 2;
        }

        index += 1;
    }

    return {
        items: allItems,
        metadata: lastMetadata
    };
}

function summarizeHealthMetricResource(resourceDefinition, payload, now = Date.now()) {
    const {
        key,
        label
    } = resourceDefinition;
    const metadata = payload?.metadata || {};
    const unlicensedTypes = Array.isArray(metadata.unlicensed_resource_types) ? metadata.unlicensed_resource_types : [];
    const failedToLoad = Array.isArray(metadata.failed_to_load) ? metadata.failed_to_load : [];
    const licensed = !unlicensedTypes.includes(String(key || '').toUpperCase());

    if (key === 'agent') {
        const summary = Array.isArray(payload?.items) && payload.items[0] ? payload.items[0] : {};
        const online = Math.max(0, parseInt(summary.online, 10) || 0);
        const offline = Math.max(0, parseInt(summary.offline, 10) || 0);
        const stale = Math.max(0, parseInt(summary.stale, 10) || 0);
        const total = Math.max(online + offline + stale, parseInt(summary.total, 10) || 0);

        return {
            key,
            label,
            licensed,
            available: total > 0,
            metadata,
            totals: {
                total,
                healthy: online,
                attention: offline + stale
            },
            states: [
                { state: 'ONLINE', count: online },
                { state: 'OFFLINE', count: offline },
                { state: 'STALE', count: stale }
            ].filter(entry => entry.count > 0),
            items: [],
            summary: {
                online,
                offline,
                stale,
                total
            },
            errors: failedToLoad
        };
    }

    const normalizedItems = Array.isArray(payload?.items)
        ? payload.items.map(item => normalizeHealthMetricItem(key, item, now))
        : [];
    const attentionItems = normalizedItems.filter(item => item.attention);
    const stateCounts = buildHealthMetricStateMap(payload?.items || []);

    const derived = {
        collectors: null,
        system: null
    };

    if (key === 'collectors') {
        const totalUsed = normalizedItems.reduce((sum, item) => sum + (item.event_sources_used || 0), 0);
        const totalCapacity = normalizedItems.reduce((sum, item) => sum + (item.max_event_sources || 0), 0);

        derived.collectors = {
            total_event_sources_used: totalUsed,
            total_max_event_sources: totalCapacity,
            fleet_capacity_pct: totalCapacity > 0
                ? Number(((totalUsed / totalCapacity) * 100).toFixed(1))
                : null
        };
    }

    if (['collectors', 'network_sensors', 'orchestrator', 'honeypots', 'scan_engines'].includes(key)) {
        const cpuSamples = normalizedItems
            .map(item => item.percent_cpu_used !== null ? item.percent_cpu_used : item.cpu_used)
            .filter(value => value !== null);
        const memorySamples = normalizedItems
            .map(item => item.memory_pct)
            .filter(value => value !== null);
        const storageSamples = normalizedItems
            .map(item => item.storage_pct)
            .filter(value => value !== null);

        derived.system = {
            avg_cpu_pct: cpuSamples.length
                ? Number((cpuSamples.reduce((sum, value) => sum + value, 0) / cpuSamples.length).toFixed(1))
                : null,
            avg_memory_pct: memorySamples.length
                ? Number((memorySamples.reduce((sum, value) => sum + value, 0) / memorySamples.length).toFixed(1))
                : null,
            avg_storage_pct: storageSamples.length
                ? Number((storageSamples.reduce((sum, value) => sum + value, 0) / storageSamples.length).toFixed(1))
                : null
        };
    }

    return {
        key,
        label,
        licensed,
        available: normalizedItems.length > 0,
        metadata,
        totals: {
            total: normalizedItems.length,
            healthy: Math.max(normalizedItems.length - attentionItems.length, 0),
            attention: attentionItems.length
        },
        states: formatHealthMetricStateCounts(stateCounts),
        items: normalizedItems,
        summary: null,
        errors: failedToLoad,
        derived
    };
}

async function buildHealthMetricsOverview(options = {}) {
    const {
        orgId = null
    } = options;
    const client = getApiClient();
    const now = Date.now();
    const resources = await Promise.all(HEALTH_METRIC_RESOURCE_TYPES.map(async resourceDefinition => {
        try {
            const payload = await fetchAllHealthMetricsForType(client, resourceDefinition.key, { orgId });
            return summarizeHealthMetricResource(resourceDefinition, payload, now);
        } catch (error) {
            const message = error.response?.data?.message
                || error.response?.data?.error
                || error.message
                || 'Unknown health metric error';

            return {
                key: resourceDefinition.key,
                label: resourceDefinition.label,
                licensed: true,
                available: false,
                metadata: {},
                totals: {
                    total: 0,
                    healthy: 0,
                    attention: 0
                },
                states: [],
                items: [],
                summary: null,
                errors: [message]
            };
        }
    }));

    const getAttentionPriority = item => {
        const issue = String(item?.issue || '').trim().toUpperCase();
        const reasons = Array.isArray(item?.attention_reasons) ? item.attention_reasons : [];

        if (
            /^(CRITICAL|ERROR|FAILED|UNHEALTHY)\b/.test(issue)
            || reasons.some(reason => /^state:(CRITICAL|ERROR|FAILED|UNHEALTHY)\b/.test(String(reason || '').toUpperCase()))
        ) {
            return 0;
        }

        if (
            /^(WARNING|DEGRADED)\b/.test(issue)
            || reasons.some(reason => /^state:(WARNING|DEGRADED)\b/.test(String(reason || '').toUpperCase()))
        ) {
            return 1;
        }

        if (reasons.includes('drop_rate:nonzero') || reasons.includes('capacity:high')) {
            return 2;
        }

        if (reasons.includes('last_active:stale')) {
            return 3;
        }

        return 4;
    };

    const attentionItems = resources
        .flatMap(resource => (resource.items || [])
            .filter(item => item.attention)
            .map(item => ({
                resource_type: resource.key,
                resource_label: resource.label,
                name: item.name,
                state: item.state,
                last_active: item.last_active,
                issue: item.issue,
                drop_rate: item.drop_rate,
                attention_reasons: item.attention_reasons
            })))
        .sort((a, b) => {
            const priorityDelta = getAttentionPriority(a) - getAttentionPriority(b);
            if (priorityDelta !== 0) return priorityDelta;

            const aLastActive = Date.parse(a.last_active || '') || 0;
            const bLastActive = Date.parse(b.last_active || '') || 0;
            return aLastActive - bLastActive;
        });
    const monitoredResources = resources.reduce((sum, resource) => {
        if (resource.key === 'agent') return sum;
        return sum + (resource.totals?.total || 0);
    }, 0);
    const agentSummary = resources.find(resource => resource.key === 'agent')?.summary || {
        online: 0,
        offline: 0,
        stale: 0,
        total: 0
    };

    return {
        updated_at: new Date(now).toISOString(),
        overview: {
            monitored_resources: monitoredResources,
            healthy_resources: resources.reduce((sum, resource) => sum + (resource.totals?.healthy || 0), 0),
            attention_resources: resources.reduce((sum, resource) => sum + (resource.totals?.attention || 0), 0),
            reporting_families: resources.filter(resource => resource.available || resource.key === 'agent').length,
            licensed_families: resources.filter(resource => resource.licensed).length,
            unlicensed_families: resources.filter(resource => !resource.licensed).length,
            empty_families: resources.filter(resource => resource.licensed && !resource.available && resource.key !== 'agent').length,
            agent_summary: agentSummary
        },
        attention_items: attentionItems,
        resources
    };
}

function isLikelyEmail(value) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(value || '').trim());
}

function normalizeAnalystAccount(account) {
    const accountName = String(account?.name || '').trim();
    if (!accountName) return null;

    const email = isLikelyEmail(accountName) ? accountName : null;
    const stableKey = account?.user?.rrn || account?.rrn || email || accountName.toLowerCase();
    return {
        rrn: account?.user?.rrn || account?.rrn || accountName,
        name: account.user?.name || accountName,
        domain: account.domain || '',
        email,
        accountRrn: account.rrn || null,
        value: email || accountName,
        key: stableKey,
        label: email
            ? `${account.user?.name || email} (${email})`
            : `${account.user?.name || accountName} (${accountName})`
    };
}

function normalizePlatformUser(user) {
    const email = String(user?.email || '').trim();
    if (!email) return null;

    const fullName = [user.first_name, user.last_name].filter(Boolean).join(' ').trim();
    return {
        rrn: user.id || email,
        id: user.id || null,
        name: fullName || email,
        email,
        value: email,
        label: fullName ? `${fullName} (${email})` : email,
        platformAdmin: Boolean(user.platform_admin),
        status: user.status || ''
    };
}

app.get('/api/analysts', async (req, res) => {
    if (!hasConfiguredApiKey()) {
        return res.status(401).json({ error: 'API key not configured' });
    }

    try {
        const cacheBucket = getSessionCacheBucket();
        const rawQuery = typeof req.query.q === 'string' ? req.query.q.trim() : '';
        const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 15, 1), 25);
        const cacheKey = `${rawQuery.toLowerCase()}::${limit}`;
        const now = Date.now();

        if (
            cacheBucket.analystDirectoryCache?.key === cacheKey
            && now - cacheBucket.analystDirectoryCache.loadedAt < ANALYST_DIRECTORY_TTL_MS
        ) {
            return res.json({
                data: cacheBucket.analystDirectoryCache.data,
                metadata: {
                    total_items: cacheBucket.analystDirectoryCache.data.length,
                    cached: true,
                    query: rawQuery
                }
            });
        }

        if (cacheBucket.analystDirectoryPromise?.key === cacheKey) {
            const cachedInFlight = await cacheBucket.analystDirectoryPromise.promise;
            return res.json({
                data: cachedInFlight,
                metadata: {
                    total_items: cachedInFlight.length,
                    cached: true,
                    query: rawQuery
                }
            });
        }

        const promise = (async () => {
            const client = getPlatformUserApiClient();
            const response = await client.get('/account/api/1/users', {
                params: {
                    email: rawQuery || undefined
                }
            });

            const users = Array.isArray(response.data) ? response.data : [];
            return users
                .map(normalizePlatformUser)
                .filter(Boolean)
                .sort((a, b) => a.label.localeCompare(b.label))
                .slice(0, limit);
        })();

        cacheBucket.analystDirectoryPromise = {
            key: cacheKey,
            promise
        };

        const analysts = await promise;
        cacheBucket.analystDirectoryCache = {
            key: cacheKey,
            loadedAt: Date.now(),
            data: analysts
        };
        cacheBucket.analystDirectoryPromise = null;

        res.json({
            data: analysts,
            metadata: {
                total_items: analysts.length,
                cached: false,
                query: rawQuery
            }
        });
    } catch (error) {
        getSessionCacheBucket().analystDirectoryPromise = null;
        console.error('Error fetching analyst directory:', error.response?.data || error.message);
        const statusCode = error.response ? error.response.status : 500;
        const errorBody = error.response?.data || { error: error.message };

        if (statusCode === 403) {
            return res.status(403).json({
                error: 'Platform User API key is not authorized for user lookup',
                details: errorBody
            });
        }

        res.status(statusCode).json(errorBody);
    }
});

app.get('/api/logsets/resolve', async (req, res) => {
    if (!hasConfiguredApiKey()) {
        return res.status(401).json({ error: 'API key not configured' });
    }

    try {
        const cacheBucket = getSessionCacheBucket();
        const rawIds = Array.isArray(req.query.ids)
            ? req.query.ids
            : (typeof req.query.ids === 'string' ? req.query.ids.split(',') : []);
        const ids = Array.from(new Set(rawIds.map(id => String(id || '').trim()).filter(Boolean))).slice(0, 25);

        if (ids.length === 0) {
            return res.json({
                data: [],
                metadata: {
                    total_items: 0,
                    resolved_items: 0
                }
            });
        }

        const client = getLogSearchApiClient();
        const now = Date.now();
        const failures = [];

        const data = await Promise.all(ids.map(async id => {
            const cached = cacheBucket.logsetNameCache.get(id);
            if (cached && now - cached.loadedAt < LOGSET_NAME_TTL_MS) {
                return {
                    id,
                    name: cached.name,
                    cached: true
                };
            }

            if (!cacheBucket.logsetNamePromises.has(id)) {
                const promise = client.get(`/management/logsets/${encodeURIComponent(id)}`)
                    .then(response => {
                        const payload = response.data?.logset || response.data || {};
                        const name = getDisplayName(payload.name) || id;
                        cacheBucket.logsetNameCache.set(id, {
                            name,
                            loadedAt: Date.now()
                        });
                        return name;
                    })
                    .finally(() => {
                        cacheBucket.logsetNamePromises.delete(id);
                    });

                cacheBucket.logsetNamePromises.set(id, promise);
            }

            try {
                const name = await cacheBucket.logsetNamePromises.get(id);
                return {
                    id,
                    name,
                    cached: false
                };
            } catch (error) {
                failures.push({
                    id,
                    status: getErrorStatus(error)
                });
                return {
                    id,
                    name: id,
                    cached: false,
                    unresolved: true
                };
            }
        }));

        res.json({
            data,
            metadata: {
                total_items: ids.length,
                resolved_items: data.filter(item => !item.unresolved).length
            },
            failures
        });
    } catch (error) {
        console.error('Error resolving logset names:', error.response?.data || error.message);
        res.status(getErrorStatus(error)).json(getErrorBody(error));
    }
});

app.get('/api/event-sources/resolve', async (req, res) => {
    if (!hasConfiguredApiKey()) {
        return res.status(401).json({ error: 'API key not configured' });
    }

    try {
        const cacheBucket = getSessionCacheBucket();
        const rawRrns = Array.isArray(req.query.rrn)
            ? req.query.rrn
            : (typeof req.query.rrn === 'string' ? req.query.rrn.split(',') : []);
        const rawLogIds = Array.isArray(req.query.log_id)
            ? req.query.log_id
            : (typeof req.query.log_id === 'string' ? req.query.log_id.split(',') : []);
        const rrns = Array.from(new Set(rawRrns.map(rrn => String(rrn || '').trim()).filter(Boolean))).slice(0, 50);
        const logIds = Array.from(new Set(rawLogIds.map(logId => String(logId || '').trim()).filter(Boolean))).slice(0, 25);

        if (rrns.length === 0) {
            return res.json({
                data: [],
                metadata: {
                    total_items: 0,
                    resolved_items: 0
                }
            });
        }

        const directory = await loadEventSourceDirectory();
        const unresolvedRrns = rrns.filter(rrn => !directory.get(rrn));

        if (unresolvedRrns.length > 0 && logIds.length > 0) {
            const logMatches = await loadEventSourcesForLogs(logIds);
            logMatches.forEach((value, rrn) => {
                directory.set(rrn, value);
            });
        }

        const data = rrns.map(rrn => {
            const match = directory.get(rrn);

            if (!match) {
                return {
                    rrn,
                    name: rrn,
                    unresolved: true
                };
            }

            return {
                rrn,
                id: match.id,
                name: match.name,
                state: match.state,
                type: match.type || null,
                source: match.source || 'inventory',
                cached: true
            };
        });

        res.json({
            data,
            metadata: {
                total_items: rrns.length,
                resolved_items: data.filter(item => !item.unresolved).length,
                directory_size: directory.size,
                loaded_at: cacheBucket.eventSourceDirectoryCache?.loadedAt
                    ? new Date(cacheBucket.eventSourceDirectoryCache.loadedAt).toISOString()
                    : null
            }
        });
    } catch (error) {
        console.error('Error resolving event source names:', error.response?.data || error.message);
        res.status(getErrorStatus(error)).json(getErrorBody(error));
    }
});

app.get('/api/mitre/resolve', async (req, res) => {
    try {
        const rawCodes = Array.isArray(req.query.code)
            ? req.query.code
            : (typeof req.query.code === 'string' ? req.query.code.split(',') : []);
        const codes = Array.from(new Set(rawCodes.map(normalizeMitreCode).filter(Boolean))).slice(0, 50);

        if (codes.length === 0) {
            return res.json({
                data: [],
                metadata: {
                    total_items: 0,
                    resolved_items: 0
                }
            });
        }

        const catalog = await loadMitreCatalog();
        const data = codes.map(code => {
            const catalogEntry = catalog.get(code);
            const category = catalogEntry?.category || getMitreCategory(code);
            const name = catalogEntry?.name || null;

            return {
                code,
                category,
                name,
                label: name ? `${name} (${code})` : code,
                url: catalogEntry?.url || buildMitreUrl(code),
                resolved: Boolean(catalogEntry)
            };
        });

        res.json({
            data,
            metadata: {
                total_items: codes.length,
                resolved_items: data.filter(item => item.resolved).length,
                loaded_at: mitreCatalogCache?.loadedAt
                    ? new Date(mitreCatalogCache.loadedAt).toISOString()
                    : null
            }
        });
    } catch (error) {
        console.error('Error resolving MITRE ATT&CK codes:', error.response?.data || error.message);
        res.status(getErrorStatus(error)).json(getErrorBody(error));
    }
});

app.get('/api/alerts', async (req, res) => {
    if (!hasConfiguredApiKey()) {
        return res.status(401).json({ error: 'API key not configured' });
    }

    try {
        const client = getApiClient();
        const range = typeof req.query.range === 'string' ? req.query.range : '7d';
        const { startTime, endTime } = getAlertSearchWindow(range);
        const searchSize = 100;
        const hydrateBatchSize = 100;
        const searchBody = {
            search: {
                start_time: startTime,
                end_time: endTime,
                terms: []
            }
        };
        const rrns = [];
        let totalItems = 0;
        let index = 0;
        let isLastIndex = false;

        // The search endpoint reliably pages RRNs across indexes. Full alert payloads
        // on deeper indexes are inconsistent, so hydrate RRNs in a second step.
        while (!isLastIndex) {
            const response = await client.post(
                '/idr/at/alerts/ops/search',
                searchBody,
                {
                    params: {
                        index,
                        size: searchSize,
                        rrns_only: true
                    }
                }
            );
            const payload = response.data || {};
            const batchRrns = Array.isArray(payload.rrns) ? payload.rrns : [];
            const metadata = payload.metadata || {};

            rrns.push(...batchRrns);
            totalItems = metadata.total_items || totalItems;
            isLastIndex = Boolean(metadata.is_last_index);
            index += 1;
        }

        const allAlerts = await fetchAlertsByRrns(client, rrns, {
            batchSize: hydrateBatchSize
        });

        const alertsByRrn = new Map(allAlerts.map(alert => [alert.rrn, alert]));
        const orderedAlerts = rrns
            .map(rrn => alertsByRrn.get(rrn))
            .filter(Boolean);

        res.json({
            data: orderedAlerts,
            metadata: {
                range,
                start_time: startTime,
                end_time: endTime,
                total_items: totalItems || orderedAlerts.length
            }
        });
    } catch (error) {
        console.error('Error fetching alerts:', error.response?.data || error.message);
        res.status(getErrorStatus(error)).json(getErrorBody(error));
    }
});

app.patch('/api/alerts/:id', async (req, res) => {
    if (!hasConfiguredApiKey()) {
        return res.status(401).json({ error: 'API key not configured' });
    }

    const id = req.params.id;
    const updateBody = {};

    ['status', 'priority', 'disposition', 'assignee_id', 'investigation_rrn'].forEach(field => {
        if (req.body?.[field] !== undefined && req.body[field] !== null && req.body[field] !== '') {
            updateBody[field] = { value: req.body[field] };
        }
    });

    if (Object.keys(updateBody).length === 0) {
        return res.status(400).json({ error: 'No alert fields provided to update' });
    }

    try {
        const client = getApiClient();
        const response = await client.patch(`/idr/at/alerts/${encodeURIComponent(id)}`, updateBody);
        res.json(response.data);
    } catch (error) {
        console.error(`Error updating alert ${id}:`, error.response?.data || error.message);
        const status = error.response ? error.response.status : 500;
        res.status(status).json(error.response?.data || { error: error.message });
    }
});

app.get('/api/alerts/:id/evidences', async (req, res) => {
    const alertRrn = req.params.id;
    if (!hasConfiguredApiKey()) {
        return res.status(401).json({ error: 'API key not configured' });
    }

    try {
        const client = getApiClient();
        const response = await client.get(`/idr/at/alerts/${encodeURIComponent(alertRrn)}/evidences`);
        res.json(response.data);
    } catch (error) {
        console.error(
            `Error fetching evidences for alert ${alertRrn}:`,
            error.response?.data || error.message
        );
        const status = error.response ? error.response.status : 500;
        res.status(status).json(error.response?.data || { error: error.message });
    }
});

app.get('/api/alerts/:id/actors', async (req, res) => {
    const alertRrn = req.params.id;
    if (!hasConfiguredApiKey()) {
        return res.status(401).json({ error: 'API key not configured' });
    }

    try {
        const client = getApiClient();
        const actors = await fetchAlertActors(client, alertRrn);
        res.json({
            data: actors.map(normalizeActor),
            metadata: {
                total_items: actors.length
            }
        });
    } catch (error) {
        console.error(
            `Error fetching actors for alert ${alertRrn}:`,
            error.response?.data || error.message
        );
        res.status(getErrorStatus(error)).json(getErrorBody(error));
    }
});

app.get('/api/alerts/:id/process-trees', async (req, res) => {
    const alertRrn = req.params.id;
    if (!hasConfiguredApiKey()) {
        return res.status(401).json({ error: 'API key not configured' });
    }

    try {
        const client = getApiClient();
        const payload = await fetchAlertProcessTrees(client, alertRrn, {
            index: parseInt(req.query.index, 10) || 0,
            size: Math.min(parseInt(req.query.size, 10) || 20, 100),
            forceRefresh: String(req.query.force_refresh || '').toLowerCase() === 'true',
            branch: req.query.branch
        });
        res.json({
            data: Array.isArray(payload.process_trees) ? payload.process_trees : [],
            metadata: payload.metadata || {}
        });
    } catch (error) {
        if (error.response?.status === 404) {
            return res.json({
                data: [],
                metadata: {
                    total_items: 0
                }
            });
        }

        console.error(
            `Error fetching process trees for alert ${alertRrn}:`,
            error.response?.data || error.message
        );
        res.status(getErrorStatus(error)).json(getErrorBody(error));
    }
});

app.post('/api/alerts/:id/investigate', async (req, res) => {
    const alertRrn = req.params.id;
    if (!hasConfiguredApiKey()) {
        return res.status(401).json({ error: 'API key not configured' });
    }

    try {
        const client = getApiClient();
        const alert = await fetchAlert(client, alertRrn);
        const organizationId = req.body?.organization_id || alert.organization?.id;

        if (!organizationId) {
            return res.status(400).json({ error: 'Could not determine organization for alert investigation creation' });
        }

        const investigateBody = {
            organization_id: organizationId,
            title: req.body?.title || alert.title || 'Alert investigation',
            priority: req.body?.priority || 'HIGH',
            status: req.body?.status || 'OPEN',
            disposition: req.body?.disposition || 'UNDECIDED',
            search: {
                terms: [
                    {
                        field_id: 'alert.rrn',
                        values: [alertRrn]
                    }
                ]
            }
        };

        if (req.body?.assignee_id) {
            investigateBody.assignee_id = req.body.assignee_id;
        }

        if (Array.isArray(req.body?.tags) && req.body.tags.length > 0) {
            investigateBody.tags = req.body.tags;
        }

        if (req.body?.comment) {
            investigateBody.comment = req.body.comment;
        }

        const response = await client.post('/idr/at/alerts/ops/investigate', investigateBody);
        res.json(response.data);
    } catch (error) {
        console.error(
            `Error creating investigation from alert ${alertRrn}:`,
            error.response?.data || error.message
        );
        res.status(getErrorStatus(error)).json(getErrorBody(error));
    }
});

app.get('/api/rules/:rrn/summary', async (req, res) => {
    const ruleRrn = req.params.rrn;
    const items = Array.isArray(req.query.item)
        ? req.query.item
        : (req.query.item ? [req.query.item] : []);
    if (!hasConfiguredApiKey()) {
        return res.status(401).json({ error: 'API key not configured' });
    }

    try {
        const client = getApiClient();
        const response = await client.get(`/idr/v1/rules/${encodeURIComponent(ruleRrn)}/summary`, {
            params: items.length > 0 ? { item: items } : undefined
        });
        res.json(response.data);
    } catch (error) {
        console.error(
            `Error fetching detection rule summary for ${ruleRrn}:`,
            error.response?.data || error.message
        );
        const status = error.response ? error.response.status : 500;
        res.status(status).json(error.response?.data || { error: error.message });
    }
});

// --- INVESTIGATIONS ---

app.get('/api/investigations', async (req, res) => {
    if (!hasConfiguredApiKey()) {
        return res.status(401).json({ error: 'API key not configured' });
    }

    try {
        const client = getApiClient();
        const range = typeof req.query.range === 'string' ? req.query.range : '7d';
        const { startTime, endTime } = getAlertSearchWindow(range);
        const pageSize = 100;
        let pageIndex = 0;
        let totalPages = 1;
        const allInvestigations = [];

        while (pageIndex < totalPages) {
            const response = await client.get('/idr/v2/investigations', {
                params: {
                    index: pageIndex,
                    size: pageSize,
                    start_time: startTime,
                    end_time: endTime,
                    sort: 'priority,DESC'
                }
            });

            const payload = response.data || {};
            const investigations = Array.isArray(payload.data) ? payload.data : [];
            allInvestigations.push(...investigations);

            totalPages = payload.metadata?.total_pages || 1;
            pageIndex += 1;
        }

        res.json({
            data: allInvestigations,
            metadata: {
                range,
                start_time: startTime,
                end_time: endTime,
                total_items: allInvestigations.length
            }
        });
    } catch (error) {
        console.error('Error fetching investigations:', error.response?.data || error.message);
        const status = error.response ? error.response.status : 500;
        res.status(status).json(error.response?.data || { error: error.message });
    }
});

app.post('/api/investigations', (req, res) => {
    proxyRequest(req, res, 'POST', `/idr/v2/investigations`, req.body);
});

app.get('/api/investigations/:id', async (req, res) => {
    if (!hasConfiguredApiKey()) {
        return res.status(401).json({ error: 'API key not configured' });
    }

    const id = req.params.id;

    try {
        const client = getApiClient();
        const investigation = await fetchInvestigation(client, id);
        res.json(investigation);
    } catch (error) {
        console.error(`Error fetching investigation ${id}:`, error.response?.data || error.message);
        res.status(getErrorStatus(error)).json(getErrorBody(error));
    }
});

app.get('/api/investigations/:id/alerts', async (req, res) => {
    if (!hasConfiguredApiKey()) {
        return res.status(401).json({ error: 'API key not configured' });
    }

    const id = req.params.id;

    try {
        const client = getApiClient();
        const investigationId = await resolveInvestigationApiId(client, id);
        const summaryAlerts = await fetchInvestigationAlerts(client, investigationId);
        const alertRrns = summaryAlerts.map(getAlertRrn).filter(Boolean);
        const triageAlerts = alertRrns.length > 0
            ? await fetchAlertsByRrns(client, alertRrns)
            : [];
        const triageByRrn = new Map(
            triageAlerts
                .filter(alert => alert?.rrn)
                .map(alert => [alert.rrn, alert])
        );
        const allAlerts = summaryAlerts.map(alert =>
            mergeInvestigationAlert(alert, triageByRrn.get(getAlertRrn(alert)) || {})
        );

        res.json({
            data: allAlerts,
            metadata: {
                total_data: allAlerts.length,
                enriched_items: triageAlerts.length
            }
        });
    } catch (error) {
        console.error(`Error fetching investigation alerts for ${id}:`, error.response?.data || error.message);
        const status = error.response ? error.response.status : 500;
        res.status(status).json(error.response?.data || { error: error.message });
    }
});

app.get('/api/investigations/:id/actors', async (req, res) => {
    if (!hasConfiguredApiKey()) {
        return res.status(401).json({ error: 'API key not configured' });
    }

    const id = req.params.id;

    try {
        const client = getApiClient();
        const investigationId = await resolveInvestigationApiId(client, id);

        try {
            const actors = await fetchInvestigationActors(client, investigationId);
            return res.json({
                data: actors.map(normalizeActor),
                metadata: {
                    source: 'investigation',
                    total_items: actors.length
                }
            });
        } catch {}

        const alerts = await fetchInvestigationAlerts(client, investigationId);
        const actorMap = new Map();
        const alertActorResults = await settleWithConcurrency(
            alerts,
            async alert => {
                const alertRrn = getAlertRrn(alert);
                if (!alertRrn) {
                    return { alertRrn: '', actors: [] };
                }

                try {
                    return {
                        alertRrn,
                        actors: await fetchAlertActors(client, alertRrn)
                    };
                } catch (error) {
                    error.alertRrn = alertRrn;
                    throw error;
                }
            }
        );

        alertActorResults.forEach(result => {
            if (result.status !== 'fulfilled') {
                console.warn(
                    `Could not fetch actors for alert ${result.reason?.alertRrn || 'unknown'} while building investigation actors:`,
                    result.reason?.response?.data || result.reason?.message || result.reason
                );
                return;
            }

            const { alertRrn, actors } = result.value || {};
            if (!alertRrn) return;

            actors.forEach(actor => {
                const normalized = normalizeActor(actor);
                const key = normalized.rrn || normalized.id || normalized.name;
                const existing = actorMap.get(key);

                actorMap.set(key, {
                    ...normalized,
                    alert_count: (existing?.alert_count || 0) + 1
                });
            });
        });

        const aggregatedActors = Array.from(actorMap.values()).sort((a, b) => {
            const countDelta = (b.alert_count || 0) - (a.alert_count || 0);
            if (countDelta !== 0) return countDelta;
            return String(a.name || '').localeCompare(String(b.name || ''));
        });

        res.json({
            data: aggregatedActors,
            metadata: {
                source: 'alert-aggregation',
                total_items: aggregatedActors.length,
                total_alerts: alerts.length
            }
        });
    } catch (error) {
        console.error(`Error fetching investigation actors for ${id}:`, error.response?.data || error.message);
        res.status(getErrorStatus(error)).json(getErrorBody(error));
    }
});

app.get('/api/investigations/:id/comments', async (req, res) => {
    if (!hasConfiguredApiKey()) {
        return res.status(401).json({ error: 'API key not configured' });
    }

    const id = req.params.id;

    try {
        const client = getApiClient();
        const target = await resolveInvestigationTarget(client, id);
        const payload = await fetchCommentsByTarget(client, target);

        res.json({
            data: payload.data,
            metadata: {
                ...(payload.metadata || {}),
                target,
                total_items: payload.data.length
            }
        });
    } catch (error) {
        console.error(`Error fetching investigation comments for ${id}:`, error.response?.data || error.message);
        res.status(getErrorStatus(error)).json(getErrorBody(error));
    }
});

app.post('/api/investigations/:id/comments', async (req, res) => {
    if (!hasConfiguredApiKey()) {
        return res.status(401).json({ error: 'API key not configured' });
    }

    const id = req.params.id;
    const body = typeof req.body?.body === 'string' ? req.body.body.trim() : '';
    const attachments = Array.isArray(req.body?.attachments)
        ? Array.from(new Set(req.body.attachments.map(value => String(value || '').trim()).filter(Boolean)))
        : [];

    if (!body && attachments.length === 0) {
        return res.status(400).json({ error: 'Comment body or attachments are required' });
    }

    try {
        const client = getApiClient();
        const target = await resolveInvestigationTarget(client, id);
        const requestBody = { target };

        if (body) {
            requestBody.body = body;
        }

        if (attachments.length > 0) {
            requestBody.attachments = attachments;
        }

        const response = await client.post('/idr/v1/comments', requestBody);
        res.json(response.data);
    } catch (error) {
        console.error(`Error creating investigation comment for ${id}:`, error.response?.data || error.message);
        res.status(getErrorStatus(error)).json(getErrorBody(error));
    }
});

app.get('/api/investigations/:id/attachments', async (req, res) => {
    if (!hasConfiguredApiKey()) {
        return res.status(401).json({ error: 'API key not configured' });
    }

    const id = req.params.id;

    try {
        const client = getApiClient();
        const target = await resolveInvestigationTarget(client, id);
        const payload = await fetchAttachmentsByTarget(client, target);

        res.json({
            data: payload.data,
            metadata: {
                ...(payload.metadata || {}),
                target,
                total_items: payload.data.length
            }
        });
    } catch (error) {
        console.error(`Error fetching investigation attachments for ${id}:`, error.response?.data || error.message);
        res.status(getErrorStatus(error)).json(getErrorBody(error));
    }
});

app.post('/api/attachments', async (req, res) => {
    if (!hasConfiguredApiKey()) {
        return res.status(401).json({ error: 'API key not configured' });
    }

    const contentType = String(req.headers['content-type'] || '');
    if (!contentType) {
        return res.status(400).json({ error: 'Attachment upload requires a content type' });
    }

    const contentLength = Number(req.headers['content-length']);
    if (Number.isFinite(contentLength) && contentLength > ATTACHMENT_UPLOAD_MAX_BYTES) {
        return res.status(413).json({
            error: `Attachment upload exceeds the ${ATTACHMENT_UPLOAD_MAX_BYTES}-byte limit`
        });
    }

    try {
        const currentConfig = getCurrentConfig();
        const response = await axios({
            method: 'POST',
            baseURL: getBaseUrl(),
            url: '/idr/v1/attachments',
            data: req,
            responseType: 'json',
            timeout: ATTACHMENT_UPLOAD_TIMEOUT_MS,
            maxBodyLength: ATTACHMENT_UPLOAD_MAX_BYTES,
            maxContentLength: ATTACHMENT_UPLOAD_MAX_BYTES,
            headers: {
                'X-Api-Key': currentConfig.apiKey,
                'Accept': 'application/json',
                'Content-Type': contentType,
                ...(req.headers['content-length'] ? { 'Content-Length': req.headers['content-length'] } : {})
            }
        });

        res.json(response.data);
    } catch (error) {
        console.error('Error uploading attachment:', error.response?.data || error.message);
        res.status(getErrorStatus(error)).json(getErrorBody(error));
    }
});

app.get('/api/attachments/:rrn/download', async (req, res) => {
    if (!hasConfiguredApiKey()) {
        return res.status(401).json({ error: 'API key not configured' });
    }

    const rrn = req.params.rrn;

    try {
        const currentConfig = getCurrentConfig();
        const response = await axios({
            method: 'GET',
            baseURL: getBaseUrl(),
            url: `/idr/v1/attachments/${encodeURIComponent(rrn)}`,
            responseType: 'stream',
            timeout: DEFAULT_UPSTREAM_TIMEOUT_MS,
            headers: {
                'X-Api-Key': currentConfig.apiKey,
                'Accept': '*/*'
            }
        });

        [
            'content-type',
            'content-length',
            'content-disposition',
            'cache-control',
            'etag',
            'last-modified'
        ].forEach(headerName => {
            const headerValue = response.headers?.[headerName];
            if (headerValue) {
                res.setHeader(headerName, headerValue);
            }
        });

        response.data.on('error', error => {
            console.error(`Attachment download stream failed for ${rrn}:`, error.message);
            if (!res.headersSent) {
                res.status(500).end();
            } else {
                res.end();
            }
        });

        response.data.pipe(res);
    } catch (error) {
        console.error(`Error downloading attachment ${rrn}:`, error.response?.data || error.message);
        const errorBody = await getAttachmentDownloadErrorBody(error);
        res.status(getErrorStatus(error)).json(errorBody);
    }
});

app.patch('/api/investigations/:id', async (req, res) => {
    if (!hasConfiguredApiKey()) {
        return res.status(401).json({ error: 'API key not configured' });
    }

    const id = req.params.id;
    const {
        status,
        priority,
        disposition,
        assignee_email,
        ...rest
    } = req.body || {};
    const hasAssigneeEmailField = Object.prototype.hasOwnProperty.call(req.body || {}, 'assignee_email');

    try {
        const client = getApiClient();
        const investigationId = await resolveInvestigationApiId(client, id);
        let latestResponse = null;
        const patchBody = { ...rest };

        if (hasAssigneeEmailField) {
            patchBody.assignee = {
                email: assignee_email || null
            };
        }

        if (Object.keys(patchBody).length > 0) {
            latestResponse = await client.patch(
                `/idr/v2/investigations/${encodeURIComponent(investigationId)}`,
                patchBody
            );
        }

        if (priority) {
            latestResponse = await client.put(
                `/idr/v2/investigations/${encodeURIComponent(investigationId)}/priority/${encodeURIComponent(priority)}`
            );
        }

        if (status) {
            const statusBody = status === 'CLOSED' && disposition
                ? { disposition }
                : {};
            latestResponse = await client.put(
                `/idr/v2/investigations/${encodeURIComponent(investigationId)}/status/${encodeURIComponent(status)}`,
                statusBody
            );
        } else if (disposition) {
            latestResponse = await client.put(
                `/idr/v2/investigations/${encodeURIComponent(investigationId)}/disposition/${encodeURIComponent(disposition)}`
            );
        }

        if (!latestResponse) {
            return res.status(400).json({ error: 'No investigation fields provided to update' });
        }

        res.json(latestResponse.data);
    } catch (error) {
        console.error(`Error updating investigation ${id}:`, error.response?.data || error.message);
        const statusCode = error.response ? error.response.status : 500;
        res.status(statusCode).json(error.response?.data || { error: error.message });
    }
});

const shouldServeBuiltFrontend = process.env.NODE_ENV === 'production' && fs.existsSync(FRONTEND_DIST_DIR);

if (shouldServeBuiltFrontend) {
    app.use(express.static(FRONTEND_DIST_DIR, {
        index: false
    }));

    app.get(/^\/(?!api(?:\/|$)).*/, (req, res, next) => {
        if (req.method !== 'GET' && req.method !== 'HEAD') {
            return next();
        }

        if (path.extname(req.path)) {
            return next();
        }

        return res.sendFile(path.join(FRONTEND_DIST_DIR, 'index.html'));
    });
}

function startServer(port = PORT) {
    return app.listen(port, () => {
        console.log(`Backend server listening on port ${port}`);
    });
}

if (require.main === module) {
    startServer();
}

module.exports = {
    app,
    startServer
};
