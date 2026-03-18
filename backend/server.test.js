const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { once } = require('node:events');
const { Readable } = require('node:stream');

const SERVER_MODULE_PATH = require.resolve('./server');

async function loadTestApp(t, options = {}) {
    const {
        sessionSecretMode = 'env',
        nodeEnv,
        forceSecureCookie = false
    } = options;
    const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'pocketsoc-backend-test-'));
    const configFile = path.join(tempDir, 'config.json');
    const sessionSecretFile = path.join(tempDir, 'session-secret.hex');
    const previousConfigFile = process.env.POCKETSOC_CONFIG_FILE;
    const previousSessionSecret = process.env.POCKETSOC_SESSION_SECRET;
    const previousSessionSecretFile = process.env.POCKETSOC_SESSION_SECRET_FILE;
    const previousForceSecureCookie = process.env.POCKETSOC_FORCE_SECURE_COOKIE;
    const previousNodeEnv = process.env.NODE_ENV;

    process.env.POCKETSOC_CONFIG_FILE = configFile;
    if (sessionSecretMode === 'env') {
        process.env.POCKETSOC_SESSION_SECRET = 'test-session-secret';
        delete process.env.POCKETSOC_SESSION_SECRET_FILE;
    } else if (sessionSecretMode === 'file') {
        delete process.env.POCKETSOC_SESSION_SECRET;
        process.env.POCKETSOC_SESSION_SECRET_FILE = sessionSecretFile;
    } else {
        delete process.env.POCKETSOC_SESSION_SECRET;
        delete process.env.POCKETSOC_SESSION_SECRET_FILE;
    }
    if (forceSecureCookie) {
        process.env.POCKETSOC_FORCE_SECURE_COOKIE = 'true';
    } else {
        delete process.env.POCKETSOC_FORCE_SECURE_COOKIE;
    }
    if (nodeEnv === undefined) {
        delete process.env.NODE_ENV;
    } else {
        process.env.NODE_ENV = nodeEnv;
    }
    delete require.cache[SERVER_MODULE_PATH];

    const { app } = require(SERVER_MODULE_PATH);
    const server = app.listen(0);
    await once(server, 'listening');

    t.after(async () => {
        await new Promise((resolve, reject) => {
            server.close(error => (error ? reject(error) : resolve()));
        });
        delete require.cache[SERVER_MODULE_PATH];

        if (previousConfigFile === undefined) {
            delete process.env.POCKETSOC_CONFIG_FILE;
        } else {
            process.env.POCKETSOC_CONFIG_FILE = previousConfigFile;
        }

        if (previousSessionSecret === undefined) {
            delete process.env.POCKETSOC_SESSION_SECRET;
        } else {
            process.env.POCKETSOC_SESSION_SECRET = previousSessionSecret;
        }

        if (previousSessionSecretFile === undefined) {
            delete process.env.POCKETSOC_SESSION_SECRET_FILE;
        } else {
            process.env.POCKETSOC_SESSION_SECRET_FILE = previousSessionSecretFile;
        }

        if (previousForceSecureCookie === undefined) {
            delete process.env.POCKETSOC_FORCE_SECURE_COOKIE;
        } else {
            process.env.POCKETSOC_FORCE_SECURE_COOKIE = previousForceSecureCookie;
        }

        if (previousNodeEnv === undefined) {
            delete process.env.NODE_ENV;
        } else {
            process.env.NODE_ENV = previousNodeEnv;
        }

        await fs.rm(tempDir, { recursive: true, force: true });
    });

    return {
        baseUrl: `http://127.0.0.1:${server.address().port}`,
        configFile,
        sessionSecretFile
    };
}

function getSetCookieHeader(response) {
    if (typeof response.headers.getSetCookie === 'function') {
        return response.headers.getSetCookie()[0] || null;
    }

    return response.headers.get('set-cookie');
}

function updateCookieJar(jar, response) {
    if (!jar) return;

    const setCookieHeader = getSetCookieHeader(response);
    if (!setCookieHeader) return;

    const [cookiePair] = setCookieHeader.split(';');
    if (cookiePair) {
        jar.cookie = cookiePair;
    }
}

async function fetchWithSession(baseUrl, urlPath, options = {}) {
    const {
        jar,
        headers = {},
        ...fetchOptions
    } = options;
    const requestHeaders = { ...headers };

    if (jar?.cookie) {
        requestHeaders.cookie = jar.cookie;
    }

    const response = await fetch(`${baseUrl}${urlPath}`, {
        ...fetchOptions,
        headers: requestHeaders
    });
    updateCookieJar(jar, response);
    return response;
}

async function requestJson(baseUrl, urlPath, options = {}) {
    const {
        method = 'GET',
        body,
        headers = {},
        jar
    } = options;
    const requestHeaders = { ...headers };
    let requestBody = body;

    if (body !== undefined && !requestHeaders['content-type']) {
        requestHeaders['content-type'] = 'application/json';
        requestBody = JSON.stringify(body);
    }

    const response = await fetchWithSession(baseUrl, urlPath, {
        method,
        headers: requestHeaders,
        body: requestBody,
        jar
    });
    const responseText = await response.text();
    let data = null;

    if (responseText) {
        data = JSON.parse(responseText);
    }

    return {
        status: response.status,
        data,
        headers: response.headers
    };
}

async function setConfig(baseUrl, values = {}, jar) {
    const response = await requestJson(baseUrl, '/api/config', {
        method: 'POST',
        body: {
            apiKey: 'test-api-key',
            ...values
        },
        jar
    });

    assert.equal(response.status, 200);
}

function createSessionClient(baseUrl) {
    const jar = {};

    return {
        jar,
        requestJson(urlPath, options = {}) {
            return requestJson(baseUrl, urlPath, {
                ...options,
                jar
            });
        },
        fetch(urlPath, options = {}) {
            return fetchWithSession(baseUrl, urlPath, {
                ...options,
                jar
            });
        },
        setConfig(values = {}) {
            return setConfig(baseUrl, values, jar);
        }
    };
}

function installAxiosCreateMock(t, handlers = {}) {
    const axios = require('axios');
    const originalCreate = axios.create;
    const createCalls = [];
    const requestCalls = [];

    function invoke(method, url, data, config) {
        requestCalls.push({ method, url, data, config });
        const handler = handlers[method];

        assert.ok(handler, `Unexpected axios.${method} call to ${url}`);
        return Promise.resolve(handler({ url, data, config }));
    }

    axios.create = createConfig => {
        createCalls.push(createConfig);
        return {
            get(url, config) {
                return invoke('get', url, null, config);
            },
            post(url, data, config) {
                return invoke('post', url, data, config);
            },
            patch(url, data, config) {
                return invoke('patch', url, data, config);
            },
            put(url, data, config) {
                return invoke('put', url, data, config);
            }
        };
    };

    t.after(() => {
        axios.create = originalCreate;
    });

    return {
        createCalls,
        requestCalls
    };
}

function installAxiosRequestMock(t, handler) {
    const axiosModulePath = require.resolve('axios');
    const originalAxios = require(axiosModulePath);
    const requestCalls = [];
    const axiosMock = function axiosRequest(config) {
        requestCalls.push(config);
        return Promise.resolve(handler(config));
    };

    Object.assign(axiosMock, originalAxios);
    require.cache[axiosModulePath].exports = axiosMock;

    t.after(() => {
        require.cache[axiosModulePath].exports = originalAxios;
    });

    return {
        requestCalls
    };
}

function silenceConsoleError(t) {
    const originalError = console.error;

    console.error = () => {};

    t.after(() => {
        console.error = originalError;
    });
}

function silenceConsoleWarn(t) {
    const originalWarn = console.warn;

    console.warn = () => {};

    t.after(() => {
        console.warn = originalWarn;
    });
}

async function withTemporaryFrontendDist(t, files = {}) {
    const frontendDistDir = path.resolve(__dirname, '..', 'frontend', 'dist');
    const backupDir = `${frontendDistDir}.backup-${process.pid}-${Date.now()}`;
    let hadExistingDist = false;

    try {
        await fs.rename(frontendDistDir, backupDir);
        hadExistingDist = true;
    } catch (error) {
        if (error.code !== 'ENOENT') {
            throw error;
        }
    }

    await fs.mkdir(frontendDistDir, { recursive: true });

    await Promise.all(Object.entries(files).map(async ([relativePath, contents]) => {
        const filePath = path.join(frontendDistDir, relativePath);
        await fs.mkdir(path.dirname(filePath), { recursive: true });
        await fs.writeFile(filePath, contents, 'utf8');
    }));

    t.after(async () => {
        await fs.rm(frontendDistDir, { recursive: true, force: true });

        if (hadExistingDist) {
            await fs.rename(backupDir, frontendDistDir);
        }
    });
}

test('config endpoints remember browsers separately and encrypt stored keys', async t => {
    const { baseUrl, configFile } = await loadTestApp(t);
    const browserA = createSessionClient(baseUrl);
    const browserB = createSessionClient(baseUrl);

    const initial = await browserA.requestJson('/api/config');
    assert.equal(initial.status, 200);
    assert.deepEqual(initial.data, {
        hasApiKey: false,
        hasPlatformUserApiKey: false,
        region: 'us'
    });
    assert.match(
        getSetCookieHeader({ headers: initial.headers }) || '',
        /pocketsoc_session=.*Max-Age=77759\d{2}/
    );

    const saveResponse = await browserA.requestJson('/api/config', {
        method: 'POST',
        body: {
            apiKey: 'api-key-123',
            platformUserApiKey: 'platform-key-456',
            region: 'eu'
        }
    });

    assert.equal(saveResponse.status, 200);
    const savedConfigRaw = await fs.readFile(configFile, 'utf8');
    const savedConfig = JSON.parse(savedConfigRaw);
    assert.equal(savedConfig.version, 2);
    assert.ok(Object.keys(savedConfig.sessions).length >= 1);
    assert.equal(savedConfigRaw.includes('api-key-123'), false);
    assert.equal(savedConfigRaw.includes('platform-key-456'), false);
    const savedConfigStats = await fs.stat(configFile);
    assert.equal(savedConfigStats.mode & 0o777, 0o600);

    const configured = await browserA.requestJson('/api/config');
    assert.equal(configured.status, 200);
    assert.deepEqual(configured.data, {
        hasApiKey: true,
        hasPlatformUserApiKey: true,
        region: 'eu'
    });
    assert.equal(Object.prototype.hasOwnProperty.call(configured.data, 'apiKey'), false);
    assert.equal(Object.prototype.hasOwnProperty.call(configured.data, 'platformUserApiKey'), false);

    const otherBrowser = await browserB.requestJson('/api/config');
    assert.equal(otherBrowser.status, 200);
    assert.deepEqual(otherBrowser.data, {
        hasApiKey: false,
        hasPlatformUserApiKey: false,
        region: 'us'
    });

    const preserveKeys = await browserA.requestJson('/api/config', {
        method: 'POST',
        body: {
            apiKey: '',
            platformUserApiKey: '',
            region: 'ca'
        }
    });

    assert.equal(preserveKeys.status, 200);
    const preserved = await browserA.requestJson('/api/config');
    assert.equal(preserved.status, 200);
    assert.deepEqual(preserved.data, {
        hasApiKey: true,
        hasPlatformUserApiKey: true,
        region: 'ca'
    });

    const clearResponse = await browserA.requestJson('/api/config/clear', {
        method: 'POST'
    });
    assert.equal(clearResponse.status, 200);

    const cleared = await browserA.requestJson('/api/config');
    assert.equal(cleared.status, 200);
    assert.deepEqual(cleared.data, {
        hasApiKey: false,
        hasPlatformUserApiKey: false,
        region: 'ca'
    });

    const otherBrowserAfterClear = await browserB.requestJson('/api/config');
    assert.equal(otherBrowserAfterClear.status, 200);
    assert.deepEqual(otherBrowserAfterClear.data, {
        hasApiKey: false,
        hasPlatformUserApiKey: false,
        region: 'us'
    });
});

test('config endpoint rejects unsupported regions and keeps the previous value', async t => {
    const { baseUrl } = await loadTestApp(t);
    const client = createSessionClient(baseUrl);

    await client.setConfig({ region: 'eu' });

    const invalidResponse = await client.requestJson('/api/config', {
        method: 'POST',
        body: {
            region: 'us2'
        }
    });

    assert.equal(invalidResponse.status, 400);
    assert.deepEqual(invalidResponse.data, {
        error: 'Region must be one of: us, eu, ca, ap'
    });

    const configured = await client.requestJson('/api/config');
    assert.equal(configured.status, 200);
    assert.equal(configured.data.region, 'eu');
});

test('config endpoint ignores whitespace-only keys instead of treating them as configured', async t => {
    const { baseUrl } = await loadTestApp(t);
    const client = createSessionClient(baseUrl);

    const saveResponse = await client.requestJson('/api/config', {
        method: 'POST',
        body: {
            apiKey: '   ',
            platformUserApiKey: '\n\t',
            region: 'ca'
        }
    });

    assert.equal(saveResponse.status, 200);

    const configured = await client.requestJson('/api/config');
    assert.equal(configured.status, 200);
    assert.deepEqual(configured.data, {
        hasApiKey: false,
        hasPlatformUserApiKey: false,
        region: 'ca'
    });
});

test('generated session secret files are written with restrictive permissions', async t => {
    const { sessionSecretFile } = await loadTestApp(t, { sessionSecretMode: 'file' });
    const secretStats = await fs.stat(sessionSecretFile);

    assert.equal(secretStats.mode & 0o777, 0o600);
});

test('generated session secret defaults to the config directory when no override is provided', async t => {
    const { sessionSecretFile } = await loadTestApp(t, { sessionSecretMode: 'auto' });
    const secretStats = await fs.stat(sessionSecretFile);

    assert.equal(secretStats.mode & 0o777, 0o600);
});

test('malformed session cookies are ignored instead of crashing the request pipeline', async t => {
    const { baseUrl } = await loadTestApp(t);

    const response = await fetch(`${baseUrl}/api/config`, {
        headers: {
            cookie: 'pocketsoc_session=%E0%A4%A'
        }
    });

    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), {
        hasApiKey: false,
        hasPlatformUserApiKey: false,
        region: 'us'
    });
});

test('force secure cookie env adds the Secure flag even for non-https requests', async t => {
    const { baseUrl } = await loadTestApp(t, { forceSecureCookie: true });

    const response = await fetch(`${baseUrl}/api/config`);
    const setCookieHeader = getSetCookieHeader(response) || '';

    assert.equal(response.status, 200);
    assert.match(setCookieHeader, /;\s*Secure(?:;|$)/);
});

test('production mode serves built frontend while preserving api routes', async t => {
    await withTemporaryFrontendDist(t, {
        'index.html': '<!doctype html><html><body>PocketSOC test shell</body></html>',
        'assets/app.js': 'console.log("pocketsoc");'
    });

    const { baseUrl } = await loadTestApp(t, { nodeEnv: 'production' });

    const rootResponse = await fetch(`${baseUrl}/`);
    assert.equal(rootResponse.status, 200);
    assert.match(await rootResponse.text(), /PocketSOC test shell/);
    assert.match(rootResponse.headers.get('content-type') || '', /text\/html/);

    const assetResponse = await fetch(`${baseUrl}/assets/app.js`);
    assert.equal(assetResponse.status, 200);
    assert.equal(await assetResponse.text(), 'console.log("pocketsoc");');

    const deepLinkResponse = await fetch(`${baseUrl}/alerts/open`);
    assert.equal(deepLinkResponse.status, 200);
    assert.match(await deepLinkResponse.text(), /PocketSOC test shell/);

    const apiResponse = await requestJson(baseUrl, '/api/config');
    assert.equal(apiResponse.status, 200);
    assert.deepEqual(apiResponse.data, {
        hasApiKey: false,
        hasPlatformUserApiKey: false,
        region: 'us'
    });
});

test('alerts endpoint searches RRNs and returns hydrated alerts in search order', async t => {
    const { baseUrl } = await loadTestApp(t);
    const client = createSessionClient(baseUrl);
    await client.setConfig();
    const { createCalls, requestCalls } = installAxiosCreateMock(t, {
        post({ url, data, config }) {
            if (url === '/idr/at/alerts/ops/search') {
                assert.equal(config.params.index, 0);
                assert.equal(config.params.size, 100);
                assert.equal(config.params.rrns_only, true);
                assert.equal(new Date(data.search.start_time).getUTCHours(), 0);
                assert.equal(new Date(data.search.start_time).getUTCMinutes(), 0);
                assert.equal(new Date(data.search.start_time).getUTCSeconds(), 0);

                return {
                    data: {
                        rrns: ['rrn:alert:1', 'rrn:alert:2'],
                        metadata: {
                            total_items: 2,
                            is_last_index: true
                        }
                    }
                };
            }

            if (url === '/idr/at/alerts/ops/rrns') {
                assert.deepEqual(data.rrns, ['rrn:alert:1', 'rrn:alert:2']);

                return {
                    data: {
                        alerts: [
                            { rrn: 'rrn:alert:2', title: 'Second alert' },
                            { rrn: 'rrn:alert:1', title: 'First alert' }
                        ]
                    }
                };
            }

            assert.fail(`Unexpected POST ${url}`);
        }
    });

    const response = await client.requestJson('/api/alerts?range=today');
    assert.equal(response.status, 200);
    assert.deepEqual(response.data.data.map(alert => alert.rrn), [
        'rrn:alert:1',
        'rrn:alert:2'
    ]);
    assert.equal(response.data.metadata.range, 'today');
    assert.equal(createCalls[0].baseURL, 'https://us.api.insight.rapid7.com');
    assert.equal(createCalls[0].headers['X-Api-Key'], 'test-api-key');
    assert.equal(createCalls[0].timeout, 20000);
    assert.equal(requestCalls.length, 2);
});

test('alerts endpoint maps upstream timeouts to a 504 response', async t => {
    const { baseUrl } = await loadTestApp(t);
    const client = createSessionClient(baseUrl);
    await client.setConfig();
    const { createCalls } = installAxiosCreateMock(t, {
        post({ url }) {
            assert.equal(url, '/idr/at/alerts/ops/search');

            throw Object.assign(new Error('timeout of 20000ms exceeded'), {
                code: 'ECONNABORTED'
            });
        }
    });
    silenceConsoleError(t);

    const response = await client.requestJson('/api/alerts?range=today');
    assert.equal(response.status, 504);
    assert.deepEqual(response.data, {
        error: 'Upstream request timed out'
    });
    assert.equal(createCalls[0].timeout, 20000);
});

test('alert patch rejects empty payloads and only forwards populated fields', async t => {
    const { baseUrl } = await loadTestApp(t);
    const client = createSessionClient(baseUrl);
    await client.setConfig();

    const emptyResponse = await client.requestJson('/api/alerts/alert-123', {
        method: 'PATCH',
        body: {}
    });
    assert.equal(emptyResponse.status, 400);
    assert.deepEqual(emptyResponse.data, {
        error: 'No alert fields provided to update'
    });

    installAxiosCreateMock(t, {
        patch({ url, data }) {
            assert.equal(url, '/idr/at/alerts/alert-123');
            assert.deepEqual(data, {
                status: { value: 'OPEN' },
                priority: { value: 'HIGH' }
            });

            return {
                data: {
                    success: true
                }
            };
        }
    });

    const updateResponse = await client.requestJson('/api/alerts/alert-123', {
        method: 'PATCH',
        body: {
            status: 'OPEN',
            priority: 'HIGH',
            assignee_id: '',
            investigation_rrn: null
        }
    });

    assert.equal(updateResponse.status, 200);
    assert.deepEqual(updateResponse.data, {
        success: true
    });
});

test('investigations endpoint paginates and flattens responses', async t => {
    const { baseUrl } = await loadTestApp(t);
    const client = createSessionClient(baseUrl);
    await client.setConfig({ region: 'eu' });
    const { createCalls, requestCalls } = installAxiosCreateMock(t, {
        get({ url, config }) {
            assert.equal(url, '/idr/v2/investigations');
            assert.equal(config.params.size, 100);
            assert.equal(config.params.sort, 'priority,DESC');

            if (config.params.index === 0) {
                return {
                    data: {
                        data: [{ id: 'inv-1', title: 'First investigation' }],
                        metadata: {
                            total_pages: 2
                        }
                    }
                };
            }

            if (config.params.index === 1) {
                return {
                    data: {
                        data: [{ id: 'inv-2', title: 'Second investigation' }],
                        metadata: {
                            total_pages: 2
                        }
                    }
                };
            }

            assert.fail(`Unexpected investigations page ${config.params.index}`);
        }
    });

    const response = await client.requestJson('/api/investigations?range=28d');
    assert.equal(response.status, 200);
    assert.deepEqual(response.data.data.map(item => item.id), ['inv-1', 'inv-2']);
    assert.equal(response.data.metadata.range, '28d');
    assert.equal(response.data.metadata.total_items, 2);
    assert.equal(createCalls[0].baseURL, 'https://eu.api.insight.rapid7.com');
    assert.equal(requestCalls.length, 2);
});

test('attachment upload validates content type before proxying', async t => {
    const { baseUrl } = await loadTestApp(t);
    const client = createSessionClient(baseUrl);
    await client.setConfig();

    const response = await client.requestJson('/api/attachments', {
        method: 'POST'
    });

    assert.equal(response.status, 400);
    assert.deepEqual(response.data, {
        error: 'Attachment upload requires a content type'
    });
});

test('attachment download streams content and forwards response headers', async t => {
    const { requestCalls } = installAxiosRequestMock(t, config => {
        assert.equal(config.method, 'GET');
        assert.equal(config.baseURL, 'https://us.api.insight.rapid7.com');
        assert.equal(config.url, '/idr/v1/attachments/attachment-42');
        assert.equal(config.responseType, 'stream');
        assert.equal(config.headers['X-Api-Key'], 'test-api-key');

        return {
            headers: {
                'content-type': 'text/plain',
                'content-length': '12',
                'content-disposition': 'attachment; filename="triage.txt"'
            },
            data: Readable.from(['hello world!'])
        };
    });
    const { baseUrl } = await loadTestApp(t);
    const client = createSessionClient(baseUrl);
    await client.setConfig();

    const response = await client.fetch('/api/attachments/attachment-42/download');
    assert.equal(response.status, 200);
    assert.equal(response.headers.get('content-type'), 'text/plain');
    assert.equal(response.headers.get('content-length'), '12');
    assert.equal(
        response.headers.get('content-disposition'),
        'attachment; filename="triage.txt"'
    );
    assert.equal(await response.text(), 'hello world!');
    assert.equal(requestCalls.length, 1);
});

test('attachment download returns a usable error body when Rapid7 responds with a stream error', async t => {
    const { requestCalls } = installAxiosRequestMock(t, config => {
        assert.equal(config.method, 'GET');

        throw {
            response: {
                status: 404,
                data: Readable.from(['Attachment not found'])
            },
            message: 'Request failed with status code 404'
        };
    });
    silenceConsoleError(t);
    const { baseUrl } = await loadTestApp(t);
    const client = createSessionClient(baseUrl);
    await client.setConfig();

    const response = await client.fetch('/api/attachments/missing/download');
    assert.equal(response.status, 404);
    assert.deepEqual(await response.json(), {
        error: 'Attachment not found'
    });
    assert.equal(requestCalls.length, 1);
});

test('investigation comments resolve target RRNs and merge paged responses', async t => {
    const { baseUrl } = await loadTestApp(t);
    const client = createSessionClient(baseUrl);
    await client.setConfig();
    const { requestCalls } = installAxiosCreateMock(t, {
        get({ url, config }) {
            if (url === '/idr/v2/investigations/inv-456') {
                return {
                    data: {
                        id: 'inv-456',
                        rrn: 'rrn:investigation:456'
                    }
                };
            }

            if (url === '/idr/v1/comments') {
                assert.equal(config.params.target, 'rrn:investigation:456');
                assert.equal(config.params.size, 100);

                if (config.params.index === 0) {
                    return {
                        data: {
                            data: [{ id: 'comment-1', body: 'First note' }],
                            metadata: {
                                total_pages: 2
                            }
                        }
                    };
                }

                if (config.params.index === 1) {
                    return {
                        data: {
                            data: [{ id: 'comment-2', body: 'Second note' }],
                            metadata: {
                                total_pages: 2
                            }
                        }
                    };
                }
            }

            assert.fail(`Unexpected GET ${url}`);
        }
    });

    const response = await client.requestJson('/api/investigations/inv-456/comments');
    assert.equal(response.status, 200);
    assert.deepEqual(response.data.data.map(item => item.id), ['comment-1', 'comment-2']);
    assert.equal(response.data.metadata.target, 'rrn:investigation:456');
    assert.equal(response.data.metadata.total_items, 2);
    assert.equal(requestCalls.length, 3);
});

test('investigation comment creation trims body and deduplicates attachments', async t => {
    const { baseUrl } = await loadTestApp(t);
    const client = createSessionClient(baseUrl);
    await client.setConfig();

    const emptyResponse = await client.requestJson('/api/investigations/inv-789/comments', {
        method: 'POST',
        body: {
            body: '   ',
            attachments: [' ', '']
        }
    });
    assert.equal(emptyResponse.status, 400);
    assert.deepEqual(emptyResponse.data, {
        error: 'Comment body or attachments are required'
    });

    installAxiosCreateMock(t, {
        get({ url }) {
            assert.equal(url, '/idr/v2/investigations/inv-789');
            return {
                data: {
                    rrn: 'rrn:investigation:789'
                }
            };
        },
        post({ url, data }) {
            assert.equal(url, '/idr/v1/comments');
            assert.deepEqual(data, {
                target: 'rrn:investigation:789',
                body: 'Need analyst review',
                attachments: ['rrn:attachment:1', 'rrn:attachment:2']
            });

            return {
                data: {
                    id: 'comment-created'
                }
            };
        }
    });

    const createResponse = await client.requestJson('/api/investigations/inv-789/comments', {
        method: 'POST',
        body: {
            body: '  Need analyst review  ',
            attachments: [
                'rrn:attachment:1',
                ' ',
                'rrn:attachment:1',
                'rrn:attachment:2'
            ]
        }
    });

    assert.equal(createResponse.status, 200);
    assert.deepEqual(createResponse.data, {
        id: 'comment-created'
    });
});

test('investigation attachments resolve target RRNs and merge paged responses', async t => {
    const { baseUrl } = await loadTestApp(t);
    const client = createSessionClient(baseUrl);
    await client.setConfig({ region: 'eu' });
    const { createCalls, requestCalls } = installAxiosCreateMock(t, {
        get({ url, config }) {
            if (url === '/idr/v2/investigations/inv-321') {
                return {
                    data: {
                        rrn: 'rrn:investigation:321'
                    }
                };
            }

            if (url === '/idr/v1/attachments') {
                assert.equal(config.params.target, 'rrn:investigation:321');
                assert.equal(config.params.size, 100);

                if (config.params.index === 0) {
                    return {
                        data: {
                            data: [{ rrn: 'rrn:attachment:1', name: 'triage.txt' }],
                            metadata: {
                                total_pages: 2
                            }
                        }
                    };
                }

                if (config.params.index === 1) {
                    return {
                        data: {
                            data: [{ rrn: 'rrn:attachment:2', name: 'evidence.zip' }],
                            metadata: {
                                total_pages: 2
                            }
                        }
                    };
                }
            }

            assert.fail(`Unexpected GET ${url}`);
        }
    });

    const response = await client.requestJson('/api/investigations/inv-321/attachments');
    assert.equal(response.status, 200);
    assert.deepEqual(response.data.data.map(item => item.rrn), [
        'rrn:attachment:1',
        'rrn:attachment:2'
    ]);
    assert.equal(response.data.metadata.target, 'rrn:investigation:321');
    assert.equal(response.data.metadata.total_items, 2);
    assert.equal(createCalls[0].baseURL, 'https://eu.api.insight.rapid7.com');
    assert.equal(requestCalls.length, 3);
});

test('investigation attachment lookup preserves upstream error status and body', async t => {
    const { baseUrl } = await loadTestApp(t);
    const client = createSessionClient(baseUrl);
    await client.setConfig();
    silenceConsoleError(t);
    installAxiosCreateMock(t, {
        get({ url, config }) {
            if (url === '/idr/v2/investigations/inv-654') {
                return {
                    data: {
                        rrn: 'rrn:investigation:654'
                    }
                };
            }

            if (url === '/idr/v1/attachments') {
                assert.equal(config.params.target, 'rrn:investigation:654');
                throw {
                    response: {
                        status: 502,
                        data: {
                            error: 'Rapid7 attachments unavailable'
                        }
                    }
                };
            }

            assert.fail(`Unexpected GET ${url}`);
        }
    });

    const response = await client.requestJson('/api/investigations/inv-654/attachments');
    assert.equal(response.status, 502);
    assert.deepEqual(response.data, {
        error: 'Rapid7 attachments unavailable'
    });
});

test('investigation alerts keep summary data when no alert rrns are available for enrichment', async t => {
    const { baseUrl } = await loadTestApp(t);
    const client = createSessionClient(baseUrl);
    await client.setConfig();

    installAxiosCreateMock(t, {
        get({ url, config }) {
            if (url === '/idr/v2/investigations/inv-alerts-123/alerts') {
                assert.equal(config.params.index, 0);
                assert.equal(config.params.size, 100);
                return {
                    data: {
                        data: [
                            {
                                id: 'cdc389b6-e6f2-4979-870c-a195f9f72d08',
                                title: 'Summary-only alert',
                                created_time: '2026-03-17T10:00:00Z',
                                latest_event_time: '2026-03-17T10:05:00Z',
                                alert_source: 'Investigations',
                                alert_type: 'Endpoint',
                                alert_type_description: 'Summary payload'
                            }
                        ],
                        metadata: {
                            total_pages: 1
                        }
                    }
                };
            }

            assert.fail(`Unexpected GET ${url}`);
        },
        post({ url }) {
            assert.fail(`Unexpected POST ${url}`);
        }
    });

    const response = await client.requestJson('/api/investigations/inv-alerts-123/alerts');
    assert.equal(response.status, 200);
    assert.equal(response.data.metadata.enriched_items, 0);
    assert.deepEqual(response.data.data, [
        {
            id: 'cdc389b6-e6f2-4979-870c-a195f9f72d08',
            title: 'Summary-only alert',
            created_time: '2026-03-17T10:00:00Z',
            latest_event_time: '2026-03-17T10:05:00Z',
            alert_source: 'Investigations',
            alert_type: 'Endpoint',
            alert_type_description: 'Summary payload',
            rrn: null,
            created_at: '2026-03-17T10:00:00Z',
            alerted_at: '2026-03-17T10:05:00Z',
            external_source: 'Investigations',
            rule: {
                rrn: null,
                name: null,
                version_rrn: null
            },
            detection_rule_rrn: null
        }
    ]);
});

test('investigation actors resolve rrn inputs to canonical investigation ids', async t => {
    const { baseUrl } = await loadTestApp(t);
    const client = createSessionClient(baseUrl);
    const investigationRrn = 'rrn:investigation:us:acct-123:investigation:H96TEST';
    await client.setConfig();
    const { requestCalls } = installAxiosCreateMock(t, {
        get({ url }) {
            if (url === `/idr/v2/investigations/${encodeURIComponent(investigationRrn)}`) {
                return {
                    data: {
                        id: 'inv-actors-123',
                        rrn: investigationRrn
                    }
                };
            }

            if (url === '/idr/v2/investigations/inv-actors-123/actors') {
                return {
                    data: {
                        data: [
                            {
                                rrn: 'rrn:actor:1',
                                display_name: 'Host Alpha',
                                type: 'ASSET'
                            }
                        ]
                    }
                };
            }

            assert.fail(`Unexpected GET ${url}`);
        }
    });

    const response = await client.requestJson(`/api/investigations/${encodeURIComponent(investigationRrn)}/actors`);
    assert.equal(response.status, 200);
    assert.equal(response.data.metadata.source, 'investigation');
    assert.equal(response.data.metadata.total_items, 1);
    assert.deepEqual(response.data.data, [
        {
            rrn: 'rrn:actor:1',
            id: 'rrn:actor:1',
            type: 'ASSET',
            name: 'Host Alpha',
            domain: '',
            source: '',
            raw: {
                rrn: 'rrn:actor:1',
                display_name: 'Host Alpha',
                type: 'ASSET'
            }
        }
    ]);
    assert.equal(requestCalls.length, 2);
});

test('investigation actor fallback skips alert actor lookups when summaries do not include alert rrns', async t => {
    const { baseUrl } = await loadTestApp(t);
    const client = createSessionClient(baseUrl);
    await client.setConfig();

    installAxiosCreateMock(t, {
        get({ url, config }) {
            if (url === '/idr/v2/investigations/inv-actors-empty/actors') {
                throw {
                    response: {
                        status: 500,
                        data: {
                            message: 'A server error occurred'
                        }
                    }
                };
            }

            if (url === '/idr/v2/investigations/inv-actors-empty/alerts') {
                assert.equal(config.params.index, 0);
                assert.equal(config.params.size, 100);
                return {
                    data: {
                        data: [
                            {
                                id: 'cdc389b6-e6f2-4979-870c-a195f9f72d08',
                                title: 'Summary-only alert',
                                created_time: '2026-03-17T10:00:00Z',
                                latest_event_time: '2026-03-17T10:05:00Z',
                                alert_source: 'Investigations',
                                alert_type: 'Endpoint',
                                alert_type_description: 'Summary payload'
                            }
                        ],
                        metadata: {
                            total_pages: 1
                        }
                    }
                };
            }

            if (url.startsWith('/idr/at/alerts/')) {
                assert.fail(`Unexpected alert actor lookup ${url}`);
            }

            assert.fail(`Unexpected GET ${url}`);
        }
    });

    const response = await client.requestJson('/api/investigations/inv-actors-empty/actors');
    assert.equal(response.status, 200);
    assert.equal(response.data.metadata.source, 'alert-aggregation');
    assert.equal(response.data.metadata.total_items, 0);
    assert.equal(response.data.metadata.total_alerts, 1);
    assert.deepEqual(response.data.data, []);
});

test('investigation actors fall back to alert aggregation when direct lookup fails', async t => {
    const { baseUrl } = await loadTestApp(t);
    const client = createSessionClient(baseUrl);
    await client.setConfig();
    silenceConsoleWarn(t);

    installAxiosCreateMock(t, {
        get({ url, config }) {
            if (url === '/idr/v2/investigations/inv-aggregate-123/actors') {
                throw {
                    response: {
                        status: 500,
                        data: {
                            message: 'A server error occurred',
                            correlation_id: 'test-correlation-id'
                        }
                    }
                };
            }

            if (url === '/idr/v2/investigations/inv-aggregate-123/alerts') {
                assert.equal(config.params.index, 0);
                assert.equal(config.params.size, 100);
                return {
                    data: {
                        data: [
                            { id: 'rrn:alert:1' },
                            { rrn: 'rrn:alert:2' }
                        ],
                        metadata: {
                            total_pages: 1
                        }
                    }
                };
            }

            if (url === `/idr/at/alerts/${encodeURIComponent('rrn:alert:1')}/actors`) {
                return {
                    data: {
                        actors: [
                            {
                                rrn: 'rrn:actor:shared',
                                display_name: 'Shared Host',
                                type: 'ASSET'
                            }
                        ]
                    }
                };
            }

            if (url === `/idr/at/alerts/${encodeURIComponent('rrn:alert:2')}/actors`) {
                return {
                    data: {
                        actors: [
                            {
                                rrn: 'rrn:actor:shared',
                                display_name: 'Shared Host',
                                type: 'ASSET'
                            },
                            {
                                rrn: 'rrn:actor:user-2',
                                display_name: 'Analyst Laptop',
                                type: 'ASSET'
                            }
                        ]
                    }
                };
            }

            assert.fail(`Unexpected GET ${url}`);
        }
    });

    const response = await client.requestJson('/api/investigations/inv-aggregate-123/actors');
    assert.equal(response.status, 200);
    assert.equal(response.data.metadata.source, 'alert-aggregation');
    assert.equal(response.data.metadata.total_items, 2);
    assert.equal(response.data.metadata.total_alerts, 2);
    assert.deepEqual(
        response.data.data.map(actor => ({
            rrn: actor.rrn,
            name: actor.name,
            alert_count: actor.alert_count
        })),
        [
            {
                rrn: 'rrn:actor:shared',
                name: 'Shared Host',
                alert_count: 2
            },
            {
                rrn: 'rrn:actor:user-2',
                name: 'Analyst Laptop',
                alert_count: 1
            }
        ]
    );
});

test('investigation patch resolves rrn inputs before calling v2 endpoints', async t => {
    const { baseUrl } = await loadTestApp(t);
    const client = createSessionClient(baseUrl);
    const investigationRrn = 'rrn:investigation:us:acct-123:investigation:H96PATCH';
    await client.setConfig();

    installAxiosCreateMock(t, {
        get({ url }) {
            assert.equal(url, `/idr/v2/investigations/${encodeURIComponent(investigationRrn)}`);
            return {
                data: {
                    id: 'inv-patch-123',
                    rrn: investigationRrn
                }
            };
        },
        patch({ url, data }) {
            assert.equal(url, '/idr/v2/investigations/inv-patch-123');
            assert.deepEqual(data, {
                assignee: {
                    email: null
                }
            });

            return {
                data: {
                    updated: 'assignee'
                }
            };
        }
    });

    const response = await client.requestJson(`/api/investigations/${encodeURIComponent(investigationRrn)}`, {
        method: 'PATCH',
        body: {
            assignee_email: ''
        }
    });

    assert.equal(response.status, 200);
    assert.deepEqual(response.data, {
        updated: 'assignee'
    });
});

test('investigation patch rejects empty payloads', async t => {
    const { baseUrl } = await loadTestApp(t);
    const client = createSessionClient(baseUrl);
    await client.setConfig();

    const response = await client.requestJson('/api/investigations/inv-111', {
        method: 'PATCH',
        body: {}
    });

    assert.equal(response.status, 400);
    assert.deepEqual(response.data, {
        error: 'No investigation fields provided to update'
    });
});

test('investigation patch keeps explicit assignee clearing distinct from omission', async t => {
    const { baseUrl } = await loadTestApp(t);
    const client = createSessionClient(baseUrl);
    await client.setConfig();
    const { requestCalls } = installAxiosCreateMock(t, {
        patch({ url, data }) {
            assert.equal(url, '/idr/v2/investigations/inv-222');
            assert.deepEqual(data, {
                assignee: {
                    email: null
                }
            });

            return {
                data: {
                    updated: 'assignee'
                }
            };
        }
    });

    const response = await client.requestJson('/api/investigations/inv-222', {
        method: 'PATCH',
        body: {
            assignee_email: ''
        }
    });

    assert.equal(response.status, 200);
    assert.deepEqual(response.data, {
        updated: 'assignee'
    });
    assert.deepEqual(requestCalls.map(call => call.method), ['patch']);
});

test('investigation patch sequences general, priority, and closed status updates', async t => {
    const { baseUrl } = await loadTestApp(t);
    const client = createSessionClient(baseUrl);
    await client.setConfig({ region: 'eu' });
    const { createCalls, requestCalls } = installAxiosCreateMock(t, {
        patch({ url, data }) {
            assert.equal(url, '/idr/v2/investigations/inv-333');
            assert.deepEqual(data, {
                title: 'Escalated investigation',
                assignee: {
                    email: null
                }
            });

            return {
                data: {
                    step: 'patch'
                }
            };
        },
        put({ url, data }) {
            if (url === '/idr/v2/investigations/inv-333/priority/HIGH') {
                assert.equal(data, undefined);
                return {
                    data: {
                        step: 'priority'
                    }
                };
            }

            if (url === '/idr/v2/investigations/inv-333/status/CLOSED') {
                assert.deepEqual(data, {
                    disposition: 'BENIGN'
                });
                return {
                    data: {
                        step: 'status'
                    }
                };
            }

            assert.fail(`Unexpected PUT ${url}`);
        }
    });

    const response = await client.requestJson('/api/investigations/inv-333', {
        method: 'PATCH',
        body: {
            title: 'Escalated investigation',
            assignee_email: '',
            priority: 'HIGH',
            status: 'CLOSED',
            disposition: 'BENIGN'
        }
    });

    assert.equal(response.status, 200);
    assert.deepEqual(response.data, {
        step: 'status'
    });
    assert.equal(createCalls[0].baseURL, 'https://eu.api.insight.rapid7.com');
    assert.deepEqual(
        requestCalls.map(call => `${call.method}:${call.url}`),
        [
            'patch:/idr/v2/investigations/inv-333',
            'put:/idr/v2/investigations/inv-333/priority/HIGH',
            'put:/idr/v2/investigations/inv-333/status/CLOSED'
        ]
    );
});

test('investigation patch uses standalone disposition updates when status is omitted', async t => {
    const { baseUrl } = await loadTestApp(t);
    const client = createSessionClient(baseUrl);
    await client.setConfig();
    const { requestCalls } = installAxiosCreateMock(t, {
        put({ url, data }) {
            assert.equal(url, '/idr/v2/investigations/inv-444/disposition/FALSE_POSITIVE');
            assert.equal(data, undefined);

            return {
                data: {
                    updated: 'disposition'
                }
            };
        }
    });

    const response = await client.requestJson('/api/investigations/inv-444', {
        method: 'PATCH',
        body: {
            disposition: 'FALSE_POSITIVE'
        }
    });

    assert.equal(response.status, 200);
    assert.deepEqual(response.data, {
        updated: 'disposition'
    });
    assert.deepEqual(
        requestCalls.map(call => `${call.method}:${call.url}`),
        ['put:/idr/v2/investigations/inv-444/disposition/FALSE_POSITIVE']
    );
});
