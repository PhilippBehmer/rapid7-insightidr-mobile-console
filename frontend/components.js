function getBadgeClass(str) {
  if (!str) return 'badge-outline';
  const val = String(str).toUpperCase();
  if (val === 'CRITICAL') return 'badge-critical';
  if (val === 'HIGH') return 'badge-high';
  if (val === 'MEDIUM') return 'badge-medium';
  if (val === 'LOW') return 'badge-low';
  return 'badge-outline';
}

function getSeverityClass(str) {
  if (!str) return 'severity-neutral';
  const val = String(str).toUpperCase();
  if (val === 'CRITICAL') return 'severity-critical';
  if (val === 'HIGH') return 'severity-high';
  if (val === 'MEDIUM') return 'severity-medium';
  if (val === 'LOW') return 'severity-low';
  return 'severity-neutral';
}

function getStatusClass(str) {
  if (!str) return 'status-open';
  const val = String(str).toUpperCase();
  if (val === 'CLOSED') return 'status-closed';
  if (val === 'INVESTIGATING') return 'status-investigating';
  if (val === 'WAITING') return 'status-waiting';
  if (val === 'MIXED') return 'status-mixed';
  return 'status-open';
}

function formatDate(isoStr) {
  if (!isoStr) return '--';
  const date = new Date(isoStr);
  return date.toLocaleString(undefined, {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  });
}

function formatElapsedDuration(timestamp, now = Date.now()) {
  if (!timestamp) return '--';

  const parsed = Date.parse(timestamp);
  if (Number.isNaN(parsed)) return '--';

  const totalSeconds = Math.max(0, Math.floor((now - parsed) / 1000));
  const days = Math.floor(totalSeconds / 86400);
  const hours = Math.floor((totalSeconds % 86400) / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;

  const segments = [];

  if (days > 0) segments.push(`${days}d`);
  if (days > 0 || hours > 0) segments.push(`${String(hours).padStart(days > 0 ? 2 : 1, '0')}h`);
  if (days > 0 || hours > 0 || minutes > 0) segments.push(`${String(minutes).padStart(days > 0 || hours > 0 ? 2 : 1, '0')}m`);
  segments.push(`${String(seconds).padStart(2, '0')}s`);

  return segments.join(' ');
}

const ALERT_STATUS_OPTIONS = ['UNMAPPED', 'OPEN', 'INVESTIGATING', 'WAITING', 'CLOSED'];
const ALERT_PRIORITY_OPTIONS = ['UNMAPPED', 'INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
const ALERT_DISPOSITION_OPTIONS = [
  'UNMAPPED',
  'BENIGN',
  'SECURITY_TEST',
  'MALICIOUS',
  'FALSE_POSITIVE',
  'UNKNOWN',
  'NOT_APPLICABLE',
  'UNDECIDED'
];
const INVESTIGATION_STATUS_OPTIONS = ['OPEN', 'INVESTIGATING', 'WAITING', 'CLOSED'];
const INVESTIGATION_PRIORITY_OPTIONS = ['UNSPECIFIED', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
const INVESTIGATION_DISPOSITION_OPTIONS = ['BENIGN', 'MALICIOUS', 'NOT_APPLICABLE'];

function getAssigneeValue(assignee) {
  if (!assignee) return '';
  if (typeof assignee === 'string') return assignee;
  return assignee.email || assignee.rrn || assignee.id || '';
}

function getAssigneeLabel(assignee) {
  if (!assignee) return 'Unassigned';
  if (typeof assignee === 'string') return assignee;
  return assignee.name || assignee.email || assignee.rrn || assignee.id || 'Assigned';
}

function renderSelectOptions(options, currentValue, currentLabelSuffix = '') {
  const normalizedCurrent = String(currentValue || '').toUpperCase();
  const values = normalizedCurrent && !options.includes(normalizedCurrent)
    ? [normalizedCurrent, ...options]
    : options;

  return values.map(value => {
    const isCurrentOnly = value === normalizedCurrent && !options.includes(normalizedCurrent);
    const label = isCurrentOnly ? `${value}${currentLabelSuffix}` : value;
    const selected = value === normalizedCurrent ? 'selected' : '';
    return `<option value="${escapeHtml(value)}" ${selected}>${escapeHtml(label)}</option>`;
  }).join('');
}

function renderEmptyState(message, tone = 'idle') {
  return `
    <div class="empty-state ${tone === 'error' ? 'error' : ''}">
      <div class="empty-orb"></div>
      <p>${escapeHtml(message)}</p>
    </div>
  `;
}

function renderAssigneeOptions(analysts, currentValue) {
  const normalizedCurrent = String(currentValue || '').trim().toLowerCase();
  const hasCurrentInList = (analysts || []).some(analyst => {
    const candidateValue = String(analyst.email || analyst.rrn || '').trim().toLowerCase();
    return candidateValue && candidateValue === normalizedCurrent;
  });

  const currentOption = normalizedCurrent && !hasCurrentInList
    ? `<option value="${escapeHtml(currentValue)}" selected>${escapeHtml(currentValue)} (Current)</option>`
    : '';

  return `
    <option value="">Unassigned</option>
    ${currentOption}
    ${(analysts || []).map(analyst => {
      const optionValue = analyst.email || analyst.rrn || '';
      const selected = String(optionValue).trim().toLowerCase() === normalizedCurrent ? 'selected' : '';
      return `<option value="${escapeHtml(optionValue)}" ${selected}>${escapeHtml(analyst.label)}</option>`;
    }).join('')}
  `;
}

function renderAssigneeField({
  fieldId,
  label,
  currentValue,
  analysts = [],
  isLoading = false,
  disabled = false,
  placeholder = 'Search by analyst email'
}) {
  const listId = `${fieldId}Suggestions`;
  return `
    <div class="form-group">
      <label for="${escapeHtml(fieldId)}" class="assignee-label ${isLoading ? 'is-loading' : ''}">
        <span>${escapeHtml(label)}</span>
        <span class="mini-loader-dots" aria-hidden="true">
          <span></span>
          <span></span>
          <span></span>
        </span>
      </label>
      <input
        id="${escapeHtml(fieldId)}"
        class="control-input"
        list="${escapeHtml(listId)}"
        value="${escapeHtml(currentValue || '')}"
        placeholder="${escapeHtml(placeholder)}"
        autocomplete="off"
        ${disabled ? 'disabled' : ''}
      />
      <datalist id="${escapeHtml(listId)}">
        ${(analysts || []).map(analyst => `
          <option value="${escapeHtml(analyst.value || analyst.email || analyst.rrn || '')}" label="${escapeHtml(analyst.label || analyst.value || '')}"></option>
        `).join('')}
      </datalist>
    </div>
  `;
}

function renderCopyButton(label) {
  const safeLabel = escapeHtml(label);
  return `
    <button
      type="button"
      class="copy-btn"
      aria-label="Copy ${safeLabel}"
      title="Copy ${safeLabel}"
    >
      <span class="copy-btn-icon copy-btn-icon-default" aria-hidden="true">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8">
          <rect x="9" y="9" width="11" height="11" rx="2"></rect>
          <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
        </svg>
      </span>
      <span class="copy-btn-icon copy-btn-icon-success" aria-hidden="true">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M20 6 9 17l-5-5"></path>
        </svg>
      </span>
    </button>
  `;
}

function renderInlineLoader(isVisible = false, className = '') {
  const classes = ['mini-loader-dots', 'inline-loader', className].filter(Boolean).join(' ');
  return `
    <span class="${classes}" aria-hidden="true"${isVisible ? '' : ' hidden'}>
      <span></span>
      <span></span>
      <span></span>
    </span>
  `;
}

function sanitizeExternalUrl(value) {
  const normalized = String(value || '').trim();
  if (!normalized) return '';

  try {
    const parsed = new URL(normalized, window.location.origin);
    if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
      return parsed.href;
    }
  } catch (error) {
    return '';
  }

  return '';
}

function renderExternalPivotButton({ href, label, title, text = 'Open' }) {
  const safeHref = sanitizeExternalUrl(href);
  if (!safeHref) return '';

  return `
    <a
      class="pivot-btn"
      href="${escapeHtml(safeHref)}"
      target="_blank"
      rel="noopener noreferrer"
      aria-label="${escapeHtml(title || label)}"
      title="${escapeHtml(title || label)}"
    >
      <span class="pivot-btn-label">${escapeHtml(text)}</span>
      <span class="pivot-btn-icon" aria-hidden="true">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9">
          <path d="M14 5h5v5"></path>
          <path d="M10 14 19 5"></path>
          <path d="M19 14v4a1 1 0 0 1-1 1H6a1 1 0 0 1-1-1V6a1 1 0 0 1 1-1h4"></path>
        </svg>
      </span>
    </a>
  `;
}

function escapeHtml(value) {
  return String(value || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function isCommandLineLabel(label) {
  return /(^|[\s._-])(cmdline|commandline|command line)([\s._-]|$)/i.test(String(label || ''));
}

function valueLooksLikeCommandLine(value) {
  const normalized = String(value || '');
  if (!normalized) return false;

  return (
    /(?:^|[\s"'`])(?:powershell|pwsh|cmd(?:\.exe)?|bash|sh)(?:[\s"'`]|$)/i.test(normalized)
    || /(?:^|\s)(?:\/c|\/k|-c|-command|-encodedcommand|-enc|-ec|-e)\b/i.test(normalized)
    || /frombase64string\s*\(/i.test(normalized)
  );
}

function normalizeBase64Token(token) {
  return String(token || '')
    .trim()
    .replace(/^[("'`]+/, '')
    .replace(/[)"'`,;]+$/, '')
    .replace(/\s+/g, '')
    .replace(/-/g, '+')
    .replace(/_/g, '/');
}

function decodeBase64Bytes(token) {
  const normalized = normalizeBase64Token(token);
  if (!normalized || normalized.length < 16 || normalized.length > 8192) return null;
  if (/[^A-Za-z0-9+/=]/.test(normalized) || normalized.length % 4 === 1) return null;

  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '=');

  try {
    const binary = atob(padded);
    return Uint8Array.from(binary, char => char.charCodeAt(0));
  } catch (error) {
    return null;
  }
}

function decodeBytesAsText(bytes, encoding) {
  if (!(bytes instanceof Uint8Array) || bytes.length === 0) return '';

  try {
    const normalizedBytes = encoding === 'utf-16le' && bytes.length % 2 === 1
      ? bytes.slice(0, -1)
      : bytes;

    if (normalizedBytes.length === 0) return '';

    return new TextDecoder(encoding, { fatal: false })
      .decode(normalizedBytes)
      .replace(/\u0000/g, '');
  } catch (error) {
    return '';
  }
}

function scoreDecodedCommandText(text) {
  const normalized = String(text || '').replace(/\u0000/g, '');
  const trimmed = normalized.trim();

  if (!trimmed || trimmed.length < 4) return 0;

  const printableChars = trimmed.match(/[\t\n\r\x20-\x7E]/g) || [];
  const printableRatio = printableChars.length / trimmed.length;
  const scriptBonus = /(?:powershell|pwsh|cmd(?:\.exe)?|iex\b|invoke-|new-object|frombase64string|http[s]?:\/\/|\/bin\/(?:sh|bash)|bash\b|curl\b|wget\b|chmod\b)/i.test(trimmed)
    ? 0.2
    : 0;
  const whitespaceBonus = /\s/.test(trimmed) ? 0.05 : 0;

  return printableRatio + scriptBonus + whitespaceBonus;
}

function decodeBase64Token(token, preferredEncoding = null) {
  const bytes = decodeBase64Bytes(token);
  if (!bytes) return null;

  const candidates = [
    { encoding: 'utf-8', text: decodeBytesAsText(bytes, 'utf-8') },
    { encoding: 'utf-16le', text: decodeBytesAsText(bytes, 'utf-16le') }
  ];

  let bestMatch = null;

  candidates.forEach(candidate => {
    const text = String(candidate.text || '').trim();
    if (!text) return;

    const score = scoreDecodedCommandText(text) + (candidate.encoding === preferredEncoding ? 0.08 : 0);
    if (!bestMatch || score > bestMatch.score) {
      bestMatch = {
        decoded: text,
        encoding: candidate.encoding,
        score
      };
    }
  });

  if (!bestMatch || bestMatch.score < 0.85) {
    return null;
  }

  return {
    decoded: bestMatch.decoded,
    encoding: bestMatch.encoding
  };
}

function collectDecodedCommandSegments(commandLine) {
  const source = String(commandLine || '');
  if (!source) return [];

  const preferredEncoding = /(?:^|\s)(?:powershell|pwsh)(?:\.exe)?\b/i.test(source)
    ? 'utf-16le'
    : null;
  const matches = [];
  const seenTokens = new Set();

  const addMatch = (candidate, reason) => {
    const normalized = normalizeBase64Token(candidate);
    if (!normalized || seenTokens.has(normalized)) return;

    const decoded = decodeBase64Token(normalized, preferredEncoding);
    if (!decoded) return;

    seenTokens.add(normalized);
    matches.push({
      ...decoded,
      encoded: normalized,
      preview: normalized.length > 64 ? `${normalized.slice(0, 64)}...` : normalized,
      reason
    });
  };

  Array.from(source.matchAll(/frombase64string\(\s*['"`]?([A-Za-z0-9+/_=-]{16,})['"`]?\s*\)/ig))
    .forEach(match => addMatch(match[1], 'fromBase64String'));

  Array.from(source.matchAll(/(?:^|\s)(?:-e|-ec|-enc|-encodedcommand)\s+("[^"]+"|'[^']+'|`[^`]+`|[A-Za-z0-9+/_=-]{16,})/ig))
    .forEach(match => addMatch(match[1], 'encodedCommand'));

  Array.from(source.matchAll(/(?:^|[\s"'`=:([])([A-Za-z0-9+/_-]{20,}={0,2})(?=$|[\s"'`),;\]])/g))
    .forEach(match => addMatch(match[1], 'inlineToken'));

  return matches.slice(0, 3);
}

function renderDecodedCommandPanels(commandLine, label = 'Command line') {
  const decodedSegments = collectDecodedCommandSegments(commandLine);
  if (decodedSegments.length === 0) return '';

  return `
    <div class="decoded-command-list">
      ${decodedSegments.map((segment, index) => `
        <section class="decoded-command-panel">
          <div class="decoded-command-heading">
            <span class="meta-label">Decoded Base64${decodedSegments.length > 1 ? ` ${index + 1}` : ''}</span>
            <span class="decoded-command-chip">${segment.encoding.toUpperCase()}</span>
          </div>
          ${renderCopyableCodePanel(segment.decoded, `${label} decoded${decodedSegments.length > 1 ? ` ${index + 1}` : ''}`)}
          <p class="decoded-command-caption">
            Fragment:
            <code>${escapeHtml(segment.preview)}</code>
          </p>
        </section>
      `).join('')}
    </div>
  `;
}

function renderPlainEntityMeta(label, value, options = {}) {
  const { className = '' } = options;
  const safeValue = value !== undefined && value !== null && value !== '' ? value : 'N/A';
  const metaRowClass = ['meta-row', className].filter(Boolean).join(' ');
  return `
    <div class="${metaRowClass}">
      ${renderCopyButton(label)}
      <span class="meta-label">${escapeHtml(label)}</span>
      <span class="meta-value copy-source">${escapeHtml(String(safeValue))}</span>
    </div>
  `;
}

function renderTrustedHtmlMeta(label, html, options = {}) {
  const { className = '' } = options;
  const safeValue = html !== undefined && html !== null && html !== '' ? html : 'N/A';
  const metaRowClass = ['meta-row', className].filter(Boolean).join(' ');

  return `
    <div class="${metaRowClass}">
      ${renderCopyButton(label)}
      <span class="meta-label">${escapeHtml(label)}</span>
      <span class="meta-value copy-source">${String(safeValue)}</span>
    </div>
  `;
}

function renderCommandLineMeta(label, value, options = {}) {
  const { className = '' } = options;
  const safeValue = value !== undefined && value !== null && value !== '' ? String(value) : 'N/A';
  const stackClass = ['meta-stack', className].filter(Boolean).join(' ');

  return `
    <div class="${stackClass}">
      <div class="meta-row">
        ${renderCopyButton(label)}
        <span class="meta-label">${escapeHtml(label)}</span>
        <pre class="meta-value meta-code-value copy-source">${escapeHtml(safeValue)}</pre>
      </div>
      ${renderDecodedCommandPanels(safeValue, label)}
    </div>
  `;
}

function renderEntityMeta(label, value, options = {}) {
  if (
    (isCommandLineLabel(label) || valueLooksLikeCommandLine(value))
    && (typeof value === 'string' || typeof value === 'number')
  ) {
    return renderCommandLineMeta(label, value, options);
  }

  return renderPlainEntityMeta(label, value, options);
}

function getInteractiveCardAttributes(label) {
  const safeLabel = escapeHtml(label || 'Open details');
  return `
      role="button"
      tabindex="0"
      aria-haspopup="dialog"
      aria-label="${safeLabel}"
  `;
}

function isIpv4(value) {
  const candidate = String(value || '').trim();
  if (!/^(?:\d{1,3}\.){3}\d{1,3}$/.test(candidate)) return false;

  return candidate.split('.').every(part => {
    const parsed = Number(part);
    return parsed >= 0 && parsed <= 255;
  });
}

function isIpv6(value) {
  const candidate = String(value || '').trim();
  if (!candidate.includes(':')) return false;
  return /^[0-9a-f:]+$/i.test(candidate);
}

function looksLikeIp(value) {
  return isIpv4(value) || isIpv6(value);
}

function looksLikeDomain(value) {
  const candidate = String(value || '').trim().toLowerCase();
  if (!candidate || candidate.includes(' ')) return false;
  if (candidate.includes('://') || candidate.includes('/') || candidate.includes('@')) return false;
  if (looksLikeIp(candidate)) return false;
  if (candidate.endsWith('.local')) return false;

  return /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(candidate);
}

function looksLikeHash(value) {
  return /^(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})$/.test(String(value || '').trim());
}

function looksLikeUrl(value) {
  const candidate = String(value || '').trim();
  if (!/^https?:\/\//i.test(candidate)) return false;

  try {
    const parsed = new URL(candidate);
    return Boolean(parsed.hostname);
  } catch (error) {
    return false;
  }
}

function normalizeIndicatorValue(value, type) {
  const candidate = String(value || '').trim();
  if (!candidate) return '';

  if (type === 'hash') return candidate.toLowerCase();
  if (type === 'domain') return candidate.toLowerCase();
  if (type === 'ip') return candidate.toLowerCase();
  return candidate;
}

function buildVirusTotalUrlId(value) {
  const bytes = new TextEncoder().encode(String(value || ''));
  let binary = '';

  bytes.forEach(byte => {
    binary += String.fromCharCode(byte);
  });

  return btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

function buildVirusTotalHref(type, value) {
  const normalizedValue = normalizeIndicatorValue(value, type);
  if (!normalizedValue) return '';

  if (type === 'hash') {
    return `https://www.virustotal.com/gui/file/${encodeURIComponent(normalizedValue)}`;
  }

  if (type === 'domain') {
    return `https://www.virustotal.com/gui/domain/${encodeURIComponent(normalizedValue)}`;
  }

  if (type === 'ip') {
    return `https://www.virustotal.com/gui/ip-address/${encodeURIComponent(normalizedValue)}`;
  }

  if (type === 'url') {
    return `https://www.virustotal.com/gui/url/${buildVirusTotalUrlId(normalizedValue)}`;
  }

  return '';
}

function buildGreyNoiseHref(type, value) {
  const normalizedValue = normalizeIndicatorValue(value, type);
  if (type !== 'ip' || !normalizedValue) return '';

  return `https://viz.greynoise.io/ip/${encodeURIComponent(normalizedValue)}`;
}

function buildShodanHref(type, value) {
  const normalizedValue = normalizeIndicatorValue(value, type);
  if (!normalizedValue) return '';

  if (type === 'ip') {
    return `https://www.shodan.io/host/${encodeURIComponent(normalizedValue)}`;
  }

  if (type === 'domain') {
    return `https://www.shodan.io/search?query=${encodeURIComponent(normalizedValue)}`;
  }

  return '';
}

function createIndicatorCollector(limit = 18) {
  const items = [];
  const seen = new Set();

  return {
    add(type, value, source) {
      if (items.length >= limit) return;

      const normalizedValue = normalizeIndicatorValue(value, type);
      if (!normalizedValue) return;

      const key = `${type}:${normalizedValue}`;
      if (seen.has(key)) return;

      seen.add(key);
      items.push({
        type,
        value: normalizedValue,
        source: source || null
      });
    },
    list() {
      return items;
    }
  };
}

function collectIndicatorsFromText(value, collector, source) {
  const text = String(value || '');
  if (!text) return;

  Array.from(text.matchAll(/\bhttps?:\/\/[^\s<>"'`]+/gi))
    .forEach(match => collector.add('url', match[0], source));

  Array.from(text.matchAll(/\b(?:[A-Fa-f0-9]{64}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{32})\b/g))
    .forEach(match => collector.add('hash', match[0], source));

  Array.from(text.matchAll(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g))
    .forEach(match => {
      if (isIpv4(match[0])) {
        collector.add('ip', match[0], source);
      }
    });

  Array.from(text.matchAll(/\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b/gi))
    .forEach(match => {
      const domain = String(match[0] || '').toLowerCase();
      if (looksLikeDomain(domain)) {
        collector.add('domain', domain, source);
      }
    });
}

function collectIndicatorsFromValue(value, collector, source, depth = 0) {
  if (value === null || value === undefined || depth > 4) return;

  if (typeof value === 'string' || typeof value === 'number') {
    const scalar = String(value).trim();
    if (!scalar) return;

    if (looksLikeUrl(scalar)) collector.add('url', scalar, source);
    if (looksLikeHash(scalar)) collector.add('hash', scalar, source);
    if (looksLikeIp(scalar)) collector.add('ip', scalar, source);
    if (looksLikeDomain(scalar)) collector.add('domain', scalar, source);
    collectIndicatorsFromText(scalar, collector, source);
    return;
  }

  if (Array.isArray(value)) {
    value.forEach(entry => collectIndicatorsFromValue(entry, collector, source, depth + 1));
    return;
  }

  if (typeof value === 'object') {
    Object.values(value).forEach(entry => collectIndicatorsFromValue(entry, collector, source, depth + 1));
  }
}

function getIndicatorTypeLabel(type) {
  if (type === 'hash') return 'Hash';
  if (type === 'domain') return 'Domain';
  if (type === 'ip') return 'IP';
  if (type === 'url') return 'URL';
  return 'Indicator';
}

function getIndicatorSourceLabel(source) {
  if (source === 'process') return 'Process tree';
  if (source === 'actor') return 'Actor';
  if (source === 'evidence') return 'Evidence';
  if (source === 'alert') return 'Alert';
  return 'Observed';
}

function collectAlertIndicators(alert) {
  const collector = createIndicatorCollector();

  collectIndicatorsFromValue(alert?.rule_matching_keys, collector, 'alert');
  collectIndicatorsFromValue(alert?.description, collector, 'alert');
  collectIndicatorsFromValue(alert?.title, collector, 'alert');

  (alert?._actors || []).forEach(actor => {
    collectIndicatorsFromValue(actor?.name, collector, 'actor');
    collectIndicatorsFromValue(actor?.domain, collector, 'actor');
    collectIndicatorsFromValue(actor?.raw, collector, 'actor');
  });

  (alert?._processTrees || []).forEach(tree => {
    const root = tree?.process_tree || {};
    const hashes = root.hashes || {};
    ['sha256', 'sha1', 'md5'].forEach(hashType => collectIndicatorsFromValue(hashes[hashType], collector, 'process'));
    collectIndicatorsFromValue(root?.cmdline, collector, 'process');
    collectIndicatorsFromValue(root?.name, collector, 'process');
  });

  (alert?._evidences || []).forEach(evidence => {
    collectIndicatorsFromValue(evidence?.description, collector, 'evidence');
    collectIndicatorsFromValue(evidence?.rule_matching_keys, collector, 'evidence');
    collectIndicatorsFromValue(evidence?.data, collector, 'evidence');
    collectIndicatorsFromValue(evidence?.log_details, collector, 'evidence');
  });

  return collector.list();
}

function getIndicatorPivotActions(indicator) {
  const actions = [];
  const virusTotalHref = buildVirusTotalHref(indicator.type, indicator.value);
  const greyNoiseHref = buildGreyNoiseHref(indicator.type, indicator.value);
  const shodanHref = buildShodanHref(indicator.type, indicator.value);

  if (virusTotalHref) {
    actions.push({
      href: virusTotalHref,
      label: `Open ${indicator.value} in VirusTotal`,
      title: `Open ${indicator.value} in VirusTotal`,
      text: 'VirusTotal'
    });
  }

  if (greyNoiseHref) {
    actions.push({
      href: greyNoiseHref,
      label: `Open ${indicator.value} in GreyNoise`,
      title: `Open ${indicator.value} in GreyNoise`,
      text: 'GreyNoise'
    });
  }

  if (shodanHref) {
    actions.push({
      href: shodanHref,
      label: `Open ${indicator.value} in Shodan`,
      title: `Open ${indicator.value} in Shodan`,
      text: 'Shodan'
    });
  }

  return actions;
}

function renderIndicatorPivots(alert) {
  const indicators = collectAlertIndicators(alert);
  if (indicators.length === 0) {
    return '<p class="detail-empty">No public enrichment indicators were found in this alert detail.</p>';
  }

  return `
    <div class="vt-pivot-grid">
      ${indicators.map(indicator => `
        <article class="vt-pivot-card">
          <div class="card-topline">
            <span class="badge badge-outline">${getIndicatorTypeLabel(indicator.type)}</span>
            <span class="card-chip">${getIndicatorSourceLabel(indicator.source)}</span>
          </div>
          <p class="vt-pivot-value">${escapeHtml(indicator.value)}</p>
          <div class="vt-pivot-actions">
            ${getIndicatorPivotActions(indicator).map(action => renderExternalPivotButton(action)).join('')}
          </div>
        </article>
      `).join('')}
    </div>
  `;
}

function formatLabel(value) {
  return String(value || '')
    .replace(/_/g, ' ')
    .replace(/\b\w/g, char => char.toUpperCase());
}

function formatDuration(seconds) {
  if (seconds === null || seconds === undefined || Number.isNaN(Number(seconds))) return null;

  const totalSeconds = Math.max(0, Math.round(Number(seconds)));
  const days = Math.floor(totalSeconds / 86400);
  const hours = Math.floor((totalSeconds % 86400) / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);

  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${minutes}m`;
  if (minutes > 0) return `${minutes}m`;
  return `${totalSeconds}s`;
}

function formatScalar(value) {
  if (value === null || value === undefined || value === '') return null;
  if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
    return String(value);
  }
  if (Array.isArray(value)) {
    return value.length > 0 ? value.join(', ') : null;
  }
  if (typeof value === 'object') {
    return value.name || value.label || value.value || JSON.stringify(value);
  }
  return String(value);
}

function normalizeKeyValueEntries(entries) {
  if (!Array.isArray(entries)) return [];

  return entries
    .map(entry => {
      if (entry && typeof entry === 'object' && !Array.isArray(entry)) {
        const key = entry.key || entry.name || entry.label || null;
        const values = Array.isArray(entry.values)
          ? entry.values.filter(Boolean).join(', ')
          : formatScalar(entry.value || entry.values);

        if (!key && !values) return null;
        return {
          label: key ? formatLabel(key) : 'Value',
          value: values || 'Present'
        };
      }

      const scalar = formatScalar(entry);
      return scalar ? { label: 'Value', value: scalar } : null;
    })
    .filter(Boolean);
}

function renderEntryGrid(entries, emptyMessage = 'No analyst context available.', options = {}) {
  const normalizedEntries = (entries || [])
    .filter(entry => entry && entry.value !== null && entry.value !== undefined && entry.value !== '');

  if (normalizedEntries.length === 0) {
    return emptyMessage ? `<p class="detail-empty">${emptyMessage}</p>` : '';
  }

  return renderMetaGrid(normalizedEntries, options);
}

function renderBadgeStack(items, emptyMessage = 'No indicators available.') {
  const normalizedItems = (items || []).filter(Boolean);

  if (normalizedItems.length === 0) {
    return emptyMessage ? `<p class="detail-empty">${emptyMessage}</p>` : '';
  }

  return `
    <div class="badge-row">
      ${normalizedItems.map(item => `<span class="badge badge-outline">${escapeHtml(item)}</span>`).join('')}
    </div>
  `;
}

function safeDisplayString(value) {
  try {
    return getDisplayName(value);
  } catch (error) {
    return '';
  }
}

function getCampaignLabel(campaign) {
  try {
    if (!campaign) return '';
    if (typeof campaign === 'string') return campaign.trim();

    if (typeof campaign !== 'object') {
      return String(campaign).trim();
    }

    const primaryKeys = [
      'display_name',
      'displayName',
      'name',
      'campaign_name',
      'campaignName',
      'label',
      'title',
      'value',
      'key',
      'id'
    ];

    for (const key of primaryKeys) {
      const label = safeDisplayString(campaign[key]);
      if (label) {
        return label;
      }
    }

    const nestedKeys = ['campaign', 'related_campaign', 'details'];
    for (const key of nestedKeys) {
      const label = safeDisplayString(campaign[key]);
      if (label) {
        return label;
      }
    }

    return safeDisplayString(campaign.cause);
  } catch (error) {
    return '';
  }
}

function getCampaignLabels(campaigns) {
  let normalizedCampaigns = [];

  try {
    if (Array.isArray(campaigns)) {
      normalizedCampaigns = campaigns;
    } else if (Array.isArray(campaigns?.data)) {
      normalizedCampaigns = campaigns.data;
    } else if (Array.isArray(campaigns?.campaigns)) {
      normalizedCampaigns = campaigns.campaigns;
    } else if (
      campaigns
      && typeof campaigns !== 'string'
      && typeof campaigns[Symbol.iterator] === 'function'
    ) {
      normalizedCampaigns = Array.from(campaigns);
    } else if (campaigns) {
      normalizedCampaigns = [campaigns];
    }
  } catch (error) {
    normalizedCampaigns = [];
  }

  return Array.from(new Set(
    normalizedCampaigns
      .map(getCampaignLabel)
      .map(label => String(label || '').trim())
      .filter(Boolean)
  ));
}

function formatBytes(value) {
  const bytes = Number(value);
  if (!Number.isFinite(bytes) || bytes < 0) return '--';
  if (bytes < 1024) return `${bytes} B`;

  const units = ['KB', 'MB', 'GB', 'TB'];
  let size = bytes / 1024;
  let unitIndex = 0;

  while (size >= 1024 && unitIndex < units.length - 1) {
    size /= 1024;
    unitIndex += 1;
  }

  return `${size.toFixed(size >= 10 ? 0 : 1)} ${units[unitIndex]}`;
}

function renderMultilineText(value) {
  return escapeHtml(value).replace(/\n/g, '<br />');
}

function getCreatorLabel(creator) {
  if (!creator || typeof creator !== 'object') return 'Unknown creator';

  const name = String(creator.name || '').trim();
  const type = String(creator.type || '').trim();
  if (name && type) return `${name} (${type})`;
  return name || type || 'Unknown creator';
}

function buildAttachmentDownloadHref(rrn) {
  if (!rrn) return '';
  return `/api/attachments/${encodeURIComponent(rrn)}/download`;
}

function renderAttachmentList(attachments, options = {}) {
  const { emptyMessage = 'No attachments were returned for this investigation.' } = options;

  if (!attachments || attachments.length === 0) {
    return emptyMessage ? `<p class="detail-empty">${emptyMessage}</p>` : '';
  }

  const sortedAttachments = [...attachments].sort((a, b) => (
    new Date(b.created_time || 0) - new Date(a.created_time || 0)
  ));

  return `
    <div class="attachment-list">
      ${sortedAttachments.map(attachment => `
        <article class="attachment-card">
          <div class="attachment-header">
            <div>
              <h4 class="attachment-title">${escapeHtml(attachment.file_name || 'Attachment')}</h4>
              <p class="attachment-meta">${escapeHtml(getCreatorLabel(attachment.creator))}</p>
            </div>
            <span class="badge badge-outline">${escapeHtml(attachment.scan_status || 'UNKNOWN')}</span>
          </div>
          <div class="attachment-facts">
            <span>${escapeHtml(formatBytes(attachment.size))}</span>
            <span>${escapeHtml(attachment.mime_type || 'Unknown type')}</span>
            <span>${escapeHtml(formatDate(attachment.created_time))}</span>
          </div>
          <div class="attachment-actions">
            <a class="pivot-btn" href="${buildAttachmentDownloadHref(attachment.rrn)}" target="_blank" rel="noopener noreferrer">
              <span class="pivot-btn-label">Download</span>
              <span class="pivot-btn-icon" aria-hidden="true">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9">
                  <path d="M12 3v11"></path>
                  <path d="m7 11 5 5 5-5"></path>
                  <path d="M5 21h14"></path>
                </svg>
              </span>
            </a>
          </div>
        </article>
      `).join('')}
    </div>
  `;
}

function renderCommentList(comments) {
  if (!comments || comments.length === 0) {
    return '<p class="detail-empty">No comments have been added to this investigation yet.</p>';
  }

  const sortedComments = [...comments].sort((a, b) => (
    new Date(b.created_time || 0) - new Date(a.created_time || 0)
  ));

  return `
    <div class="comment-list">
      ${sortedComments.map(comment => `
        <article class="comment-card">
          <div class="comment-header">
            <div>
              <h4 class="comment-title">${escapeHtml(getCreatorLabel(comment.creator))}</h4>
              <p class="comment-meta">${escapeHtml(formatDate(comment.created_time))}</p>
            </div>
            <span class="badge badge-outline">${escapeHtml(comment.visibility || 'VISIBLE')}</span>
          </div>
          ${comment.body
            ? `<p class="comment-body">${renderMultilineText(comment.body)}</p>`
            : '<p class="comment-body comment-body-empty">Attachment-only comment</p>'}
          ${(comment.attachments || []).length > 0
            ? `
              <div class="comment-attachments">
                <p class="comment-attachments-label">Linked files</p>
                ${renderAttachmentList(comment.attachments, { emptyMessage: '' })}
              </div>
            `
            : ''}
        </article>
      `).join('')}
    </div>
  `;
}

function renderInvestigationCommentComposer() {
  return `
    <form id="createInvestigationCommentForm" class="glass-panel detail-form">
      <div class="section-heading">
        <p class="eyebrow">Collaboration</p>
        <h3>Add comment</h3>
      </div>
      <div class="form-group">
        <label for="investigationCommentBody">Comment</label>
        <textarea
          id="investigationCommentBody"
          class="control-input control-textarea"
          rows="5"
          placeholder="Add analyst notes, case updates, or next-step guidance"
        ></textarea>
      </div>
      <div class="form-group">
        <label for="investigationCommentAttachments">Attachments</label>
        <input
          id="investigationCommentAttachments"
          type="file"
          class="control-input control-file"
          multiple
        />
        <p class="form-hint">Selected files upload first, then the new comment links them to this investigation.</p>
      </div>
      <button class="btn mt-4" type="submit">Post Comment</button>
    </form>
  `;
}

function isAdaptiveCompactMetaLabel(normalizedLabel) {
  return (
    normalizedLabel === 'alerted'
    || normalizedLabel === 'ingested'
    || normalizedLabel === 'updated'
    || normalizedLabel === 'ai suggested disposition'
    || normalizedLabel === 'ai disposition'
    || normalizedLabel === 'model type'
    || normalizedLabel === 'model version'
    || normalizedLabel === 'executable name'
    || normalizedLabel === 'child'
    || normalizedLabel === 'hostname'
    || normalizedLabel === 'os type'
    || normalizedLabel === 'event source'
    || normalizedLabel === 'event source lookup'
    || normalizedLabel === 'event type'
    || normalizedLabel === 'time to investigate'
    || normalizedLabel === 'time to close'
    || normalizedLabel === 'user'
    || normalizedLabel === 'username'
    || normalizedLabel.endsWith('.name')
    || normalizedLabel.endsWith(' name')
    || normalizedLabel.endsWith('.md5')
    || normalizedLabel.endsWith(' md5')
    || normalizedLabel.endsWith('.sha1')
    || normalizedLabel.endsWith(' sha1')
    || normalizedLabel.endsWith('.pid')
    || normalizedLabel.endsWith(' pid')
    || normalizedLabel.endsWith('.id')
    || normalizedLabel.endsWith(' id')
    || normalizedLabel.endsWith(' version')
    || normalizedLabel.endsWith(' type')
  );
}

function getAdaptiveMetaRowClass(entry, options = {}) {
  const compactLabels = new Set(
    Array.isArray(options.compactLabels)
      ? options.compactLabels
        .map(label => String(label || '').trim().toLowerCase())
        .filter(Boolean)
      : []
  );
  const preferCompact = Boolean(options.preferCompact);
  const label = String(entry?.label || '').trim();
  const value = String(entry?.value || '').trim();
  const normalizedLabel = label.toLowerCase();
  const tokens = value.split(/\s+/).filter(Boolean);
  const longestToken = tokens.reduce((max, token) => Math.max(max, token.length), 0);
  const valueLength = value.length;

  if (
    normalizedLabel.includes('cmdline')
    || normalizedLabel.includes('path')
    || value.includes('\n')
    || valueLength > 80
    || longestToken > 48
  ) {
    return 'meta-row-full';
  }

  if (compactLabels.has(normalizedLabel)) {
    return 'meta-row-compact';
  }

  if (
    preferCompact
    && valueLength <= 48
    && longestToken <= 28
    && tokens.length <= 6
  ) {
    return 'meta-row-compact';
  }

  if (isAdaptiveCompactMetaLabel(normalizedLabel)) {
    return 'meta-row-compact';
  }

  return 'meta-row-full';
}

function renderMetaGrid(entries, options = {}) {
  const isAdaptiveLayout = options.layout === 'adaptive';
  const gridClass = [
    isAdaptiveLayout
      ? 'detail-grid detail-grid-adaptive'
      : 'detail-grid',
    String(options.gridClassName || '').trim()
  ].filter(Boolean).join(' ');

  return `
    <div class="${gridClass}">
      ${entries.map(entry => renderEntityMeta(
        entry.label,
        entry.value,
        isAdaptiveLayout
          ? { className: getAdaptiveMetaRowClass(entry, options) }
          : {}
      )).join('')}
    </div>
  `;
}

function renderKeyValuePanel(entries, emptyMessage, options = {}) {
  const normalizedEntries = normalizeKeyValueEntries(entries);

  if (normalizedEntries.length === 0) {
    return `<p class="detail-empty">${emptyMessage}</p>`;
  }

  return renderMetaGrid(normalizedEntries, options);
}

function renderDetailError(message, fallbackMessage = 'This section is temporarily unavailable.') {
  const detailMessage = String(message || '').trim() || fallbackMessage;
  return `<p class="detail-empty error-state">${escapeHtml(detailMessage)}</p>`;
}

function renderDetailLoading(message = 'Loading details...') {
  return `<p class="detail-empty">${escapeHtml(message)}</p>`;
}

function formatLoadAwareCount(items, isLoading = false) {
  if (isLoading && (!Array.isArray(items) || items.length === 0)) {
    return 'Loading';
  }

  return String((items || []).length);
}

function renderAlertEventSourceMeta(alert, rawEventSource, resolvedEventSource) {
  const eventSourceRrn = String(alert?.triggering_event_source || '').trim();
  const displayedValue = resolvedEventSource || rawEventSource || 'N/A';
  const showEventSourceRrn = Boolean(
    eventSourceRrn
    && resolvedEventSource
    && resolvedEventSource !== eventSourceRrn
  );

  return `
    <div class="detail-grid detail-grid-adaptive">
      <div class="meta-row meta-row-compact">
        ${renderCopyButton('Event Source')}
        <span class="meta-label">Event Source</span>
        <span class="meta-value copy-source">
          <span
            class="js-alert-event-source-value"
            data-event-source-rrn="${escapeHtml(eventSourceRrn)}"
            data-fallback-value="${escapeHtml(rawEventSource || 'N/A')}"
          >${escapeHtml(displayedValue)}</span>
          ${renderInlineLoader(Boolean(alert?._eventSourceLoading), 'js-alert-event-source-loader')}
        </span>
      </div>
      ${eventSourceRrn ? `
        <div class="meta-row meta-row-compact js-alert-event-source-rrn-row"${showEventSourceRrn ? '' : ' hidden'}>
          ${renderCopyButton('Event Source RRN')}
          <span class="meta-label">Event Source RRN</span>
          <span class="meta-value copy-source">${escapeHtml(eventSourceRrn)}</span>
        </div>
      ` : ''}
    </div>
  `;
}

function renderLogDetails(logDetails = []) {
  const normalizedLogDetails = (logDetails || []).slice(0, 6);

  if (!normalizedLogDetails.length) {
    return '<p class="detail-empty">No direct log pivot identifiers were returned.</p>';
  }

  return `
    <div class="detail-panel">
      ${normalizedLogDetails.map((detail, index) => `
        <div class="meta-row">
          <span class="meta-label">Log Ref ${index + 1}</span>
          <span class="meta-value">
            ${escapeHtml((detail.log_entry_id || detail.log_id || 'Unknown log').toString())}
            ${detail.logset_id ? `
              <br />
              <span class="logset-resolve ${detail._logsetLoading ? 'is-loading' : ''}" data-logset-id="${escapeHtml(detail.logset_id)}">
                <small class="js-logset-label">Logset: ${escapeHtml(detail._logsetName || detail.logset_id)}</small>
                ${renderInlineLoader(Boolean(detail._logsetLoading), 'js-logset-loader')}
              </span>
            ` : ''}
            ${detail.log_timestamp ? `<br /><small>Timestamp: ${formatDate(detail.log_timestamp)}</small>` : ''}
          </span>
        </div>
      `).join('')}
    </div>
  `;
}

function countProcessTreeChildren(node) {
  if (!node || !Array.isArray(node.children) || node.children.length === 0) return 0;
  return node.children.reduce((total, child) => total + 1 + countProcessTreeChildren(child), 0);
}

function renderProcessTrees(processTrees = []) {
  if (!Array.isArray(processTrees) || processTrees.length === 0) {
    return '<p class="detail-empty">No process trees were returned for this alert.</p>';
  }

  return `
    <div class="related-alert-list">
      ${processTrees.map(tree => {
        const root = tree.process_tree || {};
        const hashes = root.hashes || {};
        const childCount = countProcessTreeChildren(root);
        const hashPreview = hashes.sha256 || hashes.sha1 || hashes.md5 || null;

        return `
          <article class="related-alert-item card severity-neutral">
            <div class="card-topline">
              <span class="badge badge-outline">Process Tree</span>
              <span class="card-timestamp">${formatDate(tree.updated_at || tree.created_at)}</span>
            </div>
            <h4 class="related-alert-title">${escapeHtml(root.name || 'Unknown Process')}</h4>
            <pre class="related-alert-summary related-alert-command">${escapeHtml(root.cmdline || 'No command line returned.')}</pre>
            ${root.cmdline ? renderDecodedCommandPanels(root.cmdline, `${root.name || 'Process'} command line`) : ''}
            <div class="detail-grid compact-grid">
              ${renderEntityMeta('User', root.username || 'Unknown')}
              ${renderEntityMeta('PID', root.pid || 'N/A')}
              ${renderEntityMeta('Started', formatDate(root.start_time))}
              ${renderEntityMeta('Child Processes', String(childCount))}
              ${hashPreview ? renderEntityMeta('Hash', hashPreview) : ''}
            </div>
          </article>
        `;
      }).join('')}
    </div>
  `;
}

function renderLinkedInvestigationCard(investigation, fallbackRrn, options = {}) {
  const { compact = false } = options;
  const investigationRef = investigation?.rrn || fallbackRrn;
  if (!investigationRef) {
    return '<p class="detail-empty">This alert is not currently linked to an investigation.</p>';
  }

  const cardClasses = [
    'related-alert-item',
    'card',
    getSeverityClass(investigation?.priority),
    'linked-entity-card',
    compact ? 'linked-entity-card-compact' : ''
  ].filter(Boolean).join(' ');
  const title = investigation?.title || `Case ${shortRef(investigationRef)}`;
  const summary = compact
    ? ''
    : (investigation?.source || fallbackRrn || 'Investigation workflow entity');
  const assigneeLabel = investigation?.assignee?.name || investigation?.assignee?.email || 'Unassigned';
  const openLabel = `Open investigation ${title}`;

  return `
    <article
      class="${cardClasses}"
      data-id="${escapeHtml(investigationRef)}"
      data-type="investigation-related"
      ${getInteractiveCardAttributes(openLabel)}
    >
      <div class="card-topline">
        <span class="badge ${getBadgeClass(investigation?.priority)}">${escapeHtml(investigation?.priority || 'CASE')}</span>
        <span class="status-pill ${getStatusClass(investigation?.status)}">${escapeHtml(investigation?.status || 'OPEN')}</span>
      </div>
      <h4 class="related-alert-title">${escapeHtml(title)}</h4>
      ${summary ? `<p class="related-alert-summary">${escapeHtml(summary)}</p>` : ''}
      <div class="card-metadata">
        <span class="card-chip">${escapeHtml(assigneeLabel)}</span>
        <span class="card-timestamp">${formatDate(investigation?.created_time || investigation?.createdTime)}</span>
      </div>
    </article>
  `;
}

function renderLinkedInvestigationGrid(caseRefs = [], linkedInvestigations = []) {
  const investigationLookup = new Map();

  (linkedInvestigations || []).forEach(investigation => {
    const investigationRef = String(investigation?.rrn || investigation?.id || '').trim();
    if (!investigationRef || investigationLookup.has(investigationRef)) return;
    investigationLookup.set(investigationRef, investigation);
  });

  const entries = (caseRefs || [])
    .map(ref => String(ref || '').trim())
    .filter(Boolean)
    .map(ref => renderLinkedInvestigationCard(investigationLookup.get(ref), ref, { compact: true }));

  if (!entries.length) {
    return '<p class="detail-empty">No linked investigations are available.</p>';
  }

  return `
    <div class="linked-investigation-grid">
      ${entries.join('')}
    </div>
  `;
}

function getAlertTimelineTimestamp(alert = {}) {
  const candidates = [
    alert.created_at,
    alert.created_time,
    alert.createdTime,
    alert.alerted_at,
    alert.latest_event_time
  ];

  return candidates.find(value => value && !Number.isNaN(Date.parse(value))) || null;
}

function getInvestigationAlertWindow(alerts = []) {
  return alerts.reduce((window, alert) => {
    const timestamp = getAlertTimelineTimestamp(alert);
    if (!timestamp) return window;

    const parsed = Date.parse(timestamp);
    if (Number.isNaN(parsed)) return window;

    if (!window.first || parsed < window.first.parsed) {
      window.first = { parsed, value: timestamp };
    }

    if (!window.latest || parsed > window.latest.parsed) {
      window.latest = { parsed, value: timestamp };
    }

    return window;
  }, {
    first: null,
    latest: null
  });
}

function summarizeInvestigationAlerts(alerts = []) {
  const summary = {
    total: alerts.length,
    active: 0,
    closed: 0,
    critical: 0,
    high: 0,
    sources: new Set(),
    rules: new Set()
  };

  alerts.forEach(alert => {
    const status = String(alert.status || '').toUpperCase();
    const priority = String(alert.priority || '').toUpperCase();
    const source = alert.alert_source || alert.external_source || alert.type;
    const ruleName = alert.rule?.name || alert.detection_rule_rrn?.rule_name;

    if (status === 'CLOSED') {
      summary.closed += 1;
    } else {
      summary.active += 1;
    }

    if (priority === 'CRITICAL') summary.critical += 1;
    if (priority === 'HIGH') summary.high += 1;
    if (source) summary.sources.add(source);
    if (ruleName) summary.rules.add(ruleName);
  });

  return summary;
}

function renderActorBadges(actors, emptyLabel, options = {}) {
  const {
    showType = true
  } = options;

  if (!Array.isArray(actors) || actors.length === 0) {
    return `<span class="badge badge-outline actor-badge">${escapeHtml(emptyLabel)}</span>`;
  }

  return actors.map(actor => {
    const actorName = actor.name || actor.display_name || actor.id || 'Unknown Actor';
    const actorType = showType && actor.type ? `${actor.type}: ` : '';
    const actorDomain = actor.domain ? ` (${actor.domain})` : '';
    const alertCount = actor.alert_count ? ` [${actor.alert_count}]` : '';

    return `
      <span class="badge badge-outline actor-badge">
        ${escapeHtml(`${actorType}${actorName}${actorDomain}${alertCount}`)}
      </span>
    `;
  }).join('');
}

function renderGroupedActorBadges(actors, emptyLabel) {
  if (!Array.isArray(actors) || actors.length === 0) {
    return `<div class="badge-row">${renderActorBadges([], emptyLabel)}</div>`;
  }

  const groups = new Map();

  actors.forEach(actor => {
    const typeLabel = escapeHtml(actor?.type || 'Unknown Type');
    if (!groups.has(typeLabel)) {
      groups.set(typeLabel, []);
    }

    groups.get(typeLabel).push(actor);
  });

  return `
    <div class="actor-group-list">
      ${[...groups.entries()].map(([typeLabel, groupedActors]) => `
        <div class="actor-group">
          <p class="actor-group-label">${typeLabel}</p>
          <div class="badge-row">
            ${renderActorBadges(groupedActors, emptyLabel, { showType: false })}
          </div>
        </div>
      `).join('')}
    </div>
  `;
}

function renderCollapsibleDetailSection({
  eyebrow,
  title,
  body,
  open = false,
  extraClass = ''
}) {
  return `
    <details class="detail-section detail-collapsible glass-panel ${escapeHtml(extraClass)}" ${open ? 'open' : ''}>
      <summary class="detail-collapse-summary">
        <div class="section-heading">
          <p class="eyebrow">${escapeHtml(eyebrow)}</p>
          <h3>${escapeHtml(title)}</h3>
        </div>
        <span class="detail-collapse-icon" aria-hidden="true">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9">
            <path d="m6 9 6 6 6-6"></path>
          </svg>
        </span>
      </summary>
      <div class="detail-collapse-body">
        ${body}
      </div>
    </details>
  `;
}

function renderInvestigationAlertList(alerts) {
  if (!Array.isArray(alerts) || alerts.length === 0) {
    return '<p class="detail-empty">No related alerts were returned for this investigation.</p>';
  }

  return `
    <div class="related-alert-list">
      ${alerts.map(alert => `
        <article
          class="related-alert-item card ${getSeverityClass(alert.priority)}"
          data-id="${escapeHtml(alert.rrn || alert.id || '')}"
          data-type="alert-related"
          ${getInteractiveCardAttributes(`Open alert ${alert.title || 'Untitled Alert'}`)}
        >
          <div class="card-topline">
            <span class="badge ${getBadgeClass(alert.priority)}">${escapeHtml(alert.priority || alert.alert_type || 'Alert')}</span>
            <span class="status-pill ${getStatusClass(alert.status)}">${escapeHtml(alert.status || 'OPEN')}</span>
          </div>
          <h4 class="related-alert-title">${escapeHtml(alert.title || 'Untitled Alert')}</h4>
          <p class="related-alert-summary">${escapeHtml(alert.alert_source || alert.external_source || alert.alert_type_description || 'Investigation-linked alert')}</p>
          <div class="card-metadata">
            <span class="card-chip">${escapeHtml(alert.rule?.name || alert.detection_rule_rrn?.rule_name || alert.alert_type || 'Detection event')}</span>
            <span class="card-timestamp">${formatDate(alert.created_at || alert.created_time)}</span>
          </div>
        </article>
      `).join('')}
    </div>
  `;
}

function renderRuleSummary(ruleSummary, mitreLookup = {}) {
  if (!ruleSummary) {
    return '<p class="detail-empty">No detection rule summary available for this alert.</p>';
  }

  const renderList = value => Array.isArray(value) && value.length > 0 ? value.join(', ') : null;
  const getMitreFallbackUrl = code => {
    const normalizedCode = String(code || '').trim().toUpperCase();
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
  };
  const renderMitreLinks = (value, category, mitreLookup = {}) => {
    if (!Array.isArray(value) || value.length === 0) return null;
    return value.map(code => {
      const safeCode = String(code).trim().toUpperCase();
      const resolved = mitreLookup[safeCode];
      const label = resolved?.label || safeCode;
      const href = sanitizeExternalUrl(resolved?.url) || getMitreFallbackUrl(safeCode);
      const title = resolved?.name && category === 'technique' ? ` title="${escapeHtml(safeCode)}"` : '';
      return `<a href="${escapeHtml(href)}" target="_blank" rel="noopener noreferrer"${title}>${escapeHtml(label)}</a>`;
    }).join(', ');
  };
  const renderScalar = value => {
    if (value === null || value === undefined) return null;
    if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
      return String(value);
    }
    if (Array.isArray(value)) {
      return value.length > 0 ? value.join(', ') : null;
    }
    if (typeof value === 'object') {
      return value.name || value.label || value.value || value.state || JSON.stringify(value);
    }
    return String(value);
  };

  const ruleDescription = ruleSummary.description || ruleSummary.DESCRIPTION || null;
  const ruleRecommendation = ruleSummary.recommendation || ruleSummary.RECOMMENDATION || null;
  const ruleEventTypes = renderList(ruleSummary.event_types || ruleSummary.EVENT_TYPES);
  const ruleTactics = renderMitreLinks(
    ruleSummary.tactic_codes || ruleSummary.TACTIC_CODES,
    'tactic',
    mitreLookup
  );
  const ruleTechniques = renderMitreLinks(
    ruleSummary.technique_codes || ruleSummary.TECHNIQUE_CODES,
    'technique',
    mitreLookup
  );
  const rulePriority = renderScalar(ruleSummary.priority_level || ruleSummary.PRIORITY_LEVEL);
  const ruleState = renderScalar(ruleSummary.state || ruleSummary.STATE);
  const ruleDetectionCount = renderScalar(ruleSummary.detection_count || ruleSummary.DETECTION_COUNT);

  return `
    <div class="detail-panel">
      ${renderEntityMeta('Rule', ruleSummary.name || 'N/A')}
      ${renderEntityMeta('Rule RRN', ruleSummary.rrn || 'N/A')}
      ${rulePriority ? renderEntityMeta('Priority', rulePriority) : ''}
      ${ruleState ? renderEntityMeta('State', ruleState) : ''}
      ${ruleDetectionCount ? renderEntityMeta('Detection Count', ruleDetectionCount) : ''}
      ${ruleEventTypes ? renderEntityMeta('Event Types', ruleEventTypes) : ''}
      ${ruleTactics ? renderTrustedHtmlMeta('MITRE Tactics', ruleTactics) : ''}
      ${ruleTechniques ? renderTrustedHtmlMeta('MITRE Techniques', ruleTechniques) : ''}
      ${ruleDescription ? renderEntityMeta('Description', ruleDescription) : ''}
      ${ruleRecommendation ? renderEntityMeta('Recommendation', ruleRecommendation) : ''}
    </div>
  `;
}

function renderCopyableCodePanel(value, label = 'field') {
  return renderCopyableCodePanelWithOptions(value, label);
}

function normalizeHighlightTerm(value, { isKey = false } = {}) {
  const normalized = String(value ?? '').trim();
  if (!normalized) return '';
  if (normalized.length === 1 && !isKey) return '';
  if (!isKey && normalized.length < 3 && !/[.@:_/-]/.test(normalized)) return '';
  return normalized;
}

function normalizeHighlightPathSegment(value) {
  return String(value ?? '')
    .trim()
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '');
}

function normalizeHighlightPath(value) {
  return String(value ?? '')
    .split('.')
    .map(segment => normalizeHighlightPathSegment(segment))
    .filter(Boolean)
    .join('.');
}

function collectHighlightTermsFromEntries(entries = [], options = {}) {
  const {
    includeKeys = true,
    includeValues = true
  } = options;
  const terms = new Map();

  (Array.isArray(entries) ? entries : []).forEach(entry => {
    if (!entry || typeof entry !== 'object') return;

    if (includeKeys) {
      const key = normalizeHighlightTerm(entry.key || entry.name || entry.label, { isKey: true });
      if (key) {
        terms.set(key.toLowerCase(), key);
      }
    }

    if (includeValues) {
      const scalarValues = Array.isArray(entry.values)
        ? entry.values
        : [entry.value];

      scalarValues.forEach(value => {
        if (value === null || value === undefined) return;
        if (typeof value === 'object') return;

        const normalizedValue = normalizeHighlightTerm(value);
        if (normalizedValue) {
          terms.set(normalizedValue.toLowerCase(), normalizedValue);
        }
      });
    }
  });

  return [...terms.values()]
    .sort((a, b) => b.length - a.length || a.localeCompare(b));
}

function collectHighlightPathsFromEntries(entries = []) {
  const paths = new Map();

  (Array.isArray(entries) ? entries : []).forEach(entry => {
    if (!entry || typeof entry !== 'object') return;

    const normalizedPath = normalizeHighlightPath(entry.key || entry.name || entry.label);
    if (normalizedPath) {
      paths.set(normalizedPath, normalizedPath);
    }
  });

  return [...paths.values()].sort((a, b) => b.length - a.length || a.localeCompare(b));
}

function collectHighlightTermsByPath(entries = []) {
  const termsByPath = new Map();

  (Array.isArray(entries) ? entries : []).forEach(entry => {
    if (!entry || typeof entry !== 'object') return;

    const normalizedPath = normalizeHighlightPath(entry.key || entry.name || entry.label);
    if (!normalizedPath) return;

    const values = Array.isArray(entry.values) ? entry.values : [entry.value];
    const currentTerms = termsByPath.get(normalizedPath) || new Map();

    values.forEach(value => {
      if (value === null || value === undefined) return;
      if (typeof value === 'object') return;

      const normalizedValue = normalizeHighlightTerm(value);
      if (!normalizedValue) return;

      currentTerms.set(normalizedValue.toLowerCase(), normalizedValue);
    });

    if (currentTerms.size > 0) {
      termsByPath.set(normalizedPath, currentTerms);
    }
  });

  return new Map(
    [...termsByPath.entries()].map(([path, terms]) => [
      path,
      [...terms.values()].sort((a, b) => b.length - a.length || a.localeCompare(b))
    ])
  );
}

function renderHighlightedCodeContent(value, highlightTerms = []) {
  const source = String(value ?? '');
  const normalizedTerms = (highlightTerms || []).filter(Boolean);

  if (!source || normalizedTerms.length === 0) {
    return escapeHtml(source);
  }

  const pattern = normalizedTerms
    .map(term => term.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))
    .join('|');

  if (!pattern) {
    return escapeHtml(source);
  }

  const matcher = new RegExp(pattern, 'gi');
  let cursor = 0;
  let html = '';

  source.replace(matcher, (match, offset) => {
    html += escapeHtml(source.slice(cursor, offset));
    html += `<mark class="code-highlight">${escapeHtml(match)}</mark>`;
    cursor = offset + match.length;
    return match;
  });

  html += escapeHtml(source.slice(cursor));
  return html;
}

function collectJsonScalarHighlightTerms(value, terms = []) {
  const variants = new Map();

  (terms || []).forEach(term => {
    const normalizedTerm = String(term ?? '');
    if (!normalizedTerm) return;

    variants.set(normalizedTerm.toLowerCase(), normalizedTerm);

    if (typeof value === 'string') {
      const serializedTerm = JSON.stringify(normalizedTerm);
      if (!serializedTerm) return;

      variants.set(serializedTerm.toLowerCase(), serializedTerm);

      const escapedInnerTerm = serializedTerm.slice(1, -1);
      if (escapedInnerTerm) {
        variants.set(escapedInnerTerm.toLowerCase(), escapedInnerTerm);
      }
    }
  });

  return [...variants.values()]
    .sort((a, b) => b.length - a.length || a.localeCompare(b));
}

function renderHighlightedJsonContent(value, options = {}, depth = 0, currentPath = '') {
  const {
    highlightedPaths = new Set(),
    scalarTerms = [],
    scalarTermsByPath = new Map()
  } = options;

  const indent = '  '.repeat(depth);
  const nextIndent = '  '.repeat(depth + 1);

  if (Array.isArray(value)) {
    if (value.length === 0) return '[]';

    const items = value.map(item => (
      `${nextIndent}${renderHighlightedJsonContent(item, options, depth + 1, currentPath)}`
    ));
    return `[\n${items.join(',\n')}\n${indent}]`;
  }

  if (value && typeof value === 'object') {
    const entries = Object.entries(value);
    if (entries.length === 0) return '{}';

    const items = entries.map(([key, childValue]) => {
      const childPath = currentPath
        ? `${currentPath}.${normalizeHighlightPathSegment(key)}`
        : normalizeHighlightPathSegment(key);
      const keyHtml = highlightedPaths.has(childPath)
        ? `<mark class="code-highlight">${escapeHtml(JSON.stringify(key))}</mark>`
        : escapeHtml(JSON.stringify(key));

      return `${nextIndent}${keyHtml}: ${renderHighlightedJsonContent(childValue, options, depth + 1, childPath)}`;
    });

    return `{\n${items.join(',\n')}\n${indent}}`;
  }

  const scopedTerms = [
    ...(scalarTerms || []),
    ...(scalarTermsByPath.get(currentPath) || [])
  ].filter((term, index, allTerms) => allTerms.findIndex(candidate => candidate.toLowerCase() === term.toLowerCase()) === index);

  return renderHighlightedCodeContent(
    JSON.stringify(value),
    collectJsonScalarHighlightTerms(value, scopedTerms)
  );
}

function renderCopyableCodePanelWithOptions(value, label = 'field', options = {}) {
  const {
    highlightTerms = [],
    highlightEnabled = false,
    parsedValue = null,
    highlightPaths = [],
    highlightTermsByPath = new Map(),
    expandKey = '',
    expanded = false,
    previewLines = 50
  } = options;
  const sourceValue = String(value ?? '');
  const lineCount = sourceValue
    ? sourceValue.split(/\r?\n/).length
    : 0;
  const canExpand = Boolean(expandKey) && lineCount > previewLines;
  const renderedValue = highlightEnabled
    ? (
      parsedValue && typeof parsedValue === 'object'
        ? renderHighlightedJsonContent(parsedValue, {
          highlightedPaths: new Set((highlightPaths || []).filter(Boolean)),
          scalarTerms: highlightTerms,
          scalarTermsByPath: highlightTermsByPath instanceof Map ? highlightTermsByPath : new Map()
        })
        : renderHighlightedCodeContent(sourceValue, highlightTerms)
    )
    : escapeHtml(sourceValue);

  return `
    <div class="meta-stack">
      <div class="copy-shell code-panel-shell ${canExpand ? 'is-expandable' : ''} ${canExpand && expanded ? 'is-expanded' : ''} ${canExpand && !expanded ? 'is-collapsed' : ''}">
        ${renderCopyButton(label)}
        <pre
          class="code-panel copy-source ${canExpand ? 'code-panel-expandable' : ''}"
          ${canExpand ? `style="--code-panel-preview-lines: ${Number(previewLines) || 50};"` : ''}
        >${renderedValue}</pre>
        ${canExpand ? `
          <button
            type="button"
            class="code-panel-expand-btn"
            data-code-panel-toggle="payload"
            data-evidence-key="${escapeHtml(expandKey)}"
            aria-expanded="${expanded ? 'true' : 'false'}"
          >
            ${expanded ? `Show first ${previewLines} lines` : `Click to expand for the full log (${lineCount} lines)`}
          </button>
        ` : ''}
      </div>
      ${renderDecodedCommandPanels(sourceValue, label)}
    </div>
  `;
}

function renderPayloadHighlightActions({ evidenceKey, highlightKoi = false, highlightMatching = false }) {
  return `
    <div class="payload-highlight-actions" data-evidence-key="${escapeHtml(evidenceKey)}">
      <button
        type="button"
        class="payload-highlight-btn ${highlightKoi ? 'is-active' : ''}"
        data-payload-highlight-toggle="koi"
        data-evidence-key="${escapeHtml(evidenceKey)}"
      >
        Keys of Interest
      </button>
      <button
        type="button"
        class="payload-highlight-btn ${highlightMatching ? 'is-active' : ''}"
        data-payload-highlight-toggle="matching"
        data-evidence-key="${escapeHtml(evidenceKey)}"
      >
        Rule Matching Keys
      </button>
    </div>
  `;
}

function formatCountLabel(count, singular, plural = `${singular}s`) {
  return `${count} ${count === 1 ? singular : plural}`;
}

function shortRef(value) {
  const normalized = String(value || '').trim();
  if (!normalized) return '';
  const parts = normalized.split(':').filter(Boolean);
  return parts[parts.length - 1] || normalized;
}

function uniqueStrings(values = []) {
  return [...new Set((values || []).filter(Boolean))];
}

function renderAlertCard(alert, { compact = false, cardType = 'alert' } = {}) {
  const title = alert.title || 'Untitled Alert';
  const summary = compact
    ? (alert?._stackMeta?.preview || alert.description || alert.external_source || alert.type || alert.alert_source || 'InsightIDR detection event')
    : (alert.description || alert.external_source || alert.type || alert.alert_source || 'InsightIDR detection event');
  const supportText = compact && alert?.description && alert._stackMeta?.preview && alert.description !== alert._stackMeta.preview
    ? `<p class="alert-stack-note">${escapeHtml(alert.description)}</p>`
    : '';

  return `
    <article
      class="card alert-card ${compact ? 'alert-stack-item' : ''} ${getSeverityClass(alert.priority)}"
      data-id="${escapeHtml(alert._uiKey || alert.rrn || alert.id || '')}"
      data-type="${escapeHtml(cardType)}"
      ${getInteractiveCardAttributes(`Open alert ${title}`)}
    >
      <div class="card-topline">
        <span class="badge ${getBadgeClass(alert.priority)}">${escapeHtml(alert.priority || 'UNKNOWN')}</span>
        <span class="card-timestamp">${formatDate(alert.created_at || alert.alerted_at || alert.created_time || alert.createdTime)}</span>
      </div>
      <h3 class="card-title">${escapeHtml(title)}</h3>
      <p class="card-summary">${escapeHtml(summary)}</p>
      ${supportText}
      <div class="card-metadata">
        <span class="status-pill ${getStatusClass(alert.status)}">${escapeHtml(alert.status || 'OPEN')}</span>
        <span class="card-chip">
          ${alert.investigation_rrn ? 'Case Linked' : (alert.assignee ? 'Analyst Assigned' : 'Standalone')}
        </span>
      </div>
    </article>
  `;
}

function renderDuplicateLane(group, options = {}) {
  const { cardType = 'alert-stack-alert', forceSection = false } = options;

  if (!group || !Array.isArray(group.alerts) || group.alerts.length === 0) {
    return '';
  }

  if (!forceSection && group.alerts.length === 1) {
    return renderAlertCard(group.alerts[0], { compact: true, cardType });
  }

  return `
    <section class="alert-lane glass-panel">
      <div class="alert-lane-head">
        <div class="alert-lane-copy">
          <p class="alert-lane-kicker">${escapeHtml(forceSection && group.stageLabel ? group.stageLabel : formatCountLabel(group.alertCount, 'alert'))}</p>
          <h4 class="alert-lane-title">${escapeHtml(group.label || 'Duplicate signal lane')}</h4>
          <p class="alert-lane-reason">${escapeHtml(group.reasonSummary || group.reason || 'Shared detection fingerprint')}</p>
        </div>
        <div class="alert-lane-meta">
          <span class="badge ${getBadgeClass(group.priority)}">${escapeHtml(group.priority || 'UNKNOWN')}</span>
          <span class="status-pill ${getStatusClass(group.statusSummary?.className || group.statusSummary?.label)}">
            ${escapeHtml(group.statusSummary?.label || 'OPEN')}
          </span>
        </div>
      </div>
      <div class="alert-lane-list">
        ${group.alerts.map(alert => renderAlertCard(alert, { compact: true, cardType })).join('')}
      </div>
    </section>
  `;
}

function renderAlertCluster(cluster) {
  if (!cluster || !Array.isArray(cluster.alerts) || cluster.alerts.length === 0) {
    return '';
  }

  if (cluster.alerts.length === 1 && cluster.mode !== 'ATTACK_PATH') {
    return renderAlertCard(cluster.alerts[0]);
  }

  const isAttackPath = cluster.mode === 'ATTACK_PATH';
  const groupedLabel = isAttackPath ? 'Path basis' : 'Grouped on';
  const clusterMetaHtml = isAttackPath
    ? `
      <div class="alert-cluster-meta">
        <span class="status-pill ${getStatusClass(cluster.statusSummary?.className || cluster.statusSummary?.label)}">
          ${escapeHtml(cluster.statusSummary?.label || 'OPEN')}
        </span>
        ${cluster.confidenceLabel ? `<span class="card-chip">${escapeHtml(cluster.confidenceLabel)}</span>` : ''}
        <span class="card-chip">${escapeHtml(cluster.subSummary || formatCountLabel(cluster.duplicateGroups?.length || 0, 'stage'))}</span>
      </div>
    `
    : `
      <div class="alert-cluster-meta">
        <span class="status-pill ${getStatusClass(cluster.statusSummary?.className || cluster.statusSummary?.label)}">
          ${escapeHtml(cluster.statusSummary?.label || 'OPEN')}
        </span>
        <span class="card-chip">${escapeHtml(cluster.subSummary || formatCountLabel(cluster.duplicateGroups?.length || 0, 'signal lane'))}</span>
        <span class="card-chip">${escapeHtml(cluster.statusSummary?.detail || '')}</span>
      </div>
    `;

  return `
    <article
      class="card alert-cluster-card ${getSeverityClass(cluster.highestPriority)}"
      data-stack-open="${escapeHtml(cluster.id || '')}"
      aria-label="${escapeHtml(`Open stack for ${cluster.descriptor?.label || 'alert stack'}`)}"
      role="button"
      tabindex="0"
      aria-haspopup="dialog"
    >
      <div class="card-topline">
        <span class="badge ${getBadgeClass(cluster.highestPriority)}">${escapeHtml(cluster.highestPriority || 'UNKNOWN')}</span>
        <span class="card-timestamp">${formatDate(cluster.latestTimestamp)}</span>
      </div>
      <div class="alert-cluster-head">
        <div class="alert-cluster-copy">
          <h3 class="card-title">${escapeHtml(cluster.descriptor?.label || 'Alert Stack')}</h3>
          <p class="card-summary">${escapeHtml(cluster.summary || `${formatCountLabel(cluster.alertCount, 'alert')} in this stack`)}</p>
        </div>
      </div>
      <p class="alert-cluster-reason">${escapeHtml(groupedLabel)}: ${escapeHtml(cluster.reasonSummary || cluster.descriptor?.reason || 'Shared analyst context')}</p>
      ${isAttackPath && cluster.nextAction ? `<p class="alert-cluster-reason">Next: ${escapeHtml(cluster.nextAction)}</p>` : ''}
      ${clusterMetaHtml}
      <span class="alert-cluster-stack-icon" aria-hidden="true">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">
          <path d="M12 4 4 8l8 4 8-4-8-4Z"></path>
          <path d="m4 12 8 4 8-4"></path>
          <path d="m4 16 8 4 8-4"></path>
        </svg>
      </span>
    </article>
  `;
}

export function renderAlertStackDetail(cluster, options = {}) {
  const stackDetailCompactLabels = [
    'view',
    'stacking mode',
    'confidence',
    'alerts in stack',
    'alerts in path',
    'signal lanes',
    'path stages',
    'detection families',
    'linked cases',
    'first seen',
    'latest seen',
    'status spread'
  ];
  const modeLabel = options.modeLabel || 'Alert Stack';
  const alerts = Array.isArray(cluster?.alerts) ? cluster.alerts : [];
  const duplicateGroups = Array.isArray(cluster?.duplicateGroups) ? cluster.duplicateGroups : [];
  const statusSummary = cluster?.statusSummary || {};
  const isAttackPath = cluster?.mode === 'ATTACK_PATH';
  const detectionLabels = uniqueStrings(cluster?.titleLabels || alerts.map(alert => alert?._stackMeta?.title || alert?.title));
  const caseRefs = uniqueStrings(cluster?.investigationRefs || alerts.map(alert => alert?.investigation_rrn));
  const linkedInvestigations = Array.isArray(cluster?._linkedInvestigations) ? cluster._linkedInvestigations : [];
  const groupingSignals = Array.isArray(cluster?.groupingSignals) ? cluster.groupingSignals : [];
  const laneReasons = uniqueStrings(duplicateGroups.map(group => group.reasonSummary || group.reason)).slice(0, 6);
  const stageLabels = uniqueStrings(cluster?.stageLabels || duplicateGroups.map(group => group.stageLabel)).slice(0, 8);
  const heroChips = [
    modeLabel,
    isAttackPath ? cluster?.confidenceLabel : '',
    cluster?.subSummary || formatCountLabel(duplicateGroups.length, isAttackPath ? 'stage' : 'signal lane'),
    isAttackPath ? '' : statusSummary.detail || ''
  ].filter(Boolean);
  const overviewEntries = isAttackPath
    ? [
      { label: 'View', value: modeLabel },
      { label: 'Path Basis', value: cluster?.descriptor?.reason || 'Shared attack path context' },
      { label: 'Shared Pattern', value: cluster?.reasonSummary || '' },
      { label: 'Confidence', value: cluster?.confidenceLabel || '' },
      { label: 'Confidence Detail', value: cluster?.confidenceDetail || '' },
      { label: 'Alerts In Path', value: String(cluster?.alertCount || alerts.length || 0) },
      { label: 'Path Stages', value: String(duplicateGroups.length) },
      { label: 'Blast Radius', value: cluster?.blastRadiusSummary || 'Focused scope' },
      { label: 'Next Action', value: cluster?.nextAction || '' },
      { label: 'First Seen', value: formatDate(cluster?.earliestTimestamp) },
      { label: 'Latest Seen', value: formatDate(cluster?.latestTimestamp) },
      { label: 'Status Spread', value: statusSummary.detail || statusSummary.label || 'OPEN' }
    ]
    : [
      { label: 'Stacking Mode', value: modeLabel },
      { label: 'Grouping Basis', value: cluster?.descriptor?.reason || 'Shared analyst context' },
      { label: 'Shared Pattern', value: cluster?.reasonSummary || '' },
      { label: 'Alerts In Stack', value: String(cluster?.alertCount || alerts.length || 0) },
      { label: 'Signal Lanes', value: String(duplicateGroups.length) },
      { label: 'Detection Families', value: String(detectionLabels.length) },
      { label: 'Linked Cases', value: caseRefs.length ? String(caseRefs.length) : '0' },
      { label: 'First Seen', value: formatDate(cluster?.earliestTimestamp) },
      { label: 'Latest Seen', value: formatDate(cluster?.latestTimestamp) },
      { label: 'Status Spread', value: statusSummary.detail || statusSummary.label || 'OPEN' }
    ];

  return `
    <div class="detail-stack">
      <section class="detail-hero glass-panel ${getSeverityClass(cluster?.highestPriority)}">
        <div class="card-topline">
          <span class="badge ${getBadgeClass(cluster?.highestPriority)}">${escapeHtml(cluster?.highestPriority || 'UNKNOWN')}</span>
          <span class="status-pill ${getStatusClass(statusSummary.className || statusSummary.label)}">${escapeHtml(statusSummary.label || 'OPEN')}</span>
        </div>
        <h2 class="detail-title">${escapeHtml(cluster?.descriptor?.label || 'Alert Stack')}</h2>
        <p class="stack-detail-summary">${escapeHtml(cluster?.summary || `${formatCountLabel(alerts.length, 'alert')} in this stack`)}</p>
        <div class="badge-row stack-detail-chip-row">
          ${heroChips.map(chip => `<span class="card-chip">${escapeHtml(chip)}</span>`).join('')}
        </div>
      </section>

      <section class="detail-section glass-panel">
        <div class="section-heading">
          <p class="eyebrow">Why Grouped</p>
          <h3>${isAttackPath ? 'Path rationale' : 'Stack rationale'}</h3>
        </div>
        ${renderEntryGrid(overviewEntries, 'No stack overview is available right now.', {
          layout: 'adaptive',
          gridClassName: 'stack-detail-grid',
          compactLabels: stackDetailCompactLabels
        })}
        ${groupingSignals.length ? `
          <div class="stack-detail-group">
            <p class="stack-detail-label">${isAttackPath ? 'Confidence drivers' : 'Shared pivots'}</p>
            ${renderEntryGrid(groupingSignals, '', {
              layout: 'adaptive',
              gridClassName: 'stack-detail-grid',
              preferCompact: true
            })}
          </div>
        ` : ''}
        ${detectionLabels.length ? `
          <div class="stack-detail-group">
            <p class="stack-detail-label">Detection families</p>
            ${renderBadgeStack(detectionLabels, '')}
          </div>
        ` : ''}
        ${caseRefs.length ? `
          <div class="stack-detail-group">
            <p class="stack-detail-label">Linked cases</p>
            ${renderLinkedInvestigationGrid(caseRefs, linkedInvestigations)}
          </div>
        ` : ''}
        ${isAttackPath && stageLabels.length ? `
          <div class="stack-detail-group">
            <p class="stack-detail-label">Stage coverage</p>
            ${renderBadgeStack(stageLabels, '')}
          </div>
        ` : laneReasons.length ? `
          <div class="stack-detail-group">
            <p class="stack-detail-label">Shared indicators</p>
            ${renderBadgeStack(laneReasons, '')}
          </div>
        ` : ''}
        ${isAttackPath && cluster?.weakLink ? `
          <div class="stack-detail-group">
            <p class="stack-detail-label">Weak link</p>
            <p class="stack-detail-copy">${escapeHtml(cluster.weakLink)}</p>
          </div>
        ` : ''}
      </section>

      <section class="detail-section glass-panel">
        <div class="section-heading">
          <p class="eyebrow">${isAttackPath ? 'Observed Progression' : 'Contained Alerts'}</p>
          <h3>${isAttackPath ? 'Path stages' : 'Signal lanes'}</h3>
        </div>
        <p class="stack-detail-copy">
          ${isAttackPath
            ? 'Each stage below groups the alerts that support this path in observed time order. Open any child alert to inspect the underlying evidence.'
            : 'Open any child alert to pivot into the full investigation view and use the back action to return to this stack.'}
        </p>
        <div class="stack-detail-lanes">
          ${duplicateGroups.map(group => renderDuplicateLane(group, { cardType: 'alert-stack-alert', forceSection: isAttackPath })).join('')}
        </div>
      </section>
    </div>
  `;
}

export function renderAlertList(alertView) {
  const filteredAlerts = alertView?.filteredAlerts || [];
  const clusters = alertView?.clusters || [];

  if (!(alertView?.totalAlerts || []).length) {
    return renderEmptyState('No alerts detected in the current feed.');
  }

  if (filteredAlerts.length === 0) {
    return renderEmptyState('No alerts match the current filter.');
  }

  return `
    <div class="alert-stack-shell">
      <div class="alert-stack-banner">
        <span class="card-chip">${escapeHtml(alertView?.modeLabel || 'Alert Stack')}</span>
        <span class="card-chip">${escapeHtml(alertView?.countLabel || formatCountLabel(alertView?.workUnitCount || clusters.length, 'work unit'))}</span>
        ${alertView?.stackedAlertCount ? `<span class="card-chip">${escapeHtml(formatCountLabel(alertView.stackedAlertCount, 'alert'))} collapsed</span>` : ''}
      </div>
      <div class="list-grid alert-stack-grid">
        ${clusters.map(cluster => renderAlertCluster(cluster)).join('')}
      </div>
    </div>
  `;
}

export function renderInvestigationList(investigations, statusFilter = 'ACTIVE') {
  if (!investigations || investigations.length === 0) {
    return renderEmptyState('No investigations are available right now.');
  }

  let filteredInvestigations = investigations;
  if (statusFilter === 'ACTIVE') {
    filteredInvestigations = investigations.filter(inv => inv.status !== 'CLOSED');
  } else if (statusFilter === 'INVESTIGATING') {
    filteredInvestigations = investigations.filter(inv => String(inv.status || '').toUpperCase() === 'INVESTIGATING');
  } else if (statusFilter === 'CLOSED') {
    filteredInvestigations = investigations.filter(inv => inv.status === 'CLOSED');
  }

  if (filteredInvestigations.length === 0) {
    return renderEmptyState('No investigations match the current filter.');
  }

  const weight = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
  const sorted = [...filteredInvestigations].sort((a, b) => {
    const priorityDelta = (weight[String(b.priority || 'LOW').toUpperCase()] || 0)
      - (weight[String(a.priority || 'LOW').toUpperCase()] || 0);

    if (priorityDelta !== 0) return priorityDelta;

    return new Date(b.latest_alert_time || b.created_time || b.createdTime || 0)
      - new Date(a.latest_alert_time || a.created_time || a.createdTime || 0);
  });

  return `
    <div class="list-grid">
      ${sorted.map(inv => `
        <article
          class="card investigation-card ${getSeverityClass(inv.priority)}"
          data-id="${escapeHtml(inv.rrn || inv.id)}"
          data-type="investigation"
          ${getInteractiveCardAttributes(`Open investigation ${inv.title || 'Untitled Investigation'}`)}
        >
          <div class="card-topline">
            <span class="badge ${getBadgeClass(inv.priority)}">${escapeHtml(inv.priority || 'MEDIUM')}</span>
            <span class="status-pill ${getStatusClass(inv.status)}">${escapeHtml(inv.status || 'OPEN')}</span>
          </div>
          <h3 class="card-title">${escapeHtml(inv.title || 'Untitled Investigation')}</h3>
          <p class="card-summary">${escapeHtml(inv.source || 'Investigation workflow entity')}</p>
          <div class="card-metadata">
            <span class="card-chip">${escapeHtml(inv.assignee ? (inv.assignee.name || inv.assignee.email || inv.assignee) : 'Unassigned')}</span>
            <span class="card-timestamp">${formatDate(inv.created_time || inv.createdTime)}</span>
          </div>
        </article>
      `).join('')}
    </div>
  `;
}

function formatPercent(value, digits = 0) {
  if (value === null || value === undefined || Number.isNaN(Number(value))) return '--';
  return `${Number(value).toFixed(digits)}%`;
}

function formatRelativeTimestamp(timestamp) {
  if (!timestamp) return 'No heartbeat reported';
  return `${formatElapsedDuration(timestamp)} ago`;
}

function formatHealthAttentionReason(reason) {
  const normalized = String(reason || '').trim();
  if (!normalized) return '';

  if (normalized.startsWith('state:')) {
    return `State ${normalized.slice(6)}`;
  }

  if (normalized === 'last_active:stale') {
    return 'Heartbeat stale';
  }

  if (normalized === 'drop_rate:nonzero') {
    return 'Drop rate above zero';
  }

  if (normalized === 'capacity:high') {
    return 'Capacity above 85%';
  }

  if (normalized.startsWith('issue:')) {
    return normalized.slice(6);
  }

  return normalized;
}

function getHealthIssueSeverity(issue) {
  const normalized = String(issue || '').trim().toUpperCase();
  if (!normalized) return '';

  const match = normalized.match(/^([A-Z_ ]+):/);
  const severity = (match ? match[1] : '').trim();
  if (['ERROR', 'WARNING', 'CRITICAL', 'FAILED', 'UNHEALTHY'].includes(severity)) {
    return severity;
  }

  return '';
}

function getHealthStateClass(value) {
  const normalized = String(value || '').trim().toUpperCase();
  if (!normalized) return 'health-state-neutral';
  if (['RUNNING', 'ONLINE', 'ACTIVE', 'HEALTHY', 'OK', 'MONITORING'].includes(normalized)) return 'health-state-good';
  if (['WARNING', 'STALE', 'DEGRADED'].includes(normalized)) return 'health-state-warning';
  if (['OFFLINE', 'FAILED', 'ERROR', 'CRITICAL', 'UNHEALTHY'].includes(normalized)) return 'health-state-danger';
  return 'health-state-neutral';
}

function getHealthItemIndicator(item) {
  const issueSeverity = getHealthIssueSeverity(item?.issue);
  if (issueSeverity) {
    return {
      label: issueSeverity,
      className: getHealthStateClass(issueSeverity)
    };
  }

  if ((item?.attention_reasons || []).includes('last_active:stale')) {
    return {
      label: 'STALE',
      className: getHealthStateClass('STALE')
    };
  }

  const state = String(item?.state || '').trim();
  return {
    label: state || 'UNKNOWN',
    className: getHealthStateClass(state)
  };
}

function getHealthResourceTone(resource) {
  if (!resource?.licensed) return 'severity-neutral';
  if ((resource?.totals?.attention || 0) > 0) return 'severity-high';
  if (resource?.available) return 'severity-low';
  return 'severity-neutral';
}

function getHealthResourceSummary(resource) {
  if (!resource?.licensed) {
    return 'This resource family is not licensed in the current tenant.';
  }

  if ((resource?.errors || []).length > 0) {
    return resource.errors[0];
  }

  if (resource?.key === 'agent' && resource?.summary) {
    return `${resource.summary.online || 0} online, ${resource.summary.offline || 0} offline, ${resource.summary.stale || 0} stale.`;
  }

  if (!resource?.available) {
    return 'No resources are currently reporting for this family.';
  }

  if (resource?.key === 'collectors' && resource?.derived?.collectors?.total_max_event_sources) {
    const used = resource.derived.collectors.total_event_sources_used || 0;
    const max = resource.derived.collectors.total_max_event_sources || 0;
    return `${resource.totals.total} collectors carrying ${used}/${max} configured event-source slots.`;
  }

  if (resource?.key === 'event_sources') {
    return `${resource.totals.total} ingestion paths are reporting into InsightIDR.`;
  }

  if (resource?.key === 'network_sensors') {
    return `${resource.totals.total} network sensors are exposing packet-visibility health.`;
  }

  return `${resource?.totals?.total || 0} resources are currently reporting for this family.`;
}

function renderHealthStateChips(states = []) {
  if (!Array.isArray(states) || states.length === 0) {
    return '<span class="card-chip">No state telemetry</span>';
  }

  return states.slice(0, 4).map(entry => `
    <span class="health-state-pill ${getHealthStateClass(entry.state)}">${escapeHtml(entry.state)} <strong>${entry.count}</strong></span>
  `).join('');
}

function renderHealthStats(resource) {
  const stats = [];
  const collectorDerived = resource?.derived?.collectors || null;
  const systemDerived = resource?.derived?.system || null;

  if (resource?.key === 'agent' && resource?.summary) {
    stats.push({ label: 'Fleet', value: String(resource.summary.total || 0) });
    stats.push({ label: 'Online', value: String(resource.summary.online || 0) });
    stats.push({ label: 'Attention', value: String((resource.summary.offline || 0) + (resource.summary.stale || 0)) });
  } else {
    stats.push({ label: 'Reported', value: String(resource?.totals?.total || 0) });
    stats.push({ label: 'Healthy', value: String(resource?.totals?.healthy || 0) });
    stats.push({ label: 'Attention', value: String(resource?.totals?.attention || 0) });
  }

  if (resource?.key === 'collectors' && collectorDerived?.fleet_capacity_pct != null) {
    stats.push({ label: 'Load', value: formatPercent(collectorDerived.fleet_capacity_pct, 0) });
  } else if (systemDerived?.avg_cpu_pct != null) {
    stats.push({ label: 'Avg CPU', value: formatPercent(systemDerived.avg_cpu_pct, 1) });
  }

  return `
    <div class="health-stat-grid">
      ${stats.map(stat => `
        <div class="health-stat">
          <span class="health-stat-label">${escapeHtml(stat.label)}</span>
          <strong class="health-stat-value">${escapeHtml(stat.value)}</strong>
        </div>
      `).join('')}
    </div>
  `;
}

function renderHealthPreviewItems(resource) {
  if (resource?.key === 'agent') {
    return `
      <div class="health-preview-list compact">
        <div class="health-preview-row">
          <div>
            <div class="health-preview-name">Endpoint posture</div>
            <div class="health-preview-meta">Agent health is summary-only in this API family.</div>
          </div>
          <div class="health-preview-side">
            <span class="card-chip">${resource?.summary?.stale || 0} stale</span>
          </div>
        </div>
      </div>
    `;
  }

  if (!resource?.licensed) {
    return `
      <div class="health-preview-list compact">
        <div class="health-preview-row">
          <div>
            <div class="health-preview-name">Unavailable</div>
            <div class="health-preview-meta">Rapid7 reported this family as unlicensed.</div>
          </div>
        </div>
      </div>
    `;
  }

  const items = Array.isArray(resource?.items) ? resource.items : [];
  if (items.length === 0) {
    return `
      <div class="health-preview-list compact">
        <div class="health-preview-row">
          <div>
            <div class="health-preview-name">No active resources</div>
            <div class="health-preview-meta">This family is licensed, but nothing is reporting right now.</div>
          </div>
        </div>
      </div>
    `;
  }

  const prioritized = [...items]
    .sort((a, b) => {
      const attentionDelta = Number(Boolean(b.attention)) - Number(Boolean(a.attention));
      if (attentionDelta !== 0) return attentionDelta;
      return (Date.parse(a.last_active || '') || 0) - (Date.parse(b.last_active || '') || 0);
    })
    .slice(0, 3);

  return `
    <div class="health-preview-list">
      ${prioritized.map(item => {
        const indicator = getHealthItemIndicator(item);
        const secondaryMeta = item.issue
          ? item.issue
          : item.last_active
            ? `Last active ${formatRelativeTimestamp(item.last_active)}`
            : 'No activity timestamp';
        const sideMeta = item.capacity_pct !== null
          ? `${formatPercent(item.capacity_pct, 0)} cap`
          : item.drop_rate !== null
            ? `${formatPercent(item.drop_rate * 100, 2)} drop`
            : item.storage_pct !== null
              ? `${formatPercent(item.storage_pct, 0)} disk`
              : item.memory_pct !== null
                ? `${formatPercent(item.memory_pct, 0)} mem`
                : item.memory_used !== null
                  ? `${formatBytes(item.memory_used)} mem`
                : '';

        return `
          <div class="health-preview-row">
            <div>
              <div class="health-preview-name">${escapeHtml(item.name || 'Unnamed resource')}</div>
              <div class="health-preview-meta">${escapeHtml(secondaryMeta)}</div>
            </div>
            <div class="health-preview-side">
              <span class="health-state-pill ${indicator.className}">${escapeHtml(indicator.label)}</span>
              ${sideMeta ? `<span class="card-chip">${escapeHtml(sideMeta)}</span>` : ''}
            </div>
          </div>
        `;
      }).join('')}
    </div>
  `;
}

function renderHealthAttention(attentionItems = []) {
  if (!Array.isArray(attentionItems) || attentionItems.length === 0) {
    return '';
  }

  return `
    <section class="health-section">
      <div class="section-heading">
        <p class="eyebrow">Attention</p>
        <h3>Signals needing follow-up</h3>
      </div>
      <div class="health-attention-grid">
        ${attentionItems.map(item => `
          <article class="glass-panel health-attention-card">
            <div class="card-topline">
              <span class="badge badge-high">WATCH</span>
              <span class="card-chip">${escapeHtml(item.resource_label || item.resource_type || 'Resource')}</span>
            </div>
            <h4 class="health-attention-title">${escapeHtml(item.name || 'Unnamed resource')}</h4>
            <p class="health-attention-summary">
              ${escapeHtml(item.issue || item.state || 'Health telemetry requires attention.')}
            </p>
            <div class="health-attention-meta">
              ${item.last_active ? `<span>${escapeHtml(formatDate(item.last_active))}</span>` : '<span>No last-active timestamp</span>'}
              ${item.attention_reasons?.length
                ? `<span>${escapeHtml(item.attention_reasons.map(formatHealthAttentionReason).filter(Boolean).join(', '))}</span>`
                : ''}
            </div>
          </article>
        `).join('')}
      </div>
    </section>
  `;
}

export function renderHealthOverview(healthData) {
  if (!healthData?.resources) {
    return renderEmptyState('Connect your tenant to review platform health telemetry.');
  }

  const resources = Array.isArray(healthData.resources) ? healthData.resources : [];
  if (resources.length === 0) {
    return renderEmptyState('No health metrics were returned by the tenant.');
  }

  return `
    <div class="health-layout">
      ${renderHealthAttention(healthData.attention_items)}
      <section class="health-section">
        <div class="section-heading">
          <p class="eyebrow">Overview</p>
          <h3>Resource families</h3>
        </div>
        <div class="health-resource-grid">
          ${resources.map(resource => `
            <article class="glass-panel health-resource-card ${getHealthResourceTone(resource)}">
              <div class="card-topline">
                <span class="badge ${resource.licensed ? 'badge-outline' : 'badge-medium'}">
                  ${resource.licensed ? 'LICENSED' : 'UNLICENSED'}
                </span>
                <span class="card-chip">${escapeHtml(resource.label || resource.key || 'Resource')}</span>
              </div>
              <h3 class="card-title">${escapeHtml(resource.label || resource.key || 'Resource')}</h3>
              <p class="card-summary">${escapeHtml(getHealthResourceSummary(resource))}</p>
              ${renderHealthStats(resource)}
              <div class="health-state-row">
                ${renderHealthStateChips(resource.states)}
              </div>
              ${renderHealthPreviewItems(resource)}
            </article>
          `).join('')}
        </div>
      </section>
    </div>
  `;
}

export function renderAlertDetail(alert, options = {}) {
  const {
    analysts = [],
    analystsLoading = false
  } = options;
  const currentAssigneeValue = alert._assigneeDraft ?? getAssigneeValue(alert.assignee);
  const rawEventSource = alert.triggering_event_source || alert.external_source || alert.type;
  const resolvedEventSource = alert._eventSourceName || rawEventSource;
  const triagePivotsHtml = renderKeyValuePanel(
    [
      { label: 'Alert ID', value: alert.id || alert.rrn || 'N/A' },
      ...(Array.isArray(alert.rule_keys_of_interest) ? alert.rule_keys_of_interest : [])
    ],
    'No rule keys of interest were returned for this alert.',
    { layout: 'adaptive' }
  );
  const eventSourceMetaHtml = renderAlertEventSourceMeta(alert, rawEventSource, resolvedEventSource);
  const matchingLogicHtml = renderKeyValuePanel(
    alert.rule_matching_keys,
    'No rule matching keys were returned for this alert.'
  );
  const alertOperationsEntries = [
    { label: 'Alerted', value: formatDate(alert.alerted_at) },
    { label: 'Ingested', value: formatDate(alert.ingested_at) },
    { label: 'Updated', value: formatDate(alert.updated_at) },
    { label: 'Event Type', value: alert.triggering_event_type },
    { label: 'AI Disposition', value: alert.ai_suggested_disposition },
    { label: 'Time To Close', value: formatDuration(alert.status_transitions?.seconds_to_first_closed) }
  ];
  const alertOperationsHtml = renderEntryGrid(
    alertOperationsEntries,
    'No operational timings were returned for this alert.',
    { layout: 'adaptive' }
  );
  const decisionSupportEntries = [
    { label: 'AI Suggested Disposition', value: alert.ai_suggested_disposition },
    ...Object.entries(alert.prediction_metadata || {}).map(([key, value]) => ({
      label: formatLabel(key),
      value: formatScalar(value)
    })),
    ...Object.entries(alert.prediction_data || {}).map(([key, value]) => ({
      label: formatLabel(key),
      value: formatScalar(value)
    })),
    ...Object.entries(alert.analytics || {}).map(([key, value]) => ({
      label: formatLabel(key),
      value: formatScalar(value)
    }))
  ].filter(entry => entry.value);
  const evidencesHtml = alert._evidencesError
    ? renderDetailError(alert._evidencesError)
    : (alert._evidences && alert._evidences.length > 0) ? alert._evidences.map(ev => {
    let parsedData = ev.data;
    if (typeof parsedData === 'string') {
      try {
        parsedData = JSON.parse(parsedData);
      } catch (error) {
        parsedData = ev.data;
      }
    }

    let extractedHtml = '';
    const formattedRuleMatchingKeys = Array.isArray(ev.rule_matching_keys)
      ? ev.rule_matching_keys.map(entry => {
        if (entry && typeof entry === 'object') {
          const key = entry.key || 'unknown';
          const values = Array.isArray(entry.values) ? entry.values.join(', ') : '';
          return values ? `${key}: ${values}` : key;
        }
        return String(entry);
      })
      : [];

    if (parsedData && typeof parsedData === 'object') {
      const operation = parsedData.source_json?.Operation || parsedData.action || null;
      const moveToFolder = parsedData.source_json?.Parameters?.find(param => param.Name === 'MoveToFolder')?.Value || null;
      const entryId = parsedData.entry_id || null;
      const rows = [];

      if (operation) rows.push(renderEntityMeta('Operation', operation));
      if (moveToFolder) rows.push(renderEntityMeta('Move To Folder', moveToFolder));
      if (entryId) rows.push(renderEntityMeta('Entry ID', entryId));

      if (rows.length > 0) {
        extractedHtml = `<div class="detail-panel compact">${rows.join('')}</div>`;
      }
    }

    const dataStr = parsedData === undefined || parsedData === null
      ? ''
      : (typeof parsedData === 'string' ? parsedData : JSON.stringify(parsedData, null, 2));

    const evidenceKey = ev.rrn || ev.id || ev.event_id || `${ev.type || 'evidence'}-${ev.evented_at || ev.description || ''}`;
    const koiHighlightTerms = collectHighlightTermsFromEntries(alert.rule_keys_of_interest);
    const matchingHighlightPaths = [
      ...collectHighlightPathsFromEntries(alert.rule_matching_keys),
      ...collectHighlightPathsFromEntries(ev.rule_matching_keys)
    ].filter((term, index, allTerms) => allTerms.findIndex(candidate => candidate.toLowerCase() === term.toLowerCase()) === index);
    const matchingHighlightTermsByPath = new Map([
      ...collectHighlightTermsByPath(alert.rule_matching_keys),
      ...collectHighlightTermsByPath(ev.rule_matching_keys)
    ]);
    const highlightState = alert._payloadHighlightState?.[evidenceKey] || {};
    const payloadHighlightTerms = [
      ...(highlightState.koi ? koiHighlightTerms : [])
    ].filter((term, index, allTerms) => allTerms.findIndex(candidate => candidate.toLowerCase() === term.toLowerCase()) === index);

    return `
      <article class="evidence-card glass-panel">
        <div class="card-topline">
          <span class="badge badge-outline">${escapeHtml(ev.type || 'EVENT')}</span>
          <span class="card-chip">${escapeHtml(ev.event_type || 'Evidence')}</span>
        </div>
        <h4 class="evidence-title">${escapeHtml(ev.description || 'Evidence item')}</h4>
        ${renderEntryGrid([
          { label: 'Seen', value: formatDate(ev.evented_at) },
          { label: 'Source', value: ev.external_source }
        ], '')}
        ${formattedRuleMatchingKeys.length > 0 ? renderEntityMeta('Rule Matching Keys', formattedRuleMatchingKeys.join(', ')) : ''}
        ${Array.isArray(ev.log_details) && ev.log_details.length > 0 ? renderLogDetails(ev.log_details) : ''}
        ${extractedHtml}
        ${dataStr ? renderPayloadHighlightActions({
          evidenceKey,
          highlightKoi: Boolean(highlightState.koi),
          highlightMatching: Boolean(highlightState.matching)
        }) : ''}
        ${dataStr ? renderCopyableCodePanelWithOptions(dataStr, `${ev.type || 'evidence'} payload`, {
          highlightTerms: payloadHighlightTerms,
          highlightPaths: highlightState.matching ? matchingHighlightPaths : [],
          highlightTermsByPath: highlightState.matching ? matchingHighlightTermsByPath : new Map(),
          parsedValue: parsedData && typeof parsedData === 'object' ? parsedData : null,
          highlightEnabled: payloadHighlightTerms.length > 0 || (highlightState.matching && matchingHighlightPaths.length > 0),
          expandKey: evidenceKey,
          expanded: Boolean(alert._payloadExpandState?.[evidenceKey])
        }) : ''}
      </article>
    `;
  }).join('') : '<p class="detail-empty">No evidence found.</p>';

  const actorsBadgesHtml = renderGroupedActorBadges(alert._actors, 'Unknown Actor');
  const evidenceDataLoading = Boolean(alert._evidencesLoading && !alert._evidencesError && (alert._evidences || []).length === 0);
  const actorDataLoading = Boolean(alert._actorsLoading && !alert._actorsError && (alert._actors || []).length === 0);
  const processTreeDataLoading = Boolean(
    alert._processTreesLoading
    && !alert._processTreesError
    && (alert._processTrees || []).length === 0
  );
  const linkedInvestigationLoading = Boolean(
    alert.investigation_rrn
    && alert._investigationLoading
    && !alert._investigationError
  );
  const ruleSummaryLoading = Boolean(
    alert._ruleSummaryLoading
    && !alert._ruleSummaryError
    && !alert._ruleSummary
  );
  const actorsHtml = actorDataLoading
    ? renderDetailLoading('Loading related actors...')
    : alert._actorsError
    ? renderDetailError(alert._actorsError)
    : actorsBadgesHtml;

  const campaignHtml = renderBadgeStack(
    getCampaignLabels(alert.campaigns),
    'No campaign context returned.'
  );
  const processTreesHtml = processTreeDataLoading
    ? renderDetailLoading('Loading alert process trees...')
    : alert._processTreesError
    ? renderDetailError(alert._processTreesError)
    : renderProcessTrees(alert._processTrees || []);
  const linkedInvestigationHtml = linkedInvestigationLoading
    ? renderDetailLoading('Loading linked investigation...')
    : alert._investigationError
    ? `
      ${renderDetailError(alert._investigationError)}
      ${renderLinkedInvestigationCard(alert._investigation, alert.investigation_rrn)}
    `
    : renderLinkedInvestigationCard(alert._investigation, alert.investigation_rrn);
  const ruleSummaryHtml = ruleSummaryLoading
    ? renderDetailLoading('Loading detection rule summary...')
    : alert._ruleSummaryError
    ? renderDetailError(alert._ruleSummaryError)
    : renderRuleSummary(alert._ruleSummary || null, alert._mitreLookup || {});
  const evidencePanelHtml = evidenceDataLoading
    ? renderDetailLoading('Loading alert evidences...')
    : evidencesHtml;

  return `
    <div class="detail-stack">
      <section class="detail-hero glass-panel">
        <div class="card-topline">
          <span class="badge ${getBadgeClass(alert.priority)}">${escapeHtml(alert.priority || 'UNKNOWN')}</span>
          <span class="status-pill ${getStatusClass(alert.status)}">${escapeHtml(alert.status || 'OPEN')}</span>
        </div>
        <h2 class="detail-title">${escapeHtml(alert.title || 'Untitled Alert')}</h2>
        <div class="detail-grid">
          ${renderEntityMeta('Created', formatDate(alert.created_at || alert.alerted_at || alert.created_time || alert.createdTime))}
          ${renderEntityMeta('Time To Investigate', formatDuration(alert.status_transitions?.seconds_to_first_investigating))}
          ${renderEntityMeta('Source', alert.external_source || alert.type || alert.alert_source || 'SIEM')}
          ${renderEntityMeta('Disposition', alert.disposition || 'UNDECIDED')}
          ${renderEntityMeta('Responsibility', alert.responsibility || 'N/A')}
          ${renderEntityMeta('AI Suggestion', alert.ai_suggested_disposition || 'N/A')}
          ${renderEntityMeta('Assigned To', getAssigneeLabel(alert.assignee))}
        </div>
      </section>

      <section class="detail-section glass-panel">
        <div class="section-heading">
          <p class="eyebrow">Case Link</p>
          <h3>Linked investigation</h3>
        </div>
        ${linkedInvestigationHtml}
      </section>

      <section class="detail-section glass-panel">
        <div class="section-heading">
          <p class="eyebrow">Analyst Snapshot</p>
          <h3>Triage pivots</h3>
        </div>
        ${triagePivotsHtml}
        <div class="section-heading mt-4">
          <h3>Matched logic</h3>
        </div>
        ${matchingLogicHtml}
      </section>

      <section class="detail-section glass-panel">
        <div class="section-heading">
          <p class="eyebrow">Threat Context</p>
          <h3>Actors</h3>
        </div>
        ${actorsHtml}
      </section>

      ${renderCollapsibleDetailSection({
        eyebrow: 'External Enrichment',
        title: 'Public intel pivots',
        body: renderIndicatorPivots(alert)
      })}

      <section class="detail-section glass-panel">
        <div class="section-heading">
          <p class="eyebrow">Triggered Logic</p>
          <h3>Detection rule</h3>
        </div>
        ${ruleSummaryHtml}
      </section>

      <section class="detail-section glass-panel">
        <div class="section-heading">
          <p class="eyebrow">Evidence Chain</p>
          <h3>Telemetry payloads</h3>
        </div>
        <div class="evidence-grid">${evidencePanelHtml}</div>
      </section>

      <section class="detail-section glass-panel">
        <div class="section-heading">
          <p class="eyebrow">Endpoint Context</p>
          <h3>Process trees</h3>
        </div>
        ${processTreesHtml}
      </section>

      <section class="detail-section glass-panel">
        <div class="section-heading">
          <p class="eyebrow">Signal Labels</p>
          <h3>Campaigns</h3>
        </div>
        ${campaignHtml}
      </section>

      ${renderCollapsibleDetailSection({
        eyebrow: 'Decision Support',
        title: 'AI and telemetry context',
        body: `
          ${renderEntryGrid(
            decisionSupportEntries,
            'No AI or analytics support data was returned.',
            { layout: 'adaptive' }
          )}
          <div class="section-heading mt-4">
            <h3>Log references</h3>
          </div>
          ${renderLogDetails(alert.log_details)}
        `
      })}

      ${renderCollapsibleDetailSection({
        eyebrow: 'Operations',
        title: 'Timing and pivots',
        body: `
          ${eventSourceMetaHtml}
          ${alertOperationsHtml}
        `
      })}

      <form id="updateAlertForm" class="glass-panel detail-form">
        <div class="section-heading">
          <p class="eyebrow">Response</p>
          <h3>Update alert</h3>
        </div>
        <div class="form-group">
          <label for="updateAlertStatus">Status</label>
          <select id="updateAlertStatus" class="control-input">
            ${renderSelectOptions(ALERT_STATUS_OPTIONS, alert.status)}
          </select>
        </div>
        <div class="form-group">
          <label for="updateAlertPriority">Priority</label>
          <select id="updateAlertPriority" class="control-input">
            ${renderSelectOptions(ALERT_PRIORITY_OPTIONS, alert.priority)}
          </select>
        </div>
        <div class="form-group">
          <label for="updateAlertDisp">Disposition</label>
          <select id="updateAlertDisp" class="control-input">
            ${renderSelectOptions(ALERT_DISPOSITION_OPTIONS, alert.disposition)}
          </select>
        </div>
        ${renderAssigneeField({
          fieldId: 'updateAlertAssignee',
          label: 'Assign Analyst',
          currentValue: currentAssigneeValue,
          analysts,
          isLoading: analystsLoading,
          disabled: false,
          placeholder: 'Enter analyst id or email'
        })}
        <button class="btn mt-4" type="submit">Save Changes</button>
      </form>

      ${alert.investigation_rrn
        ? ''
        : '<button id="btn-create-inv" class="btn btn-secondary">Escalate to Investigation</button>'}
    </div>
  `;
}

export function renderInvestigationDetail(inv, options = {}) {
  const {
    analysts = [],
    analystsLoading = false
  } = options;
  const currentAssigneeValue = inv._assigneeDraft ?? getAssigneeValue(inv.assignee);
  const alertSummary = summarizeInvestigationAlerts(inv._alerts || []);
  const alertWindow = getInvestigationAlertWindow(inv._alerts || []);
  const alertDataLoading = Boolean(inv._alertsLoading && !inv._alertsError && (inv._alerts || []).length === 0);
  const actorDataLoading = Boolean(inv._actorsLoading && !inv._actorsError && (inv._actors || []).length === 0);
  const commentDataLoading = Boolean(inv._commentsLoading && !inv._commentsError && (inv._comments || []).length === 0);
  const attachmentDataLoading = Boolean(inv._attachmentsLoading && !inv._attachmentsError && (inv._attachments || []).length === 0);
  const relatedSources = Array.from(alertSummary.sources).slice(0, 6);
  const relatedRules = Array.from(alertSummary.rules).slice(0, 6);
  const openedAt = inv.created_time || inv.createdTime || null;
  const firstAlertTime = inv.first_alert_time || alertWindow.first?.value || null;
  const latestAlertTime = inv.latest_alert_time
    || inv.alerts_most_recent_created_time
    || inv.alerts_most_recent_detection_created_time
    || alertWindow.latest?.value
    || null;
  const detailErrorHtml = inv._detailError ? renderDetailError(inv._detailError) : '';
  const actorsHtml = actorDataLoading
    ? renderDetailLoading('Loading related actors...')
    : inv._actorsError
    ? renderDetailError(inv._actorsError)
    : `<div class="badge-row">${renderActorBadges(inv._actors, 'No related actors')}</div>`;
  const commentsHtml = commentDataLoading
    ? renderDetailLoading('Loading investigation comments...')
    : inv._commentsError
    ? renderDetailError(inv._commentsError)
    : renderCommentList(inv._comments || []);
  const attachmentsHtml = attachmentDataLoading
    ? renderDetailLoading('Loading investigation attachments...')
    : inv._attachmentsError
    ? renderDetailError(inv._attachmentsError)
    : renderAttachmentList(inv._attachments || []);
  const relatedAlertsHtml = alertDataLoading
    ? renderDetailLoading('Loading related alerts...')
    : inv._alertsError
    ? renderDetailError(inv._alertsError)
    : renderInvestigationAlertList(inv._alerts);
  const relatedSourcesHtml = alertDataLoading
    ? renderDetailLoading('Loading alert context...')
    : renderBadgeStack(relatedSources, 'No alert sources available yet.');
  const relatedRulesHtml = alertDataLoading
    ? renderDetailLoading('Loading detection rule context...')
    : renderBadgeStack(relatedRules, 'No detection rule names were returned.');

  return `
    <div class="detail-stack">
      <section class="detail-hero glass-panel">
        <div class="card-topline">
          <span class="badge ${getBadgeClass(inv.priority)}">${escapeHtml(inv.priority || 'MEDIUM')}</span>
          <span class="status-pill ${getStatusClass(inv.status)}">${escapeHtml(inv.status || 'OPEN')}</span>
        </div>
        <h2 class="detail-title">${escapeHtml(inv.title || 'Untitled Investigation')}</h2>
        <div class="detail-grid">
          ${renderEntityMeta('Disposition', inv.disposition || 'N/A')}
          ${renderEntityMeta('Responsibility', inv.responsibility || 'N/A')}
          ${renderEntityMeta('Source', inv.source || 'N/A')}
          ${renderEntityMeta('Assigned To', inv.assignee ? (inv.assignee.name || inv.assignee.email || inv.assignee) : 'Unassigned')}
          ${renderEntityMeta('Case ID', inv.id || inv.rrn || 'N/A', { className: 'meta-row-full' })}
        </div>
        ${detailErrorHtml}
      </section>

      <section class="detail-section glass-panel">
        <div class="section-heading">
          <p class="eyebrow">Timeline</p>
          <h3>Operational timestamps</h3>
        </div>
        <div class="detail-grid">
          ${renderEntityMeta('Created', formatDate(openedAt))}
          ${renderTrustedHtmlMeta(
            'Open For',
            `<span class="js-investigation-open-timer" data-opened-at="${escapeHtml(openedAt || '')}">${escapeHtml(formatElapsedDuration(openedAt))}</span>`
          )}
          ${renderEntityMeta('First Alert', formatDate(firstAlertTime))}
          ${renderEntityMeta('Latest Alert', formatDate(latestAlertTime))}
          ${renderEntityMeta('Last Accessed', formatDate(inv.last_accessed))}
        </div>
      </section>

      <section class="detail-section glass-panel">
        <div class="section-heading">
          <p class="eyebrow">Alert Pressure</p>
          <h3>Case scope</h3>
        </div>
        <div class="detail-grid">
          ${renderEntityMeta('Linked Alerts', alertDataLoading ? 'Loading' : String(alertSummary.total))}
          ${renderEntityMeta('Active Alerts', alertDataLoading ? 'Loading' : String(alertSummary.active))}
          ${renderEntityMeta('Critical Alerts', alertDataLoading ? 'Loading' : String(alertSummary.critical))}
          ${renderEntityMeta('High Alerts', alertDataLoading ? 'Loading' : String(alertSummary.high))}
          ${renderEntityMeta('Sources', alertDataLoading ? 'Loading' : String(alertSummary.sources.size))}
          ${renderEntityMeta('Rules', alertDataLoading ? 'Loading' : String(alertSummary.rules.size))}
          ${renderEntityMeta('Comments', formatLoadAwareCount(inv._comments, commentDataLoading))}
          ${renderEntityMeta('Attachments', formatLoadAwareCount(inv._attachments, attachmentDataLoading))}
        </div>
        <div class="section-heading mt-4">
          <h3>Source coverage</h3>
        </div>
        ${relatedSourcesHtml}
        <div class="section-heading mt-4">
          <h3>Detection rules</h3>
        </div>
        ${relatedRulesHtml}
      </section>

      <section class="detail-section glass-panel">
        <div class="section-heading">
          <p class="eyebrow">Related Entities</p>
          <h3>Actors</h3>
        </div>
        ${actorsHtml}
      </section>

      ${renderInvestigationCommentComposer()}

      <section class="detail-section glass-panel">
        <div class="section-heading">
          <p class="eyebrow">Collaboration Log</p>
          <h3>Comments</h3>
        </div>
        ${commentsHtml}
      </section>

      <section class="detail-section glass-panel">
        <div class="section-heading">
          <p class="eyebrow">Case Files</p>
          <h3>Attachments</h3>
        </div>
        ${attachmentsHtml}
      </section>

      <section class="detail-section glass-panel">
        <div class="section-heading">
          <p class="eyebrow">Linked Signals</p>
          <h3>Related alerts</h3>
        </div>
        ${relatedAlertsHtml}
      </section>

      <form id="updateInvForm" class="glass-panel detail-form">
        <div class="section-heading">
          <p class="eyebrow">Workflow</p>
          <h3>Update investigation</h3>
        </div>
        <div class="form-group">
          <label for="updateInvStatus">Status</label>
          <select id="updateInvStatus" class="control-input">
            ${renderSelectOptions(INVESTIGATION_STATUS_OPTIONS, inv.status)}
          </select>
        </div>
        <div class="form-group">
          <label for="updateInvPriority">Priority</label>
          <select id="updateInvPriority" class="control-input">
            ${renderSelectOptions(INVESTIGATION_PRIORITY_OPTIONS, inv.priority)}
          </select>
        </div>
        <div class="form-group">
          <label for="updateInvDisp">Disposition</label>
          <select id="updateInvDisp" class="control-input">
            ${!inv.disposition ? '<option value="" selected>No change</option>' : ''}
            ${renderSelectOptions(INVESTIGATION_DISPOSITION_OPTIONS, inv.disposition, ' (Current)')}
          </select>
        </div>
        ${renderAssigneeField({
          fieldId: 'updateInvAssignee',
          label: 'Assign Analyst',
          currentValue: currentAssigneeValue,
          analysts,
          isLoading: analystsLoading,
          disabled: false,
          placeholder: 'Enter analyst email directly'
        })}
        <button class="btn mt-4" type="submit">Save Changes</button>
      </form>
    </div>
  `;
}
