import {
  renderAlertList,
  renderAlertStackDetail,
  renderInvestigationList,
  renderHealthOverview,
  renderAlertDetail,
  renderInvestigationDetail
} from './components.js';

const API_BASE = '/api';
const INVESTIGATION_DISPOSITION_UPDATE_OPTIONS = new Set(['BENIGN', 'MALICIOUS', 'NOT_APPLICABLE']);
const ALERT_PRIORITY_WEIGHT = Object.freeze({
  CRITICAL: 6,
  HIGH: 5,
  MEDIUM: 4,
  LOW: 3,
  INFO: 2,
  UNMAPPED: 1,
  UNKNOWN: 0
});
const ALERT_GROUPING_MODE_LABELS = Object.freeze({
  HYBRID: 'Hybrid Stack',
  STREAM: 'Signal Stream',
  TECHNIQUE: 'Technique View',
  INVESTIGATION: 'Investigation View',
  OBSERVABLE: 'Observable Pairs',
  ATTACK_PATH: 'Attack Paths'
});
const ATTACK_PATH_SHARED_SIGNAL_EXCLUDE_IDS = new Set(['detection', 'signature']);
const ATTACK_PATH_MITRE_LABELS = Object.freeze({
  TA0001: 'Initial Access',
  TA0002: 'Execution',
  TA0003: 'Persistence',
  TA0004: 'Privilege Escalation',
  TA0005: 'Defense Evasion',
  TA0006: 'Credential Access',
  TA0007: 'Discovery',
  TA0008: 'Lateral Movement',
  TA0009: 'Collection',
  TA0010: 'Exfiltration',
  TA0011: 'Command and Control',
  TA0040: 'Impact',
  TA0042: 'Resource Development'
});
const LOW_CARDINALITY_MATCH_KEYS = new Set(['action', 'entryType', 'result', 'service', 'signature']);
const WRAPPER_PROCESS_NAMES = new Set(['cmd', 'cmd.exe', 'powershell', 'powershell.exe', 'pwsh', 'pwsh.exe', 'bash', 'sh', 'wscript', 'wscript.exe', 'cscript', 'cscript.exe']);
const COMMAND_FOCUS_NOISE = new Set([
  'c',
  'k',
  'command',
  'encodedcommand',
  'enc',
  'ec',
  'e',
  'executionpolicy',
  'windowstyle',
  'nologo',
  'noprofile',
  'noninteractive',
  'nop',
  'file',
  'f',
  'inputformat',
  'outputformat',
  'unrestricted',
  'bypass',
  'hidden',
  'start',
  'powershell',
  'powershell.exe',
  'pwsh',
  'pwsh.exe',
  'cmd',
  'cmd.exe',
  'bash',
  'sh'
]);
const SHARED_FIELD_SIGNAL_SKIP_KEYS = new Set([
  'account',
  'action',
  'asset',
  'destination_ip',
  'destination_port',
  'hostname',
  'parent_process.cmd_line',
  'parent_process.exe_file.hashes.md5',
  'parent_process.exe_path',
  'parent_process.name',
  'process.cmd_line',
  'process.exe_path',
  'process.name',
  'result',
  'service',
  'signature',
  'source_account',
  'source_ip',
  'target_account',
  'url'
]);
const waitForNextPaint = () => new Promise(resolve => requestAnimationFrame(() => resolve()));
const escapeHtml = value => String(value || '')
  .replace(/&/g, '&amp;')
  .replace(/</g, '&lt;')
  .replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;')
  .replace(/'/g, '&#39;');
const getAssigneeInputValue = assignee => {
  if (!assignee) return '';
  if (typeof assignee === 'string') return assignee;
  return assignee.email || assignee.rrn || assignee.id || '';
};
const normalizeTextValue = value => String(value ?? '').trim();
const normalizeSelectionValue = value => normalizeTextValue(value).toUpperCase();
const formatInvestigationOpenDuration = (timestamp, now = Date.now()) => {
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
};

const normalizeWhitespace = value => String(value ?? '').trim().replace(/\s+/g, ' ');
const normalizeKeyToken = value => normalizeWhitespace(value).toLowerCase();
const getAlertTimestampValue = alert => (
  alert.created_at
  || alert.alerted_at
  || alert.created_time
  || alert.createdTime
  || alert.updated_at
  || ''
);
const getAlertTimestampMs = alert => {
  const parsed = Date.parse(getAlertTimestampValue(alert));
  return Number.isNaN(parsed) ? 0 : parsed;
};
const getAlertPriorityWeight = priority => ALERT_PRIORITY_WEIGHT[String(priority || 'UNKNOWN').toUpperCase()] || 0;
const shortRef = value => {
  const normalized = normalizeWhitespace(value);
  if (!normalized) return '';
  const parts = normalized.split(':').filter(Boolean);
  return parts[parts.length - 1] || normalized;
};
const formatCountLabel = (count, singular, plural = `${singular}s`) => `${count} ${count === 1 ? singular : plural}`;
const uniqueValues = values => [...new Set((values || []).filter(Boolean))];
const parseUrlHost = value => {
  const normalized = normalizeWhitespace(value);
  if (!normalized) return '';

  try {
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(normalized)) {
      return new URL(normalized).hostname || '';
    }

    return new URL(`https://${normalized}`).hostname || '';
  } catch (error) {
    return normalized
      .replace(/^[a-z][a-z0-9+.-]*:\/\//i, '')
      .split('/')[0]
      .split('?')[0];
  }
};
const buildAlertFieldMap = entries => (Array.isArray(entries) ? entries : []).reduce((acc, entry) => {
  const key = normalizeWhitespace(entry?.key);
  if (!key) return acc;

  const value = Array.isArray(entry?.values)
    ? entry.values.map(item => normalizeWhitespace(item)).filter(Boolean).join(' | ')
    : normalizeWhitespace(entry?.value);

  if (value) {
    acc[key] = value;
  }

  return acc;
}, {});
const getAlertFieldValue = (fieldMap, keys) => {
  for (const key of keys) {
    const value = normalizeWhitespace(fieldMap?.[key]);
    if (value) return value;
  }

  return '';
};
const normalizeCommandSignature = value => normalizeKeyToken(value)
  .replace(/ec2launch\d+/g, 'ec2launch#')
  .replace(/attack_\d+\.ps1/g, 'attack.ps1')
  .replace(/\b[0-9a-f]{32,64}\b/g, '<hash>')
  .replace(/\b\d{3,}\b/g, '<num>');
const formatDescriptorText = value => normalizeWhitespace(value)
  .replace(/[_-]+/g, ' ')
  .replace(/\s+/g, ' ')
  .replace(/\b\w/g, char => char.toUpperCase());
const getPathBasename = value => normalizeWhitespace(value).split(/[\\/]/).pop() || normalizeWhitespace(value);
const normalizeExecutableName = value => {
  const basename = getPathBasename(value).toLowerCase();
  if (!basename) return '';
  return basename.replace(/\d+(?=(\.[a-z0-9]+)?$)/i, '');
};
const formatFieldSignalLabel = key => formatDescriptorText(String(key || '').replace(/[._]+/g, ' '));
const createSignalEntry = (id, label, value) => {
  const normalizedValue = normalizeWhitespace(value);
  if (!normalizedValue) return null;

  return {
    id: normalizeWhitespace(id || label || normalizedValue),
    label: normalizeWhitespace(label) || 'Signal',
    value: normalizedValue,
    key: `${normalizeWhitespace(id || label || 'signal')}:${normalizeKeyToken(normalizedValue)}`
  };
};
const mergeSignalEntries = (...groups) => {
  const unique = new Map();
  const renderedPairs = new Set();

  groups.flat().filter(Boolean).forEach(entry => {
    const key = entry.key || `${normalizeWhitespace(entry.label)}:${normalizeKeyToken(entry.value)}`;
    const renderedPairKey = `${normalizeWhitespace(entry.label)}:${normalizeKeyToken(entry.value)}`;
    if (!key || unique.has(key) || renderedPairs.has(renderedPairKey)) return;
    unique.set(key, entry);
    renderedPairs.add(renderedPairKey);
  });

  return [...unique.values()];
};
const formatSignalSummary = (entries, fallback = '', maxItems = 2) => {
  const summary = (entries || [])
    .slice(0, maxItems)
    .map(entry => `${entry.label}: ${entry.value}`)
    .join(' • ');

  return summary || fallback;
};
const buildDestinationValue = meta => (
  meta.destinationIp
    ? `${meta.destinationIp}${meta.destinationPort ? `:${meta.destinationPort}` : ''}`
    : ''
);
const buildFlowValue = meta => (
  meta.sourceIp && meta.destinationIp
    ? `${meta.sourceIp} -> ${buildDestinationValue(meta)}`
    : ''
);
const buildServiceActionValue = meta => [meta.service, meta.action, meta.result].filter(Boolean).join(' • ');
const buildServiceActionPairValue = meta => [meta.service, meta.action].filter(Boolean).join(' • ');
const buildProcessLineageValue = meta => {
  const parent = normalizeExecutableName(meta.parentName || meta.parentPath);
  const process = normalizeExecutableName(meta.processName || meta.processPath);
  const parts = [];

  if (parent) parts.push(formatDescriptorText(parent.replace(/\.[a-z0-9]+$/i, '')));
  if (process && (!parent || process !== parent || !WRAPPER_PROCESS_NAMES.has(process))) {
    parts.push(formatDescriptorText(process.replace(/\.[a-z0-9]+$/i, '')));
  }

  return parts.join(' -> ');
};
const buildCommandFocusValue = (meta, limit = 2) => uniqueValues([
  ...extractCommandFocusTokens(meta.processCmd, meta.processName, limit),
  ...extractCommandFocusTokens(meta.parentCmd, meta.parentName, limit)
])
  .slice(0, limit)
  .map(formatDescriptorText)
  .join(' • ');
const buildAssetScopeValue = meta => meta.hostname || meta.asset || '';
const buildAssetScopeLabel = meta => (meta.hostname ? 'Host' : 'Asset');
const buildAssetScopeSignal = meta => createSignalEntry(
  meta.hostname ? 'host' : 'asset',
  buildAssetScopeLabel(meta),
  buildAssetScopeValue(meta)
);
const buildProcessDisplayValue = meta => meta.processName || getPathBasename(meta.processPath);
const getStackSignalSpecs = () => [
  { id: 'campaign', label: 'Campaign', getValue: meta => meta.campaignLabel },
  { id: 'hostname', label: 'Host', getValue: meta => meta.hostname },
  { id: 'asset', label: 'Asset', getValue: meta => meta.asset },
  { id: 'sourceAccount', label: 'Actor', getValue: meta => meta.sourceAccount },
  { id: 'account', label: 'Account', getValue: meta => meta.account },
  { id: 'targetAccount', label: 'Target', getValue: meta => meta.targetAccount },
  { id: 'actorTarget', label: 'Actor -> Target', getValue: meta => (
    meta.sourceAccount && meta.targetAccount
      ? `${meta.sourceAccount} -> ${meta.targetAccount}`
      : ''
  ) },
  { id: 'sourceIp', label: 'Source IP', getValue: meta => meta.sourceIp },
  { id: 'destination', label: 'Destination', getValue: meta => buildDestinationValue(meta) },
  { id: 'flow', label: 'Network Flow', getValue: meta => buildFlowValue(meta) },
  { id: 'destinationHost', label: 'Destination Host', getValue: meta => meta.urlHost },
  { id: 'service', label: 'Service', getValue: meta => meta.service },
  { id: 'action', label: 'Action', getValue: meta => meta.action },
  { id: 'result', label: 'Result', getValue: meta => meta.result },
  { id: 'serviceAction', label: 'Service Action', getValue: meta => buildServiceActionValue(meta) },
  { id: 'process', label: 'Process', getValue: meta => meta.processName || getPathBasename(meta.processPath) },
  { id: 'parentProcess', label: 'Parent Process', getValue: meta => meta.parentName || getPathBasename(meta.parentPath) },
  { id: 'processLineage', label: 'Process Lineage', getValue: meta => buildProcessLineageValue(meta) },
  { id: 'signature', label: 'Signature', getValue: meta => meta.signature },
  { id: 'eventType', label: 'Event Type', getValue: meta => meta.eventType },
  { id: 'detection', label: 'Detection', getValue: meta => meta.title }
];
const collectSharedSignalEntries = (alerts, options = {}) => {
  const {
    limit = 6,
    minCount = 2,
    minCoverage = alerts.length <= 2 ? 0.5 : 0.6,
    excludeIds = new Set()
  } = options;

  const requiredCount = Math.min(Math.max(minCount, 1), Math.max(alerts.length, 1));
  const signalEntries = [];

  getStackSignalSpecs().forEach(spec => {
    if (excludeIds.has(spec.id)) return;

    const values = alerts
      .map(alert => spec.getValue(alert?._stackMeta || buildAlertStackMeta(alert)))
      .map(value => normalizeWhitespace(value))
      .filter(Boolean);

    if (values.length < requiredCount) return;

    const normalizedValues = uniqueValues(values.map(value => normalizeKeyToken(value)));
    if (normalizedValues.length !== 1) return;
    if ((values.length / Math.max(alerts.length, 1)) < minCoverage) return;

    const entry = createSignalEntry(spec.id, spec.label, values[0]);
    if (entry) {
      signalEntries.push(entry);
    }
  });

  return signalEntries.slice(0, limit);
};
const collectSharedFieldMapSignals = (alerts, mapKey, options = {}) => {
  const {
    limit = 4,
    minCount = 2,
    minCoverage = alerts.length <= 2 ? 0.5 : 0.6,
    excludeKeys = SHARED_FIELD_SIGNAL_SKIP_KEYS
  } = options;

  const requiredCount = Math.min(Math.max(minCount, 1), Math.max(alerts.length, 1));
  const statsByKey = new Map();

  alerts.forEach(alert => {
    const fieldMap = alert?._stackMeta?.[mapKey] || {};

    Object.entries(fieldMap).forEach(([rawKey, rawValue]) => {
      const key = normalizeWhitespace(rawKey);
      const value = normalizeWhitespace(rawValue);

      if (!key || !value) return;
      if (excludeKeys.has(key)) return;
      if (value.length > 120) return;
      if (/^[0-9a-f]{24,}$/i.test(value)) return;

      if (!statsByKey.has(key)) {
        statsByKey.set(key, {
          key,
          count: 0,
          values: new Map()
        });
      }

      const stats = statsByKey.get(key);
      stats.count += 1;

      const valueKey = normalizeKeyToken(value);
      if (!stats.values.has(valueKey)) {
        stats.values.set(valueKey, value);
      }
    });
  });

  return [...statsByKey.values()]
    .filter(stats => stats.count >= requiredCount)
    .filter(stats => stats.values.size === 1)
    .filter(stats => (stats.count / Math.max(alerts.length, 1)) >= minCoverage)
    .sort((a, b) => b.count - a.count || a.key.localeCompare(b.key))
    .map(stats => createSignalEntry(`${mapKey}:${stats.key}`, formatFieldSignalLabel(stats.key), [...stats.values.values()][0]))
    .filter(Boolean)
    .slice(0, limit);
};
const normalizeCommandFocusToken = token => {
  const trimmed = normalizeWhitespace(token).replace(/^['"`]+|['"`]+$/g, '');
  if (!trimmed) return '';

  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed)) {
    return parseUrlHost(trimmed);
  }

  if (/^[a-z]:\\/i.test(trimmed) || /^[\\/]/.test(trimmed)) {
    return normalizeExecutableName(trimmed);
  }

  if (/\.(exe|dll|ps1|bat|cmd|vbs|js|py|sh)$/i.test(trimmed)) {
    return normalizeExecutableName(trimmed);
  }

  const withoutSwitchPrefix = trimmed.replace(/^[-/]+/, '');
  const normalized = withoutSwitchPrefix
    .toLowerCase()
    .replace(/[<>{}()[\],;]+/g, '')
    .replace(/^['"`]+|['"`]+$/g, '');

  if (!normalized) return '';

  if (/^[a-z]+[0-9]+(?:\.[a-z0-9]+)?$/i.test(normalized)) {
    return normalized.replace(/[0-9]+(?=(\.[a-z0-9]+)?$)/i, '');
  }

  return normalized;
};
const extractCommandFocusTokens = (commandLine, processName = '', limit = 3) => {
  const tokens = String(commandLine || '').match(/"[^"]+"|'[^']+'|\S+/g) || [];
  const normalizedProcessName = normalizeExecutableName(processName);
  const focusTokens = [];

  for (const rawToken of tokens) {
    const normalizedToken = normalizeCommandFocusToken(rawToken);
    if (!normalizedToken) continue;
    if (normalizedToken === normalizedProcessName) continue;
    if (COMMAND_FOCUS_NOISE.has(normalizedToken)) continue;
    if (/^[0-9a-f]{24,}$/i.test(normalizedToken)) continue;
    if (/^[a-z0-9+/=]{28,}$/i.test(normalizedToken) && !normalizedToken.includes('.')) continue;
    if (normalizedToken.length <= 1) continue;
    if (!focusTokens.includes(normalizedToken)) {
      focusTokens.push(normalizedToken);
    }
    if (focusTokens.length >= limit) {
      break;
    }
  }

  return focusTokens;
};
const getProcessTechniqueFingerprint = meta => {
  const normalizedProcessName = normalizeExecutableName(meta.processName);
  const normalizedParentName = normalizeExecutableName(meta.parentName);
  const directFocus = extractCommandFocusTokens(meta.processCmd, meta.processName);
  const parentFocus = extractCommandFocusTokens(meta.parentCmd, meta.parentName);
  const focusTokens = uniqueValues([
    ...directFocus,
    ...parentFocus
  ]).slice(0, 3);
  const lineageParts = [];

  if (normalizedParentName) lineageParts.push(formatDescriptorText(normalizedParentName.replace(/\.[a-z0-9]+$/i, '')));
  if (normalizedProcessName && (!normalizedParentName || normalizedProcessName !== normalizedParentName || !WRAPPER_PROCESS_NAMES.has(normalizedProcessName))) {
    lineageParts.push(formatDescriptorText(normalizedProcessName.replace(/\.[a-z0-9]+$/i, '')));
  }

  const focusLabel = focusTokens.map(formatDescriptorText).join(' • ');
  const lineageLabel = lineageParts.join(' -> ');
  const wrapperOnly = normalizedProcessName && WRAPPER_PROCESS_NAMES.has(normalizedProcessName);

  if (focusTokens.length === 0 && !lineageLabel) {
    return null;
  }

  const signals = mergeSignalEntries(
    createSignalEntry('processLineage', 'Process Lineage', lineageLabel),
    createSignalEntry('commandFocus', 'Command Focus', focusLabel),
    createSignalEntry('eventType', 'Event Type', meta.eventType)
  );

  return {
    key: [
      'technique:process',
      normalizeKeyToken(lineageLabel || normalizedProcessName || 'process'),
      focusTokens.map(normalizeKeyToken).join(':'),
      normalizeKeyToken(meta.eventType)
    ].filter(Boolean).join(':'),
    label: `Technique: ${lineageLabel || formatDescriptorText(normalizedProcessName || meta.eventType || 'Process Activity')}${focusLabel ? ` • ${focusLabel}` : ''}`,
    reason: wrapperOnly || focusTokens.length > 0
      ? 'shared process lineage and command focus'
      : 'shared process telemetry pattern',
    signals
  };
};
const extractCampaignLabel = alert => {
  const campaigns = Array.isArray(alert?.campaigns) ? alert.campaigns : [];
  const labels = campaigns.map(campaign => (
    normalizeWhitespace(
      typeof campaign === 'string'
        ? campaign
        : campaign?.name || campaign?.title || campaign?.label || campaign?.id || campaign?.rrn || ''
    )
  )).filter(Boolean);

  return labels[0] || '';
};
const compareAlertsByPriorityThenTime = (a, b) => {
  const priorityDelta = getAlertPriorityWeight(b.priority) - getAlertPriorityWeight(a.priority);
  if (priorityDelta !== 0) return priorityDelta;
  return getAlertTimestampMs(b) - getAlertTimestampMs(a);
};
const getStatusCounts = alerts => alerts.reduce((acc, alert) => {
  const status = String(alert.status || 'OPEN').toUpperCase();
  acc[status] = (acc[status] || 0) + 1;
  return acc;
}, {});
const getStatusSummary = alerts => {
  const counts = Object.entries(getStatusCounts(alerts))
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));

  if (!counts.length) {
    return {
      label: 'OPEN',
      className: 'OPEN',
      detail: 'No status metadata'
    };
  }

  if (counts.length === 1) {
    return {
      label: counts[0][0],
      className: counts[0][0],
      detail: `${counts[0][1]} ${counts[0][0].toLowerCase()}`
    };
  }

  return {
    label: 'MIXED',
    className: 'MIXED',
    detail: counts.map(([status, count]) => `${count} ${status.toLowerCase()}`).join(' • ')
  };
};
const buildPrimaryEntity = candidate => {
  if (candidate.campaignLabel) {
    return {
      type: 'campaign',
      key: `campaign:${normalizeKeyToken(candidate.campaignLabel)}`,
      label: `Campaign: ${candidate.campaignLabel}`,
      shortLabel: candidate.campaignLabel,
      reason: 'same campaign context',
      signals: [createSignalEntry('campaign', 'Campaign', candidate.campaignLabel)].filter(Boolean)
    };
  }

  const orderedCandidates = [
    ['account', 'Account', candidate.sourceAccount],
    ['account', 'Account', candidate.account],
    ['host', 'Host', candidate.hostname],
    ['asset', 'Asset', candidate.asset],
    ['ip', 'Source IP', candidate.sourceIp],
    ['account', 'Target', candidate.targetAccount],
    ['ip', 'Destination IP', candidate.destinationIp]
  ];

  const match = orderedCandidates.find(([, , value]) => value);
  if (match) {
    const [type, prefix, value] = match;
    return {
      type,
      key: `${type}:${normalizeKeyToken(value)}`,
      label: `${prefix}: ${value}`,
      shortLabel: value,
      reason: `same ${prefix.toLowerCase()}`,
      signals: [createSignalEntry(type, prefix, value)].filter(Boolean)
    };
  }

  return {
    type: 'title',
    key: `title:${normalizeKeyToken(candidate.title)}`,
    label: candidate.title,
    shortLabel: candidate.title,
    reason: 'same detection family',
    signals: [createSignalEntry('detection', 'Detection', candidate.title)].filter(Boolean)
  };
};
const buildAlertStackMeta = alert => {
  const koiMap = buildAlertFieldMap(alert.rule_keys_of_interest);
  const matchingMap = buildAlertFieldMap(alert.rule_matching_keys);
  const title = normalizeWhitespace(alert.title || alert.type || alert.external_source || 'Untitled Alert');
  const campaignLabel = extractCampaignLabel(alert);
  const sourceAccount = getAlertFieldValue(koiMap, ['source_account']) || getAlertFieldValue(matchingMap, ['source_account']);
  const account = getAlertFieldValue(koiMap, ['account']) || getAlertFieldValue(matchingMap, ['account']);
  const targetAccount = getAlertFieldValue(koiMap, ['target_account']) || getAlertFieldValue(matchingMap, ['target_account']);
  const hostname = getAlertFieldValue(koiMap, ['hostname']) || getAlertFieldValue(matchingMap, ['hostname']);
  const asset = getAlertFieldValue(koiMap, ['asset']) || getAlertFieldValue(matchingMap, ['asset']);
  const sourceIp = getAlertFieldValue(koiMap, ['source_ip']) || getAlertFieldValue(matchingMap, ['source_ip']);
  const destinationIp = getAlertFieldValue(koiMap, ['destination_ip']) || getAlertFieldValue(matchingMap, ['destination_ip']);
  const destinationPort = getAlertFieldValue(koiMap, ['destination_port']) || getAlertFieldValue(matchingMap, ['destination_port']);
  const service = getAlertFieldValue(koiMap, ['service']) || getAlertFieldValue(matchingMap, ['service']);
  const action = getAlertFieldValue(koiMap, ['action']) || getAlertFieldValue(matchingMap, ['action']);
  const result = getAlertFieldValue(koiMap, ['result']) || getAlertFieldValue(matchingMap, ['result']);
  const url = getAlertFieldValue(koiMap, ['url']) || getAlertFieldValue(matchingMap, ['url']);
  const urlHost = parseUrlHost(url);
  const signature = getAlertFieldValue(koiMap, ['signature']) || getAlertFieldValue(matchingMap, ['signature']);
  const processName = getAlertFieldValue(koiMap, ['process.name']);
  const processPath = getAlertFieldValue(koiMap, ['process.exe_path']);
  const processCmd = getAlertFieldValue(koiMap, ['process.cmd_line']);
  const parentName = getAlertFieldValue(koiMap, ['parent_process.name']);
  const parentHash = getAlertFieldValue(koiMap, ['parent_process.exe_file.hashes.md5']);
  const parentCmd = getAlertFieldValue(koiMap, ['parent_process.cmd_line']);
  const parentPath = getAlertFieldValue(koiMap, ['parent_process.exe_path']);
  const primaryEntity = buildPrimaryEntity({
    campaignLabel,
    sourceAccount,
    account,
    targetAccount,
    hostname,
    asset,
    sourceIp,
    destinationIp,
    title
  });

  const preview = sourceAccount && targetAccount
    ? `${sourceAccount} -> ${targetAccount}`
    : sourceIp && destinationIp
      ? `${sourceIp} -> ${destinationIp}${destinationPort ? `:${destinationPort}` : ''}`
      : hostname && processName
        ? `${hostname} • ${processName}`
        : asset && urlHost
          ? `${asset} -> ${urlHost}`
          : service && action
            ? `${service} • ${action}`
            : primaryEntity.shortLabel;

  return {
    title,
    titleKey: normalizeKeyToken(title),
    ruleId: normalizeWhitespace(alert.rule?.rrn || alert.rule?.version_rrn || title),
    timestamp: getAlertTimestampValue(alert),
    timestampMs: getAlertTimestampMs(alert),
    priorityWeight: getAlertPriorityWeight(alert.priority),
    status: String(alert.status || 'OPEN').toUpperCase(),
    eventType: normalizeWhitespace(alert.triggering_event_type),
    campaignLabel,
    sourceAccount,
    account,
    targetAccount,
    hostname,
    asset,
    sourceIp,
    destinationIp,
    destinationPort,
    service,
    action,
    result,
    url,
    urlHost,
    signature,
    processName,
    processPath,
    processCmd,
    parentName,
    parentHash,
    parentCmd,
    parentPath,
    primaryEntity,
    preview,
    koiMap,
    matchingMap
  };
};
const getAlertMitreCodes = alert => uniqueValues(
  (alert?.rule?.mitre_tcodes || [])
    .map(code => normalizeWhitespace(code).toUpperCase())
    .filter(code => ATTACK_PATH_MITRE_LABELS[code])
);
const getAttackPathEventTypeLabel = eventType => {
  const normalized = normalizeWhitespace(eventType);
  if (!normalized) return 'Event Activity';
  return formatDescriptorText(normalized.replace(/_/g, ' '));
};
const getAttackPathEventFamily = meta => {
  const eventType = normalizeKeyToken(meta?.eventType);
  const hasIdentityContext = Boolean(meta?.sourceAccount || meta?.account || meta?.targetAccount || meta?.service || meta?.action || meta?.result);
  const hasNetworkContext = Boolean(buildFlowValue(meta) || buildDestinationValue(meta) || meta?.urlHost || meta?.sourceIp || meta?.destinationIp);
  const hasProcessContext = Boolean(
    buildProcessLineageValue(meta)
    || buildCommandFocusValue(meta)
    || buildProcessDisplayValue(meta)
    || meta?.processName
    || meta?.parentName
    || meta?.processPath
    || meta?.parentPath
  );
  const hasAssetContext = Boolean(buildAssetScopeValue(meta));

  if (
    /(?:^|_)(auth|login|identity|account|user|cloud_service)(?:_|$)/.test(eventType)
    || hasIdentityContext
  ) {
    return 'identity';
  }

  if (
    /(?:^|_)(network|connection|dns|flow|ids|proxy|firewall)(?:_|$)/.test(eventType)
    || hasNetworkContext
  ) {
    return 'network';
  }

  if (
    /(?:^|_)(process|script|execution|command)(?:_|$)/.test(eventType)
    || hasProcessContext
  ) {
    return 'process';
  }

  if (
    /(?:^|_)(host|asset|endpoint|registry|file|service|task)(?:_|$)/.test(eventType)
    || hasAssetContext
  ) {
    return 'asset';
  }

  return 'event';
};
const getAttackPathStageLabel = alert => {
  const meta = alert._stackMeta || buildAlertStackMeta(alert);
  const mitreCodes = getAlertMitreCodes(alert);
  const preferredMitreCode = [
    'TA0010',
    'TA0011',
    'TA0006',
    'TA0005',
    'TA0004',
    'TA0003',
    'TA0008',
    'TA0007',
    'TA0002',
    'TA0001',
    'TA0009',
    'TA0040',
    'TA0042'
  ].find(code => mitreCodes.includes(code)) || mitreCodes[0];

  if (preferredMitreCode) {
    return ATTACK_PATH_MITRE_LABELS[preferredMitreCode];
  }

  const eventFamily = getAttackPathEventFamily(meta);

  if (eventFamily === 'identity') {
    return 'Identity Activity';
  }

  if (eventFamily === 'network') {
    return 'Network Activity';
  }

  if (eventFamily === 'process') {
    return 'Process Activity';
  }

  if (eventFamily === 'asset') {
    return 'Asset Activity';
  }

  return getAttackPathEventTypeLabel(meta.eventType);
};
const buildAttackPathDescriptor = alert => {
  const meta = alert._stackMeta || buildAlertStackMeta(alert);
  const assetScope = buildAssetScopeValue(meta);
  const destination = buildDestinationValue(meta) || meta.urlHost;
  const serviceAction = buildServiceActionPairValue(meta);
  const processLineage = buildProcessLineageValue(meta);
  const actorTarget = meta.sourceAccount && meta.targetAccount
    ? `${meta.sourceAccount} -> ${meta.targetAccount}`
    : '';
  const eventFamily = getAttackPathEventFamily(meta);

  if (meta.campaignLabel) {
    return {
      key: `attack-path:campaign:${normalizeKeyToken(meta.campaignLabel)}`,
      label: `Campaign Path: ${meta.campaignLabel}`,
      reason: 'shared campaign context',
      family: 'campaign',
      signals: [createSignalEntry('campaign', 'Campaign', meta.campaignLabel)].filter(Boolean)
    };
  }

  if (assetScope && (eventFamily === 'process' || processLineage)) {
    return {
      key: `attack-path:host:${normalizeKeyToken(assetScope)}`,
      label: `Host Path: ${assetScope}`,
      reason: 'shared host timeline',
      family: 'host',
      signals: mergeSignalEntries(
        buildAssetScopeSignal(meta),
        createSignalEntry('processLineage', 'Process Lineage', processLineage)
      )
    };
  }

  if (meta.sourceIp && destination) {
    return {
      key: `attack-path:network:${normalizeKeyToken(meta.sourceIp)}:${normalizeKeyToken(destination)}`,
      label: `Network Path: ${meta.sourceIp} -> ${destination}`,
      reason: 'shared network flow',
      family: 'network',
      signals: mergeSignalEntries(
        createSignalEntry('sourceIp', 'Source IP', meta.sourceIp),
        createSignalEntry('destination', 'Destination', destination)
      )
    };
  }

  if (meta.sourceIp && serviceAction) {
    return {
      key: `attack-path:identity-source:${normalizeKeyToken(meta.sourceIp)}:${normalizeKeyToken(serviceAction)}`,
      label: `Identity Path: ${meta.sourceIp} on ${serviceAction}`,
      reason: 'shared identity activity from the same source',
      family: 'identity',
      signals: mergeSignalEntries(
        createSignalEntry('sourceIp', 'Source IP', meta.sourceIp),
        createSignalEntry('serviceAction', 'Service Action', serviceAction),
        createSignalEntry('actor', 'Actor', meta.sourceAccount)
      )
    };
  }

  if (meta.sourceAccount && serviceAction) {
    return {
      key: `attack-path:identity-actor:${normalizeKeyToken(meta.sourceAccount)}:${normalizeKeyToken(serviceAction)}`,
      label: `Identity Path: ${meta.sourceAccount} on ${serviceAction}`,
      reason: 'shared actor and service action',
      family: 'identity',
      signals: mergeSignalEntries(
        createSignalEntry('actor', 'Actor', meta.sourceAccount),
        createSignalEntry('serviceAction', 'Service Action', serviceAction),
        createSignalEntry('target', 'Target', meta.targetAccount)
      )
    };
  }

  if (actorTarget) {
    return {
      key: `attack-path:identity-pair:${normalizeKeyToken(actorTarget)}`,
      label: `Identity Path: ${actorTarget}`,
      reason: 'shared actor and target',
      family: 'identity',
      signals: mergeSignalEntries(
        createSignalEntry('actor', 'Actor', meta.sourceAccount),
        createSignalEntry('target', 'Target', meta.targetAccount)
      )
    };
  }

  if (assetScope && destination) {
    return {
      key: `attack-path:asset-flow:${normalizeKeyToken(assetScope)}:${normalizeKeyToken(destination)}`,
      label: `Asset Path: ${assetScope} -> ${destination}`,
      reason: 'shared asset and destination',
      family: 'asset',
      signals: mergeSignalEntries(
        buildAssetScopeSignal(meta),
        createSignalEntry('destination', 'Destination', destination)
      )
    };
  }

  if (assetScope) {
    return {
      key: `attack-path:asset:${normalizeKeyToken(assetScope)}`,
      label: `Asset Path: ${assetScope}`,
      reason: 'shared asset scope',
      family: 'asset',
      signals: [buildAssetScopeSignal(meta)].filter(Boolean)
    };
  }

  if (meta.sourceAccount || meta.account || meta.targetAccount) {
    const identityEntity = meta.sourceAccount || meta.account || meta.targetAccount;
    return {
      key: `attack-path:identity-entity:${normalizeKeyToken(identityEntity)}`,
      label: `Identity Path: ${identityEntity}`,
      reason: 'shared identity scope',
      family: 'identity',
      signals: mergeSignalEntries(
        createSignalEntry('actor', 'Actor', meta.sourceAccount || meta.account),
        createSignalEntry('target', 'Target', meta.targetAccount)
      )
    };
  }

  if (meta.sourceIp) {
    return {
      key: `attack-path:source:${normalizeKeyToken(meta.sourceIp)}`,
      label: `Source Path: ${meta.sourceIp}`,
      reason: 'shared source IP',
      family: 'network',
      signals: [createSignalEntry('sourceIp', 'Source IP', meta.sourceIp)].filter(Boolean)
    };
  }

  if (processLineage) {
    return {
      key: `attack-path:process:${normalizeKeyToken(processLineage)}`,
      label: `Process Path: ${processLineage}`,
      reason: 'shared process lineage',
      family: 'process',
      signals: [createSignalEntry('processLineage', 'Process Lineage', processLineage)].filter(Boolean)
    };
  }

  return {
    key: `attack-path:uncorrelated:${normalizeKeyToken(alert._uiKey || alert.rrn || alert.id || `${meta.eventType}:${meta.timestampMs || '0'}`)}`,
    label: `Path: ${getAttackPathEventTypeLabel(meta.eventType)}`,
    reason: 'no reusable shared pivot detected',
    family: 'generic',
    signals: [createSignalEntry('eventType', 'Event Type', meta.eventType)].filter(Boolean)
  };
};
const buildAttackStageDescriptor = alert => {
  const meta = alert._stackMeta || buildAlertStackMeta(alert);
  const stageLabel = getAttackPathStageLabel(alert);
  const eventTypeLabel = getAttackPathEventTypeLabel(meta.eventType);
  const assetScope = buildAssetScopeValue(meta);
  const identityEntity = meta.sourceAccount || meta.account || meta.targetAccount || '';
  const flowValue = buildFlowValue(meta) || (
    meta.sourceIp && (buildDestinationValue(meta) || meta.urlHost)
      ? `${meta.sourceIp} -> ${buildDestinationValue(meta) || meta.urlHost}`
      : ''
  );
  const processDescriptor = (
    buildProcessLineageValue(meta)
    || buildCommandFocusValue(meta)
    || buildProcessDisplayValue(meta)
  );
  const identityDescriptor = buildServiceActionValue(meta) || buildServiceActionPairValue(meta) || identityEntity;
  const stageValue = (
    ['Network Activity', 'Command and Control', 'Exfiltration'].includes(stageLabel)
      ? (flowValue || meta.urlHost || buildDestinationValue(meta) || meta.sourceIp || eventTypeLabel)
      : ['Identity Activity', 'Initial Access', 'Persistence', 'Privilege Escalation'].includes(stageLabel)
        ? (identityDescriptor || eventTypeLabel)
        : ['Process Activity', 'Execution', 'Discovery', 'Credential Access', 'Defense Evasion', 'Collection', 'Impact', 'Resource Development'].includes(stageLabel)
          ? (processDescriptor || assetScope || eventTypeLabel)
          : stageLabel === 'Asset Activity'
            ? (assetScope || eventTypeLabel)
            : (identityDescriptor || flowValue || processDescriptor || assetScope || eventTypeLabel)
  );
  const stageCorrelationValue = stageValue || eventTypeLabel || normalizeWhitespace(alert._uiKey || alert.rrn || alert.id || meta.timestampMs);

  return {
    key: `attack-stage:${normalizeKeyToken(stageLabel)}:${normalizeKeyToken(stageCorrelationValue)}`,
    label: `${stageLabel}: ${stageValue || eventTypeLabel}`,
    stageLabel,
    reason: `observed ${stageLabel.toLowerCase()} activity`,
    signals: mergeSignalEntries(
      createSignalEntry('stage', 'Stage', stageLabel),
      buildAssetScopeSignal(meta),
      createSignalEntry('actor', 'Actor', meta.sourceAccount),
      createSignalEntry('target', 'Target', meta.targetAccount),
      createSignalEntry('networkFlow', 'Network Flow', flowValue),
      createSignalEntry('serviceAction', 'Service Action', buildServiceActionValue(meta) || buildServiceActionPairValue(meta)),
      createSignalEntry('processLineage', 'Process Lineage', buildProcessLineageValue(meta)),
      createSignalEntry('eventType', 'Event Type', meta.eventType)
    ).slice(0, 6)
  };
};
const getAttackPathConfidence = ({ family, alerts, stageGroups, targetCount }) => {
  let score = 0;

  if (stageGroups.length >= 3) score += 2;
  else if (stageGroups.length >= 2) score += 1;

  if (alerts.length >= 4) score += 1;
  if (family === 'host' || family === 'network') score += 1;
  if (stageGroups.length === 1) score -= 1;
  if (family === 'identity' && targetCount > 1) score -= 1;

  const label = score >= 3 ? 'High Confidence' : score >= 1 ? 'Medium Confidence' : 'Low Confidence';
  const detail = score >= 3
    ? 'Multiple stages with strong shared pivots'
    : score >= 1
      ? 'Strong shared pivots with limited stage depth'
      : 'Initial grouping that still needs analyst verification';
  const weakLink = stageGroups.length === 1
    ? 'Single-stage pattern; no follow-on stage observed yet.'
    : family === 'identity' && targetCount > 1
      ? 'Multiple targets share the same source or service action; confirm account linkage.'
      : 'Sequence inferred from shared pivots and timing.';

  return {
    label,
    detail,
    weakLink
  };
};
const buildAttackPathNextAction = (family, stageLabels) => {
  if (stageLabels.includes('Exfiltration') || stageLabels.includes('Privilege Change') || stageLabels.includes('Credential Access')) {
    return 'Contain the affected scope, verify privileged changes, and review outbound activity.';
  }

  if (family === 'network') {
    return 'Review or block the destination, then inspect the source asset or user behind the flow.';
  }

  if (family === 'identity') {
    return 'Validate the source identity, review MFA or admin changes, and confirm affected targets.';
  }

  if (family === 'host' || family === 'asset') {
    return 'Review the host timeline, process lineage, and whether the activity matches expected administration.';
  }

  return 'Validate the shared pivots, then decide whether to promote the path into an investigation.';
};
const buildTechniqueDescriptor = alert => {
  const meta = alert._stackMeta || buildAlertStackMeta(alert);
  const eventTypeLabel = formatDescriptorText(meta.eventType || 'Alert Behavior');
  const processFingerprint = getProcessTechniqueFingerprint(meta);

  if (meta.campaignLabel) {
    return {
      key: `technique:campaign:${normalizeKeyToken(meta.campaignLabel)}`,
      label: `Technique: Campaign ${meta.campaignLabel}`,
      reason: 'shared campaign context',
      signals: mergeSignalEntries(
        createSignalEntry('campaign', 'Campaign', meta.campaignLabel),
        createSignalEntry('eventType', 'Event Type', meta.eventType)
      )
    };
  }

  if (processFingerprint) {
    return processFingerprint;
  }

  if (meta.service || meta.action) {
    const behaviorLabel = [meta.service, meta.action, meta.result].filter(Boolean).join(' • ');
    return {
      key: `technique:service:${normalizeKeyToken(meta.service)}:${normalizeKeyToken(meta.action)}:${normalizeKeyToken(meta.result)}:${normalizeKeyToken(meta.eventType)}`,
      label: `Technique: ${behaviorLabel || eventTypeLabel}`,
      reason: 'shared service action pattern',
      signals: mergeSignalEntries(
        createSignalEntry('serviceAction', 'Service Action', buildServiceActionValue(meta)),
        createSignalEntry('eventType', 'Event Type', meta.eventType)
      )
    };
  }

  if (meta.signature) {
    return {
      key: `technique:signature:${normalizeKeyToken(meta.signature)}:${normalizeKeyToken(meta.eventType)}`,
      label: `Technique: ${eventTypeLabel} Signature ${meta.signature}`,
      reason: 'shared detection signature pattern',
      signals: mergeSignalEntries(
        createSignalEntry('signature', 'Signature', meta.signature),
        createSignalEntry('eventType', 'Event Type', meta.eventType)
      )
    };
  }

  if (meta.urlHost) {
    return {
      key: `technique:web:${normalizeKeyToken(meta.urlHost)}:${normalizeKeyToken(meta.eventType)}`,
      label: `Technique: ${eventTypeLabel} To ${meta.urlHost}`,
      reason: 'shared destination domain or URL pattern',
      signals: mergeSignalEntries(
        createSignalEntry('destinationHost', 'Destination Host', meta.urlHost),
        createSignalEntry('eventType', 'Event Type', meta.eventType)
      )
    };
  }

  if (meta.sourceAccount || meta.account || meta.targetAccount) {
    const identityScope = uniqueValues([
      meta.service ? formatDescriptorText(meta.service) : '',
      meta.result ? formatDescriptorText(meta.result) : '',
      meta.action ? formatDescriptorText(meta.action) : ''
    ]).slice(0, 2).join(' • ');
    return {
      key: `technique:identity:${normalizeKeyToken(meta.service)}:${normalizeKeyToken(meta.action)}:${normalizeKeyToken(meta.result)}:${normalizeKeyToken(meta.eventType)}`,
      label: `Technique: ${identityScope ? `${identityScope} Identity Activity` : `${eventTypeLabel} Identity Activity`}`,
      reason: 'shared identity activity pattern',
      signals: mergeSignalEntries(
        createSignalEntry('serviceAction', 'Identity Pattern', identityScope || eventTypeLabel),
        createSignalEntry('service', 'Service', meta.service),
        createSignalEntry('action', 'Action', meta.action),
        createSignalEntry('result', 'Result', meta.result),
        createSignalEntry('eventType', 'Event Type', meta.eventType)
      )
    };
  }

  if (meta.sourceIp || meta.destinationIp) {
    const directionLabel = meta.destinationIp
      ? `${meta.destinationIp}${meta.destinationPort ? `:${meta.destinationPort}` : ''}`
      : (meta.sourceIp || 'Network');
    return {
      key: `technique:network:${normalizeKeyToken(meta.signature)}:${normalizeKeyToken(meta.destinationIp)}:${normalizeKeyToken(meta.destinationPort)}:${normalizeKeyToken(meta.eventType)}`,
      label: `Technique: ${eventTypeLabel} Network Activity${directionLabel ? ` • ${directionLabel}` : ''}`,
      reason: 'shared network communication pattern',
      signals: mergeSignalEntries(
        createSignalEntry('networkFlow', 'Network Flow', buildFlowValue(meta) || directionLabel),
        createSignalEntry('signature', 'Signature', meta.signature),
        createSignalEntry('eventType', 'Event Type', meta.eventType)
      )
    };
  }

  if (meta.asset || meta.hostname) {
    return {
      key: `technique:asset:${normalizeKeyToken(meta.eventType)}:${normalizeKeyToken(meta.title)}`,
      label: `Technique: ${eventTypeLabel} Asset Activity`,
      reason: 'shared asset telemetry pattern',
      signals: mergeSignalEntries(
        createSignalEntry('host', 'Host', meta.hostname),
        createSignalEntry('asset', 'Asset', meta.asset),
        createSignalEntry('eventType', 'Event Type', meta.eventType)
      )
    };
  }

  if (meta.eventType) {
    return {
      key: `technique:event:${normalizeKeyToken(meta.eventType)}:${meta.titleKey}`,
      label: `Technique: ${eventTypeLabel}`,
      reason: 'shared event type behavior',
      signals: [createSignalEntry('eventType', 'Event Type', meta.eventType)].filter(Boolean)
    };
  }

  return {
    key: `technique:title:${meta.titleKey}`,
    label: `Technique: ${meta.title}`,
    reason: 'shared detection family',
    signals: [createSignalEntry('detection', 'Detection', meta.title)].filter(Boolean)
  };
};
const buildObservableDescriptor = alert => {
  const meta = alert._stackMeta || buildAlertStackMeta(alert);
  const assetScopeValue = buildAssetScopeValue(meta);
  const assetScopeLabel = buildAssetScopeLabel(meta);
  const assetScopeSignal = buildAssetScopeSignal(meta);
  const destination = buildDestinationValue(meta);
  const processLineage = buildProcessLineageValue(meta);
  const commandFocus = buildCommandFocusValue(meta);
  const processDisplay = buildProcessDisplayValue(meta);
  const serviceAction = buildServiceActionPairValue(meta);
  const createObservable = ({ key, label, reason, signals }) => ({
    key,
    label,
    reason,
    signals: mergeSignalEntries(...signals)
  });

  if (meta.sourceAccount && meta.targetAccount) {
    return createObservable({
      key: `observable:actor-target:${normalizeKeyToken(meta.sourceAccount)}:${normalizeKeyToken(meta.targetAccount)}`,
      label: `Pair: ${meta.sourceAccount} -> ${meta.targetAccount}`,
      reason: 'same actor and target',
      signals: [
        createSignalEntry('actor', 'Actor', meta.sourceAccount),
        createSignalEntry('target', 'Target', meta.targetAccount)
      ]
    });
  }

  if (meta.sourceAccount && assetScopeValue) {
    return createObservable({
      key: `observable:actor-asset:${normalizeKeyToken(meta.sourceAccount)}:${normalizeKeyToken(assetScopeValue)}`,
      label: `Pair: ${meta.sourceAccount} on ${assetScopeValue}`,
      reason: 'same actor and asset',
      signals: [
        createSignalEntry('actor', 'Actor', meta.sourceAccount),
        assetScopeSignal
      ]
    });
  }

  if (meta.sourceAccount && meta.sourceIp) {
    return createObservable({
      key: `observable:actor-source:${normalizeKeyToken(meta.sourceAccount)}:${normalizeKeyToken(meta.sourceIp)}`,
      label: `Pair: ${meta.sourceAccount} from ${meta.sourceIp}`,
      reason: 'same actor and source IP',
      signals: [
        createSignalEntry('actor', 'Actor', meta.sourceAccount),
        createSignalEntry('sourceIp', 'Source IP', meta.sourceIp)
      ]
    });
  }

  if (meta.account && meta.sourceIp) {
    return createObservable({
      key: `observable:account-ip:${normalizeKeyToken(meta.account)}:${normalizeKeyToken(meta.sourceIp)}`,
      label: `Pair: ${meta.account} from ${meta.sourceIp}`,
      reason: 'same account and source IP',
      signals: [
        createSignalEntry('account', 'Account', meta.account),
        createSignalEntry('sourceIp', 'Source IP', meta.sourceIp)
      ]
    });
  }

  if (meta.targetAccount && meta.sourceIp) {
    return createObservable({
      key: `observable:target-source:${normalizeKeyToken(meta.targetAccount)}:${normalizeKeyToken(meta.sourceIp)}`,
      label: `Pair: ${meta.targetAccount} from ${meta.sourceIp}`,
      reason: 'same target and source IP',
      signals: [
        createSignalEntry('target', 'Target', meta.targetAccount),
        createSignalEntry('sourceIp', 'Source IP', meta.sourceIp)
      ]
    });
  }

  if (meta.sourceAccount && meta.urlHost) {
    return createObservable({
      key: `observable:actor-destination-host:${normalizeKeyToken(meta.sourceAccount)}:${normalizeKeyToken(meta.urlHost)}`,
      label: `Pair: ${meta.sourceAccount} -> ${meta.urlHost}`,
      reason: 'same actor and destination host',
      signals: [
        createSignalEntry('actor', 'Actor', meta.sourceAccount),
        createSignalEntry('destinationHost', 'Destination Host', meta.urlHost)
      ]
    });
  }

  if (meta.sourceAccount && destination) {
    return createObservable({
      key: `observable:actor-destination:${normalizeKeyToken(meta.sourceAccount)}:${normalizeKeyToken(destination)}`,
      label: `Pair: ${meta.sourceAccount} -> ${destination}`,
      reason: 'same actor and destination',
      signals: [
        createSignalEntry('actor', 'Actor', meta.sourceAccount),
        createSignalEntry('destination', 'Destination', destination)
      ]
    });
  }

  if (meta.sourceAccount && serviceAction) {
    return createObservable({
      key: `observable:actor-service-action:${normalizeKeyToken(meta.sourceAccount)}:${normalizeKeyToken(serviceAction)}`,
      label: `Pair: ${meta.sourceAccount} on ${serviceAction}`,
      reason: 'same actor and service action',
      signals: [
        createSignalEntry('actor', 'Actor', meta.sourceAccount),
        createSignalEntry('serviceAction', 'Service Action', serviceAction)
      ]
    });
  }

  if (meta.sourceAccount && meta.service) {
    return createObservable({
      key: `observable:account-service:${normalizeKeyToken(meta.sourceAccount)}:${normalizeKeyToken(meta.service)}`,
      label: `Pair: ${meta.sourceAccount} on ${meta.service}`,
      reason: 'same actor and service',
      signals: [
        createSignalEntry('actor', 'Actor', meta.sourceAccount),
        createSignalEntry('service', 'Service', meta.service)
      ]
    });
  }

  if (assetScopeValue && processLineage) {
    return createObservable({
      key: `observable:asset-lineage:${normalizeKeyToken(assetScopeValue)}:${normalizeKeyToken(processLineage)}`,
      label: `Behavior: ${assetScopeValue} • ${processLineage}`,
      reason: `same ${assetScopeLabel.toLowerCase()} and process lineage`,
      signals: [
        assetScopeSignal,
        createSignalEntry('processLineage', 'Process Lineage', processLineage)
      ]
    });
  }

  if (assetScopeValue && commandFocus) {
    return createObservable({
      key: `observable:asset-command-focus:${normalizeKeyToken(assetScopeValue)}:${normalizeKeyToken(commandFocus)}`,
      label: `Behavior: ${assetScopeValue} • ${commandFocus}`,
      reason: `same ${assetScopeLabel.toLowerCase()} and command focus`,
      signals: [
        assetScopeSignal,
        createSignalEntry('commandFocus', 'Command Focus', commandFocus)
      ]
    });
  }

  if (assetScopeValue && meta.urlHost) {
    return createObservable({
      key: `observable:asset-url:${normalizeKeyToken(assetScopeValue)}:${normalizeKeyToken(meta.urlHost)}`,
      label: `Flow: ${assetScopeValue} -> ${meta.urlHost}`,
      reason: `same ${assetScopeLabel.toLowerCase()} and destination host`,
      signals: [
        assetScopeSignal,
        createSignalEntry('destinationHost', 'Destination Host', meta.urlHost)
      ]
    });
  }

  if (assetScopeValue && destination) {
    return createObservable({
      key: `observable:asset-destination:${normalizeKeyToken(assetScopeValue)}:${normalizeKeyToken(destination)}`,
      label: `Flow: ${assetScopeValue} -> ${destination}`,
      reason: `same ${assetScopeLabel.toLowerCase()} and destination`,
      signals: [
        assetScopeSignal,
        createSignalEntry('destination', 'Destination', destination)
      ]
    });
  }

  if (processLineage && meta.urlHost) {
    return createObservable({
      key: `observable:lineage-url:${normalizeKeyToken(processLineage)}:${normalizeKeyToken(meta.urlHost)}`,
      label: `Flow: ${processLineage} -> ${meta.urlHost}`,
      reason: 'same process lineage and destination host',
      signals: [
        createSignalEntry('processLineage', 'Process Lineage', processLineage),
        createSignalEntry('destinationHost', 'Destination Host', meta.urlHost)
      ]
    });
  }

  if (processDisplay && meta.urlHost) {
    return createObservable({
      key: `observable:process-url:${normalizeKeyToken(processDisplay)}:${normalizeKeyToken(meta.urlHost)}`,
      label: `Flow: ${processDisplay} -> ${meta.urlHost}`,
      reason: 'same process and destination host',
      signals: [
        createSignalEntry('process', 'Process', processDisplay),
        createSignalEntry('destinationHost', 'Destination Host', meta.urlHost)
      ]
    });
  }

  if (meta.sourceIp && meta.urlHost) {
    return createObservable({
      key: `observable:source-host:${normalizeKeyToken(meta.sourceIp)}:${normalizeKeyToken(meta.urlHost)}`,
      label: `Flow: ${meta.sourceIp} -> ${meta.urlHost}`,
      reason: 'same source and destination host',
      signals: [
        createSignalEntry('sourceIp', 'Source IP', meta.sourceIp),
        createSignalEntry('destinationHost', 'Destination Host', meta.urlHost)
      ]
    });
  }

  if (meta.sourceIp && meta.destinationIp) {
    return createObservable({
      key: `observable:network:${normalizeKeyToken(meta.sourceIp)}:${normalizeKeyToken(destination)}`,
      label: `Flow: ${meta.sourceIp} -> ${destination}`,
      reason: 'same source and destination flow',
      signals: [
        createSignalEntry('sourceIp', 'Source IP', meta.sourceIp),
        createSignalEntry('destination', 'Destination', destination)
      ]
    });
  }

  if (serviceAction) {
    return createObservable({
      key: `observable:service-action:${normalizeKeyToken(serviceAction)}`,
      label: `Service Action: ${serviceAction}`,
      reason: 'same service action',
      signals: [
        createSignalEntry('serviceAction', 'Service Action', serviceAction)
      ]
    });
  }

  return {
    key: `observable:fallback:${meta.primaryEntity.key}`,
    label: `Observable: ${meta.primaryEntity.label}`,
    reason: 'Grouped by the strongest shared entity',
    signals: meta.primaryEntity.signals || []
  };
};
const buildClusterDescriptor = (alert, mode, options = {}) => {
  const meta = alert._stackMeta || buildAlertStackMeta(alert);
  const investigationLookup = options.investigationLookup || null;

  if (mode === 'TECHNIQUE') {
    return buildTechniqueDescriptor(alert);
  }

  if (mode === 'INVESTIGATION') {
    if (alert.investigation_rrn) {
      const investigationRef = String(alert.investigation_rrn || '').trim();
      const linkedInvestigation = investigationLookup?.get(investigationRef);
      const linkedTitle = normalizeWhitespace(linkedInvestigation?.title);

      return {
        key: `investigation:${investigationRef}`,
        label: linkedTitle || `Case: ${shortRef(investigationRef)}`,
        reason: 'shared linked investigation',
        signals: [
          createSignalEntry('investigation', 'Investigation', linkedTitle || shortRef(investigationRef))
        ].filter(Boolean)
      };
    }

    return {
      key: `investigation:fallback:${meta.primaryEntity.key}:${meta.titleKey}`,
      label: `Unlinked: ${meta.primaryEntity.shortLabel}`,
      reason: 'no case link, grouped by the main entity',
      signals: meta.primaryEntity.signals || []
    };
  }

  if (mode === 'OBSERVABLE') {
    return buildObservableDescriptor(alert);
  }

  return {
    key: `hybrid:${meta.primaryEntity.key}`,
    label: meta.primaryEntity.label,
    reason: meta.primaryEntity.reason,
    signals: meta.primaryEntity.signals || []
  };
};
const buildDuplicateDescriptor = alert => {
  const meta = alert._stackMeta || buildAlertStackMeta(alert);
  const stableParts = [`rule:${normalizeKeyToken(meta.ruleId)}`];
  const signalEntries = [createSignalEntry('rule', 'Rule', meta.title)].filter(Boolean);
  const pushPart = (id, label, value) => {
    const normalized = normalizeWhitespace(value);
    if (!normalized) return;
    stableParts.push(`${id}:${normalizeKeyToken(normalized)}`);
    signalEntries.push(createSignalEntry(id, label, normalized));
  };

  pushPart('signature', 'Signature', meta.signature);
  pushPart('service', 'Service', meta.service);
  pushPart('action', 'Action', meta.action);
  pushPart('sourceAccount', 'Actor', meta.sourceAccount);
  pushPart('targetAccount', 'Target', meta.targetAccount);
  pushPart('hostname', 'Host', meta.hostname);
  pushPart('sourceIp', 'Source IP', meta.sourceIp);
  pushPart('destinationIp', 'Destination IP', meta.destinationIp);
  pushPart('destinationPort', 'Destination Port', meta.destinationPort);
  pushPart('urlHost', 'Destination Host', meta.urlHost);
  pushPart('result', 'Result', meta.result);

  Object.entries(meta.matchingMap || {}).forEach(([key, value]) => {
    if (!LOW_CARDINALITY_MATCH_KEYS.has(key)) return;
    pushPart(`match:${key}`, formatFieldSignalLabel(key), value);
  });
  const signals = mergeSignalEntries(signalEntries);

  return {
    key: stableParts.join('|'),
    label: meta.title,
    reason: 'shared detection fingerprint',
    signals,
    reasonSummary: formatSignalSummary(signals, 'Shared detection fingerprint', 3)
  };
};
const buildAlertCluster = (clusterEntry, mode) => {
  const alerts = [...clusterEntry.alerts].sort(compareAlertsByPriorityThenTime);
  const duplicateMap = new Map();

  alerts.forEach(alert => {
    const descriptor = buildDuplicateDescriptor(alert);
    if (!duplicateMap.has(descriptor.key)) {
      duplicateMap.set(descriptor.key, {
        id: `${clusterEntry.id}::dup::${duplicateMap.size}`,
        key: descriptor.key,
        label: descriptor.label,
        reason: descriptor.reason,
        signals: descriptor.signals || [],
        reasonSummary: descriptor.reasonSummary || descriptor.reason,
        alerts: []
      });
    }

    duplicateMap.get(descriptor.key).alerts.push(alert);
  });

  const duplicateGroups = [...duplicateMap.values()]
    .map(group => {
      const groupAlerts = [...group.alerts].sort(compareAlertsByPriorityThenTime);
      const highestPriorityAlert = groupAlerts[0] || alerts[0];
      const groupingSignals = mergeSignalEntries(
        group.signals || [],
        collectSharedSignalEntries(groupAlerts, { limit: 6, minCoverage: 0.5 }),
        collectSharedFieldMapSignals(groupAlerts, 'koiMap', { limit: 3, minCoverage: 0.5 }),
        collectSharedFieldMapSignals(groupAlerts, 'matchingMap', { limit: 2, minCoverage: 0.5 })
      ).slice(0, 6);

      return {
        ...group,
        alerts: groupAlerts,
        alertCount: groupAlerts.length,
        latestTimestamp: groupAlerts[0]?._stackMeta?.timestamp || '',
        latestTimestampMs: groupAlerts[0]?._stackMeta?.timestampMs || 0,
        priority: highestPriorityAlert?.priority || 'UNKNOWN',
        statusSummary: getStatusSummary(groupAlerts),
        groupingSignals,
        reasonSummary: formatSignalSummary(groupingSignals, group.reasonSummary || group.reason, 3)
      };
    })
    .sort((a, b) => {
      const countDelta = b.alertCount - a.alertCount;
      if (countDelta !== 0) return countDelta;
      const priorityDelta = getAlertPriorityWeight(b.priority) - getAlertPriorityWeight(a.priority);
      if (priorityDelta !== 0) return priorityDelta;
      return b.latestTimestampMs - a.latestTimestampMs;
    });

  const titleLabels = uniqueValues(alerts.map(alert => alert._stackMeta?.title || 'Untitled Alert'));
  const investigationRefs = uniqueValues(alerts.map(alert => alert.investigation_rrn));
  const highestPriorityAlert = alerts[0];
  const timestampValues = alerts.map(alert => alert._stackMeta?.timestampMs || 0).filter(Boolean);
  const latestTimestampMs = timestampValues.length ? Math.max(...timestampValues) : 0;
  const latestTimestamp = alerts.find(alert => (alert._stackMeta?.timestampMs || 0) === latestTimestampMs)?._stackMeta?.timestamp || '';
  const earliestTimestampMs = timestampValues.length ? Math.min(...timestampValues) : 0;
  const earliestTimestamp = alerts.find(alert => (alert._stackMeta?.timestampMs || 0) === earliestTimestampMs)?._stackMeta?.timestamp || '';
  const groupingSignals = mergeSignalEntries(
    clusterEntry.descriptor?.signals || [],
    collectSharedSignalEntries(alerts, { limit: 7, minCoverage: 0.5 }),
    collectSharedFieldMapSignals(alerts, 'koiMap', { limit: 4, minCoverage: 0.5 }),
    collectSharedFieldMapSignals(alerts, 'matchingMap', { limit: 3, minCoverage: 0.5 })
  ).slice(0, 8);
  const riskScore = (
    (highestPriorityAlert?._stackMeta?.priorityWeight || 0) * 1000
    + alerts.length * 40
    + duplicateGroups.length * 65
    + titleLabels.length * 120
    + investigationRefs.length * 35
    + alerts.filter(alert => !alert.assignee).length * 15
  );

  return {
    ...clusterEntry,
    mode,
    alerts,
    alertCount: alerts.length,
    duplicateGroups,
    duplicateStackCount: duplicateGroups.filter(group => group.alertCount > 1).length,
    titleLabels,
    investigationRefs,
    highestPriority: highestPriorityAlert?.priority || 'UNKNOWN',
    latestTimestamp,
    latestTimestampMs,
    earliestTimestamp,
    earliestTimestampMs,
    statusSummary: getStatusSummary(alerts),
    groupingSignals,
    reasonSummary: formatSignalSummary(groupingSignals, clusterEntry.descriptor?.reason || 'Shared analyst context', 3),
    summary: `${formatCountLabel(alerts.length, 'alert')} across ${titleLabels.length} unique ${titleLabels.length === 1 ? 'detection' : 'detections'}`,
    subSummary: [
      `${formatCountLabel(duplicateGroups.length, 'signal lane')}`,
      investigationRefs.length ? `${formatCountLabel(investigationRefs.length, 'case')}` : 'No linked case'
    ].filter(Boolean).join(' • '),
    riskScore
  };
};
const buildAttackPathCluster = clusterEntry => {
  const alerts = [...clusterEntry.alerts].sort(compareAlertsByPriorityThenTime);
  const stageMap = new Map();

  alerts.forEach(alert => {
    const descriptor = buildAttackStageDescriptor(alert);
    if (!stageMap.has(descriptor.key)) {
      stageMap.set(descriptor.key, {
        ...descriptor,
        alerts: []
      });
    }

    stageMap.get(descriptor.key).alerts.push(alert);
  });

  const stageGroups = [...stageMap.values()]
    .map((group, index) => {
      const groupAlerts = [...group.alerts].sort(compareAlertsByPriorityThenTime);
      const highestPriorityAlert = groupAlerts[0] || alerts[0];
      const timestampValues = groupAlerts.map(alert => alert._stackMeta?.timestampMs || 0).filter(Boolean);
      const earliestTimestampMs = timestampValues.length ? Math.min(...timestampValues) : 0;
      const latestTimestampMs = timestampValues.length ? Math.max(...timestampValues) : 0;
      const earliestTimestamp = groupAlerts.find(alert => (alert._stackMeta?.timestampMs || 0) === earliestTimestampMs)?._stackMeta?.timestamp || '';
      const latestTimestamp = groupAlerts.find(alert => (alert._stackMeta?.timestampMs || 0) === latestTimestampMs)?._stackMeta?.timestamp || '';
      const groupingSignals = mergeSignalEntries(
        group.signals || [],
        collectSharedSignalEntries(groupAlerts, {
          limit: 5,
          minCoverage: 0.5,
          excludeIds: ATTACK_PATH_SHARED_SIGNAL_EXCLUDE_IDS
        }),
        collectSharedFieldMapSignals(groupAlerts, 'koiMap', { limit: 3, minCoverage: 0.5 }),
        collectSharedFieldMapSignals(groupAlerts, 'matchingMap', { limit: 2, minCoverage: 0.5 })
      ).slice(0, 6);

      return {
        id: `${clusterEntry.id}::stage::${index}`,
        key: group.key,
        stageLabel: group.stageLabel,
        label: group.label,
        reason: group.reason,
        signals: group.signals || [],
        groupingSignals,
        reasonSummary: formatSignalSummary(groupingSignals, group.reason, 2),
        alerts: groupAlerts,
        alertCount: groupAlerts.length,
        earliestTimestamp,
        earliestTimestampMs,
        latestTimestamp,
        latestTimestampMs,
        priority: highestPriorityAlert?.priority || 'UNKNOWN',
        statusSummary: getStatusSummary(groupAlerts),
        detectionLabels: uniqueValues(groupAlerts.map(alert => alert?._stackMeta?.title || alert?.title))
      };
    })
    .sort((a, b) => {
      if (a.earliestTimestampMs !== b.earliestTimestampMs) {
        return a.earliestTimestampMs - b.earliestTimestampMs;
      }

      const priorityDelta = getAlertPriorityWeight(b.priority) - getAlertPriorityWeight(a.priority);
      if (priorityDelta !== 0) return priorityDelta;
      return b.alertCount - a.alertCount;
    });

  const titleLabels = uniqueValues(alerts.map(alert => alert._stackMeta?.title || 'Untitled Alert'));
  const investigationRefs = uniqueValues(alerts.map(alert => alert.investigation_rrn));
  const highestPriorityAlert = alerts[0];
  const timestampValues = alerts.map(alert => alert._stackMeta?.timestampMs || 0).filter(Boolean);
  const latestTimestampMs = timestampValues.length ? Math.max(...timestampValues) : 0;
  const latestTimestamp = alerts.find(alert => (alert._stackMeta?.timestampMs || 0) === latestTimestampMs)?._stackMeta?.timestamp || '';
  const earliestTimestampMs = timestampValues.length ? Math.min(...timestampValues) : 0;
  const earliestTimestamp = alerts.find(alert => (alert._stackMeta?.timestampMs || 0) === earliestTimestampMs)?._stackMeta?.timestamp || '';
  const confidenceDrivers = mergeSignalEntries(
    clusterEntry.descriptor?.signals || [],
    collectSharedSignalEntries(alerts, {
      limit: 6,
      minCoverage: 0.5,
      excludeIds: ATTACK_PATH_SHARED_SIGNAL_EXCLUDE_IDS
    }),
    collectSharedFieldMapSignals(alerts, 'koiMap', { limit: 3, minCoverage: 0.5 }),
    collectSharedFieldMapSignals(alerts, 'matchingMap', { limit: 2, minCoverage: 0.5 })
  ).slice(0, 6);
  const assetValues = uniqueValues(
    alerts
      .map(alert => buildAssetScopeValue(alert._stackMeta || buildAlertStackMeta(alert)))
      .filter(Boolean)
  );
  const identityValues = uniqueValues(
    alerts.flatMap(alert => {
      const meta = alert._stackMeta || buildAlertStackMeta(alert);
      return [meta.sourceAccount, meta.account, meta.targetAccount].filter(Boolean);
    })
  );
  const targetValues = uniqueValues(
    alerts
      .map(alert => (alert._stackMeta || buildAlertStackMeta(alert)).targetAccount)
      .filter(Boolean)
  );
  const destinationValues = uniqueValues(
    alerts
      .map(alert => {
        const meta = alert._stackMeta || buildAlertStackMeta(alert);
        return buildDestinationValue(meta) || meta.urlHost;
      })
      .filter(Boolean)
  );
  const stageLabels = uniqueValues(stageGroups.map(group => group.stageLabel).filter(Boolean));
  const confidence = getAttackPathConfidence({
    family: clusterEntry.descriptor?.family,
    alerts,
    stageGroups,
    targetCount: targetValues.length
  });
  const nextAction = buildAttackPathNextAction(clusterEntry.descriptor?.family, stageLabels);
  const blastRadiusSummary = [
    assetValues.length ? formatCountLabel(assetValues.length, 'asset') : '',
    identityValues.length ? formatCountLabel(identityValues.length, 'identity') : '',
    targetValues.length ? formatCountLabel(targetValues.length, 'target') : '',
    destinationValues.length ? formatCountLabel(destinationValues.length, 'destination') : ''
  ].filter(Boolean).slice(0, 3).join(' • ');
  const highImpactStageCount = stageLabels.filter(label => (
    label === 'Exfiltration'
    || label === 'Privilege Change'
    || label === 'Privilege Escalation'
    || label === 'Credential Access'
    || label === 'Defense Evasion'
    || label === 'Command and Control'
  )).length;
  const riskScore = (
    (highestPriorityAlert?._stackMeta?.priorityWeight || 0) * 1000
    + stageGroups.length * 180
    + alerts.length * 35
    + assetValues.length * 40
    + identityValues.length * 30
    + destinationValues.length * 25
    + highImpactStageCount * 110
    + (confidence.label === 'High Confidence' ? 160 : confidence.label === 'Medium Confidence' ? 70 : 0)
  );

  return {
    ...clusterEntry,
    mode: 'ATTACK_PATH',
    alerts,
    alertCount: alerts.length,
    duplicateGroups: stageGroups,
    duplicateStackCount: stageGroups.filter(group => group.alertCount > 1).length,
    titleLabels,
    investigationRefs,
    highestPriority: highestPriorityAlert?.priority || 'UNKNOWN',
    latestTimestamp,
    latestTimestampMs,
    earliestTimestamp,
    earliestTimestampMs,
    statusSummary: getStatusSummary(alerts),
    groupingSignals: confidenceDrivers,
    confidenceLabel: confidence.label,
    confidenceDetail: confidence.detail,
    weakLink: confidence.weakLink,
    nextAction,
    blastRadiusSummary,
    stageLabels,
    reasonSummary: formatSignalSummary(confidenceDrivers, clusterEntry.descriptor?.reason || 'Shared attack path context', 3),
    summary: stageGroups.length > 1
      ? `${formatCountLabel(stageGroups.length, 'stage')} across ${formatCountLabel(alerts.length, 'alert')}`
      : `Emerging path with ${formatCountLabel(alerts.length, 'alert')}`,
    subSummary: [
      formatCountLabel(stageGroups.length, 'stage'),
      blastRadiusSummary || 'Focused scope'
    ].filter(Boolean).join(' • '),
    riskScore
  };
};

const MainApp = {
  data: {
    config: { hasApiKey: false, hasPlatformUserApiKey: false },
    alerts: [],
    alertByKey: {},
    investigations: [],
    healthOverview: null,
    healthError: '',
    logsetNameById: {},
    eventSourceNameByRrn: {},
    mitreByCode: {},
    analysts: [],
    analystsLoaded: false,
    analystsLoading: false,
    analystQuery: '',
    currentDetail: null,
    detailHistory: [],
    alertRange: '7d',
    alertGroupingMode: 'STREAM',
    investigationRange: '7d',
    lastAlertSyncAt: null,
    lastInvestigationSyncAt: null,
    lastHealthSyncAt: null
  },
  pendingCardEl: null,
  pressedCardEl: null,
  analystsRequestPromise: null,
  analystSearchTimer: null,
  investigationOpenTimerId: null,
  alertsRequestController: null,
  alertRequestToken: 0,
  investigationsRequestController: null,
  investigationRequestToken: 0,
  appShellEl: null,
  overlayContentEl: null,
  overlayReturnFocusEl: null,

  views: {
    settingsView: `
      <section class="view" id="settingsView">
        <div class="page-shell single-column">
          <section class="hero-panel hero-panel-clean glass-panel">
            <div class="hero-copy">
              <p class="eyebrow">Secure Link</p>
              <h2>Establish command uplink</h2>
              <p class="hero-text">
                Connect your InsightIDR tenant to unlock live detections, case triage, and
                investigation workflows from this mobile command surface.
              </p>
            </div>
            <div class="metric-strip">
              <article class="metric-card compact">
                <span class="metric-label">Channel</span>
                <strong class="metric-value" id="settingsApiState">Offline</strong>
              </article>
              <article class="metric-card compact">
                <span class="metric-label">Region</span>
                <strong class="metric-value" id="settingsRegionValue">Not Set</strong>
              </article>
            </div>
          </section>

          <section class="glass-panel form-shell">
            <div class="section-heading">
              <p class="eyebrow">Configuration</p>
              <h3>API credentials</h3>
            </div>
            <form id="configForm">
              <div class="form-group">
                <label for="configRegion">InsightIDR Region</label>
                <select id="configRegion" class="control-input">
                  <option value="us">United States (us)</option>
                  <option value="us2">United States 2 (us2)</option>
                  <option value="us3">United States 3 (us3)</option>
                  <option value="eu">Europe (eu)</option>
                  <option value="ca">Canada (ca)</option>
                  <option value="ap">Asia Pacific (ap)</option>
                </select>
              </div>
              <div class="form-group">
                <label for="configApiKey">API Key</label>
                <input
                  type="password"
                  id="configApiKey"
                  class="control-input"
                  placeholder="Enter Command Platform API Key"
                  required
                />
              </div>
              <button type="submit" class="btn mt-4">Save Secure Configuration</button>
              <button type="button" id="btnForgetApiKey" class="btn btn-secondary mt-4">Forget My API Key</button>
            </form>
          </section>
        </div>
      </section>
    `,
    healthView: `
      <section class="view" id="healthView">
        <div class="page-shell">
          <section class="hero-panel hero-panel-clean glass-panel">
            <div class="hero-copy">
              <p class="eyebrow">Platform Health</p>
              <h2>Collection surface overview</h2>
              <p class="hero-text">
                Keep a secondary eye on ingest paths, collector load, and sensor heartbeat
                without pulling focus away from alert and case workflows.
              </p>
            </div>
            <div class="hero-actions">
              <div class="toolbar-group">
                <div class="toolbar-cluster">
                  <span class="card-chip health-hero-chip">Secondary operations view</span>
                </div>
              </div>
              <button id="btn-refresh-health" class="icon-btn refresh-btn" aria-label="Refresh health metrics">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8">
                  <polyline points="23 4 23 10 17 10"></polyline>
                  <polyline points="1 20 1 14 7 14"></polyline>
                  <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"></path>
                </svg>
              </button>
            </div>
          </section>

          <section class="metric-grid">
            <article class="metric-card glass-panel">
              <span class="metric-label">Monitored Resources</span>
              <strong class="metric-value" id="healthMetricMonitored">0</strong>
              <span class="metric-meta" id="healthMetricCoverage">Awaiting telemetry</span>
            </article>
            <article class="metric-card glass-panel">
              <span class="metric-label">Attention Needed</span>
              <strong class="metric-value accent" id="healthMetricAttention">0</strong>
              <span class="metric-meta" id="healthMetricAttentionMeta">No follow-up items</span>
            </article>
            <article class="metric-card glass-panel">
              <span class="metric-label">Agent Fleet</span>
              <strong class="metric-value" id="healthMetricAgents">0</strong>
              <span class="metric-meta" id="healthMetricAgentsMeta">Summary-only posture</span>
            </article>
            <article class="metric-card glass-panel">
              <span class="metric-label">Last Sync</span>
              <strong class="metric-value" id="healthMetricSync">--:--</strong>
              <span class="metric-meta">Health overview heartbeat</span>
            </article>
          </section>

          <section class="list-shell glass-panel">
            <div class="health-shell-head">
              <span class="panel-note" id="healthPanelNote">Loading platform health</span>
            </div>
            <div id="healthContainer" class="list-container">
              <div class="loading"><div class="loader-spinner"></div></div>
            </div>
          </section>
        </div>
      </section>
    `,
    alertsView: `
      <section class="view" id="alertsView">
        <div class="page-shell">
          <section class="hero-panel hero-panel-clean glass-panel">
            <div class="hero-copy">
              <p class="eyebrow">Threat Monitor</p>
              <h2>Live alert command feed</h2>
              <p class="hero-text">
                Prioritize critical detections, isolate active risk, and drive response actions
                from a single operational surface.
              </p>
            </div>
            <div class="hero-actions">
              <div class="toolbar-group">
                <div class="toolbar-cluster">
                  <label class="control-label" for="filterAlertStatus">Status</label>
                  <select id="filterAlertStatus" class="control-select">
                    <option value="ACTIVE">Active Only</option>
                    <option value="ALL">All States</option>
                    <option value="INVESTIGATING">Investigating Only</option>
                    <option value="CLOSED">Closed Only</option>
                  </select>
                </div>
                <div class="toolbar-cluster">
                  <label class="control-label" for="filterAlertRange">Timeframe</label>
                  <select id="filterAlertRange" class="control-select">
                    <option value="today">Today</option>
                    <option value="7d" selected>Last 7 Days</option>
                    <option value="28d">Last 28 Days</option>
                  </select>
                </div>
                <div class="toolbar-cluster">
                  <label class="control-label" for="filterAlertGrouping">View</label>
                  <select id="filterAlertGrouping" class="control-select">
                    <option value="HYBRID">Hybrid Stack</option>
                    <option value="STREAM" selected>Signal Stream</option>
                    <option value="TECHNIQUE">Technique View</option>
                    <option value="INVESTIGATION">Investigation View</option>
                    <option value="OBSERVABLE">Observable Pairs</option>
                    <option value="ATTACK_PATH">Attack Paths</option>
                  </select>
                </div>
              </div>
              <button id="btn-refresh-alerts" class="icon-btn refresh-btn" aria-label="Refresh alerts">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8">
                  <polyline points="23 4 23 10 17 10"></polyline>
                  <polyline points="1 20 1 14 7 14"></polyline>
                  <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"></path>
                </svg>
              </button>
            </div>
          </section>

          <section class="metric-grid">
            <article class="metric-card glass-panel">
              <span class="metric-label">Active Alerts</span>
              <strong class="metric-value" id="alertsMetricActive">0</strong>
              <span class="metric-meta" id="alertsMetricCoverage">Awaiting sync</span>
            </article>
            <article class="metric-card glass-panel">
              <span class="metric-label">Critical Priority</span>
              <strong class="metric-value accent" id="alertsMetricCritical">0</strong>
              <span class="metric-meta" id="alertsMetricCriticalMeta">Immediate analyst focus</span>
            </article>
            <article class="metric-card glass-panel">
              <span class="metric-label">Assigned</span>
              <strong class="metric-value" id="alertsMetricAssigned">0</strong>
              <span class="metric-meta" id="alertsMetricAssignedMeta">Owner-linked detections</span>
            </article>
            <article class="metric-card glass-panel">
              <span class="metric-label">Last Sync</span>
              <strong class="metric-value" id="alertsMetricSync">--:--</strong>
              <span class="metric-meta">Command feed heartbeat</span>
            </article>
          </section>

          <section class="list-shell glass-panel">
            <div class="section-heading section-heading-inline">
              <div>
                <p class="eyebrow">Queue</p>
                <h3>Alert view</h3>
              </div>
              <span class="panel-note" id="alertsPanelNote">Loading detection feed</span>
            </div>
            <div id="alertsContainer" class="list-container">
              <div class="loading"><div class="loader-spinner"></div></div>
            </div>
          </section>
        </div>
      </section>
    `,
    investigationsView: `
      <section class="view" id="investigationsView">
        <div class="page-shell">
          <section class="hero-panel hero-panel-clean glass-panel">
            <div class="hero-copy">
              <p class="eyebrow">Case Operations</p>
              <h2>Investigation control deck</h2>
              <p class="hero-text">
                Track active cases, escalate with confidence, and keep analyst attention centered
                on the highest-risk incidents.
              </p>
            </div>
            <div class="hero-actions">
              <div class="toolbar-group">
                <div class="toolbar-cluster">
                  <label class="control-label" for="filterInvStatus">Status</label>
                  <select id="filterInvStatus" class="control-select">
                    <option value="ACTIVE">Active Only</option>
                    <option value="ALL">All States</option>
                    <option value="INVESTIGATING">Investigating Only</option>
                    <option value="CLOSED">Closed Only</option>
                  </select>
                </div>
                <div class="toolbar-cluster">
                  <label class="control-label" for="filterInvRange">Timeframe</label>
                  <select id="filterInvRange" class="control-select">
                    <option value="today">Today</option>
                    <option value="7d" selected>Last 7 Days</option>
                    <option value="28d">Last 28 Days</option>
                  </select>
                </div>
              </div>
              <button id="btn-refresh-inv" class="icon-btn refresh-btn" aria-label="Refresh investigations">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8">
                  <polyline points="23 4 23 10 17 10"></polyline>
                  <polyline points="1 20 1 14 7 14"></polyline>
                  <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"></path>
                </svg>
              </button>
            </div>
          </section>

          <section class="metric-grid">
            <article class="metric-card glass-panel">
              <span class="metric-label">Open Cases</span>
              <strong class="metric-value" id="invMetricOpen">0</strong>
              <span class="metric-meta" id="invMetricOpenMeta">Currently under review</span>
            </article>
            <article class="metric-card glass-panel">
              <span class="metric-label">Critical Cases</span>
              <strong class="metric-value accent" id="invMetricCritical">0</strong>
              <span class="metric-meta" id="invMetricCriticalMeta">Priority escalation band</span>
            </article>
            <article class="metric-card glass-panel">
              <span class="metric-label">Assigned</span>
              <strong class="metric-value" id="invMetricAssigned">0</strong>
              <span class="metric-meta" id="invMetricAssignedMeta">Analyst ownership</span>
            </article>
            <article class="metric-card glass-panel">
              <span class="metric-label">Last Sync</span>
              <strong class="metric-value" id="invMetricSync">--:--</strong>
              <span class="metric-meta">Case feed heartbeat</span>
            </article>
          </section>

          <section class="list-shell glass-panel">
            <div class="section-heading section-heading-inline">
              <div>
                <p class="eyebrow">Workflow</p>
                <h3>Case queue</h3>
              </div>
              <span class="panel-note" id="invPanelNote">Loading investigations</span>
            </div>
            <div id="invContainer" class="list-container">
              <div class="loading"><div class="loader-spinner"></div></div>
            </div>
          </section>
        </div>
      </section>
    `
  },

  async init() {
    this.mainEl = document.getElementById('main-content');
    this.appShellEl = document.getElementById('app');
    this.connectionStatusEl = document.getElementById('connection-status');
    this.connectionStatusTextEl = document.getElementById('connection-status-text');
    this.connectionRegionEl = document.getElementById('connection-region');

    this.overlayEl = document.createElement('div');
    this.overlayEl.className = 'overlay';
    this.overlayEl.setAttribute('role', 'dialog');
    this.overlayEl.setAttribute('aria-modal', 'true');
    this.overlayEl.setAttribute('aria-labelledby', 'overlay-title');
    this.overlayEl.setAttribute('aria-hidden', 'true');
    this.overlayEl.innerHTML = `
      <div class="overlay-header glass-panel">
        <button id="btn-close-overlay" class="icon-btn overlay-close" aria-label="Close details">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9">
            <line x1="19" y1="12" x2="5" y2="12"></line>
            <polyline points="12 19 5 12 12 5"></polyline>
          </svg>
        </button>
        <div class="overlay-heading">
          <div class="overlay-kicker" id="overlay-kicker">Telemetry</div>
          <div class="overlay-title" id="overlay-title">Details</div>
        </div>
      </div>
      <div class="overlay-content" id="overlay-content" tabindex="-1"></div>
    `;
    document.body.appendChild(this.overlayEl);

    document.getElementById('btn-close-overlay').addEventListener('click', () => {
      this.closeCurrentDetailOverlay();
    });

    document.addEventListener('keydown', e => {
      if (!this.overlayEl?.classList.contains('active')) return;

      if (e.key === 'Escape') {
        e.preventDefault();
        this.closeCurrentDetailOverlay();
        return;
      }

      if (e.key === 'Tab') {
        this.trapOverlayFocus(e);
      }
    });

    document.getElementById('btn-health').addEventListener('click', () => this.switchView('healthView'));
    document.getElementById('btn-settings').addEventListener('click', () => this.switchView('settingsView'));
    document.querySelectorAll('.nav-btn').forEach(btn => {
      btn.addEventListener('click', () => this.switchView(btn.dataset.target));
    });

    await this.fetchConfig();

    if (this.data.config.hasApiKey) {
      this.switchView('alertsView');
    } else {
      this.switchView('settingsView');
    }
  },

  injectViews() {
    this.mainEl.innerHTML = Object.values(this.views).join('');
    this.syncConfigForm();

    document.getElementById('configForm').addEventListener('submit', async e => {
      e.preventDefault();
      await this.saveConfigForm(e.target);
    });
    document.getElementById('btnForgetApiKey').addEventListener('click', async () => {
      await this.forgetStoredApiKey();
    });

    document.getElementById('btn-refresh-alerts').addEventListener('click', () => this.fetchAlerts());
    document.getElementById('btn-refresh-inv').addEventListener('click', () => this.fetchInvestigations());
    document.getElementById('btn-refresh-health').addEventListener('click', () => this.fetchHealthOverview());

    document.getElementById('filterAlertStatus').addEventListener('change', () => this.renderAlerts());
    document.getElementById('filterAlertRange').addEventListener('change', e => {
      this.data.alertRange = e.target.value;
      this.fetchAlerts();
    });
    document.getElementById('filterAlertGrouping').addEventListener('change', e => {
      this.data.alertGroupingMode = e.target.value;
      this.renderAlerts();

      if (this.data.alertGroupingMode === 'INVESTIGATION' && !this.data.investigations.length) {
        this.fetchInvestigations();
      }
    });
    document.getElementById('filterInvStatus').addEventListener('change', () => this.renderInvestigations());
    document.getElementById('filterInvRange').addEventListener('change', e => {
      this.data.investigationRange = e.target.value;
      this.fetchInvestigations();
    });

    this.mainEl.addEventListener('pointerdown', e => {
      const card = e.target.closest('.card[data-type]');
      if (!card) return;
      this.setPressedCard(card);
    });

    this.mainEl.addEventListener('pointerup', () => this.clearPressedCard());
    this.mainEl.addEventListener('pointercancel', () => this.clearPressedCard());
    this.mainEl.addEventListener('pointerleave', e => {
      if (e.target === this.mainEl) {
        this.clearPressedCard();
      }
    });

    this.mainEl.addEventListener('click', async e => {
      const stackOpenButton = e.target.closest('[data-stack-open]');
      if (stackOpenButton) {
        e.preventDefault();
        const cluster = this.findAlertClusterById(stackOpenButton.dataset.stackOpen);
        if (cluster) {
          this.openDetailView('alert-stack', cluster);
        }
        return;
      }

      const card = e.target.closest('.card[data-type]');
      if (!card) return;
      await this.handleCardSelection(card);
    });
    this.mainEl.addEventListener('keydown', e => {
      this.handleInteractiveCardKeydown(e);
    });

    this.overlayContentEl = document.getElementById('overlay-content');
    this.overlayContentEl.addEventListener('click', async e => {
      const copyButton = e.target.closest('.copy-btn');
      if (copyButton) {
        e.preventDefault();
        e.stopPropagation();
        await this.handleCopyTrigger(copyButton);
        return;
      }

      const payloadHighlightButton = e.target.closest('[data-payload-highlight-toggle]');
      if (payloadHighlightButton) {
        e.preventDefault();
        e.stopPropagation();

        const currentAlert = this.data.currentDetail?.type === 'alert'
          ? this.data.currentDetail.item
          : null;
        const evidenceKey = String(payloadHighlightButton.dataset.evidenceKey || '').trim();
        const highlightType = String(payloadHighlightButton.dataset.payloadHighlightToggle || '').trim();

        if (!currentAlert || !evidenceKey || !highlightType) return;

        currentAlert._payloadHighlightState = currentAlert._payloadHighlightState || {};
        currentAlert._payloadHighlightState[evidenceKey] = currentAlert._payloadHighlightState[evidenceKey] || {};
        currentAlert._payloadHighlightState[evidenceKey][highlightType] = !currentAlert._payloadHighlightState[evidenceKey][highlightType];

        const scrollTop = this.overlayContentEl.scrollTop;
        this.openDetailView('alert', currentAlert, { resetScroll: false });
        this.overlayContentEl.scrollTop = scrollTop;
        return;
      }

      const codePanelToggleButton = e.target.closest('[data-code-panel-toggle]');
      if (codePanelToggleButton) {
        e.preventDefault();
        e.stopPropagation();

        const currentAlert = this.data.currentDetail?.type === 'alert'
          ? this.data.currentDetail.item
          : null;
        const evidenceKey = String(codePanelToggleButton.dataset.evidenceKey || '').trim();

        if (!currentAlert || !evidenceKey) return;

        currentAlert._payloadExpandState = currentAlert._payloadExpandState || {};
        currentAlert._payloadExpandState[evidenceKey] = !currentAlert._payloadExpandState[evidenceKey];

        const scrollTop = this.overlayContentEl.scrollTop;
        this.openDetailView('alert', currentAlert, { resetScroll: false });
        this.overlayContentEl.scrollTop = scrollTop;
        return;
      }

      const card = e.target.closest('.card[data-type]');
      if (!card) return;
      await this.handleCardSelection(card);
    });
    this.overlayContentEl.addEventListener('keydown', e => {
      this.handleInteractiveCardKeydown(e);
    });

    this.overlayContentEl.addEventListener('submit', async e => {
      e.preventDefault();
      if (e.target.id === 'updateAlertForm') {
        this.submitAlertUpdate();
      } else if (e.target.id === 'createInvForm') {
        this.submitCreateInv();
      } else if (e.target.id === 'createInvestigationCommentForm') {
        this.submitInvestigationComment(e.target);
      } else if (e.target.id === 'updateInvForm') {
        this.submitInvUpdate();
      }
    });

    this.overlayContentEl.addEventListener('input', e => {
      if (e.target.id === 'updateAlertAssignee' || e.target.id === 'updateInvAssignee') {
        this.handleAnalystFieldInput(e.target.value);
      }
    });

    this.refreshShellState();
  },

  handleInteractiveCardKeydown(e) {
    if (e.key !== 'Enter' && e.key !== ' ') return;

    const stackOpenButton = e.target.closest('[data-stack-open]');
    if (stackOpenButton) {
      e.preventDefault();
      const cluster = this.findAlertClusterById(stackOpenButton.dataset.stackOpen);
      if (cluster) {
        this.openDetailView('alert-stack', cluster);
      }
      return;
    }

    const card = e.target.closest('.card[data-type]');
    if (!card) return;

    e.preventDefault();
    this.handleCardSelection(card);
  },

  getOverlayFocusableElements() {
    if (!this.overlayEl) return [];

    const selector = [
      'button:not([disabled])',
      '[href]',
      'input:not([disabled])',
      'select:not([disabled])',
      'textarea:not([disabled])',
      '[tabindex]:not([tabindex="-1"])'
    ].join(', ');

    return [...this.overlayEl.querySelectorAll(selector)].filter(element => {
      const htmlElement = /** @type {HTMLElement} */ (element);
      return !htmlElement.hidden && !htmlElement.closest('[hidden]');
    });
  },

  trapOverlayFocus(e) {
    const focusableElements = this.getOverlayFocusableElements();
    if (focusableElements.length === 0) {
      e.preventDefault();
      this.overlayContentEl?.focus({ preventScroll: true });
      return;
    }

    const firstElement = focusableElements[0];
    const lastElement = focusableElements[focusableElements.length - 1];
    const activeElement = document.activeElement;

    if (e.shiftKey && activeElement === firstElement) {
      e.preventDefault();
      lastElement.focus();
      return;
    }

    if (!e.shiftKey && activeElement === lastElement) {
      e.preventDefault();
      firstElement.focus();
    }
  },

  setAppShellInert(isInert) {
    if (!this.appShellEl) return;

    if (isInert) {
      this.appShellEl.setAttribute('aria-hidden', 'true');
    } else {
      this.appShellEl.removeAttribute('aria-hidden');
    }

    if ('inert' in this.appShellEl) {
      this.appShellEl.inert = isInert;
    }
  },

  setPendingCard(card) {
    if (this.pendingCardEl && this.pendingCardEl !== card) {
      this.clearPendingCard(this.pendingCardEl);
    }

    this.pendingCardEl = card;
    card.classList.add('card-pending');
    card.setAttribute('aria-busy', 'true');
  },

  clearPendingCard(card = this.pendingCardEl) {
    if (!card) return;

    card.classList.remove('card-pending');
    card.removeAttribute('aria-busy');

    if (this.pendingCardEl === card) {
      this.pendingCardEl = null;
    }
  },

  setPressedCard(card) {
    if (this.pressedCardEl && this.pressedCardEl !== card) {
      this.clearPressedCard(this.pressedCardEl);
    }

    this.pressedCardEl = card;
    card.classList.add('card-pressed');
  },

  clearPressedCard(card = this.pressedCardEl) {
    if (!card) return;

    card.classList.remove('card-pressed');

    if (this.pressedCardEl === card) {
      this.pressedCardEl = null;
    }
  },

  async safeJson(response) {
    if (!response) return null;

    try {
      return await response.json();
    } catch (error) {
      return null;
    }
  },

  getErrorMessage(payload, fallbackMessage) {
    if (!payload) return fallbackMessage;
    if (typeof payload.error === 'string' && payload.error.trim()) return payload.error;
    if (typeof payload.message === 'string' && payload.message.trim()) return payload.message;
    return fallbackMessage;
  },

  async describeFetchResult(result, fallbackMessage) {
    if (result.status !== 'fulfilled') {
      return {
        ok: false,
        payload: null,
        error: result.reason?.message || fallbackMessage
      };
    }

    const payload = await this.safeJson(result.value);
    return {
      ok: result.value.ok,
      payload,
      error: result.value.ok ? '' : this.getErrorMessage(payload, fallbackMessage)
    };
  },

  primeInvestigationDetailState(item) {
    if (!item || typeof item !== 'object') return;

    if (!Array.isArray(item._alerts)) item._alerts = [];
    if (!Array.isArray(item._actors)) item._actors = [];
    if (!Array.isArray(item._comments)) item._comments = [];
    if (!Array.isArray(item._attachments)) item._attachments = [];

    item._detailError = typeof item._detailError === 'string' ? item._detailError : '';
    item._alertsError = typeof item._alertsError === 'string' ? item._alertsError : '';
    item._actorsError = typeof item._actorsError === 'string' ? item._actorsError : '';
    item._commentsError = typeof item._commentsError === 'string' ? item._commentsError : '';
    item._attachmentsError = typeof item._attachmentsError === 'string' ? item._attachmentsError : '';

    item._detailLoading = !item._detailLoaded;
    item._alertsLoading = !item._alertsLoaded;
    item._actorsLoading = !item._actorsLoaded;
    item._commentsLoading = !item._commentsLoaded;
    item._attachmentsLoading = !item._attachmentsLoaded;
  },

  primeAlertDetailState(item) {
    if (!item || typeof item !== 'object') return;

    if (!Array.isArray(item._evidences)) item._evidences = [];
    if (!Array.isArray(item._actors)) item._actors = [];
    if (!Array.isArray(item._processTrees)) item._processTrees = [];
    if (!item._mitreLookup || typeof item._mitreLookup !== 'object') item._mitreLookup = {};

    item._evidencesError = typeof item._evidencesError === 'string' ? item._evidencesError : '';
    item._actorsError = typeof item._actorsError === 'string' ? item._actorsError : '';
    item._processTreesError = typeof item._processTreesError === 'string' ? item._processTreesError : '';
    item._investigationError = typeof item._investigationError === 'string' ? item._investigationError : '';
    item._ruleSummaryError = typeof item._ruleSummaryError === 'string' ? item._ruleSummaryError : '';

    item._evidencesLoading = !item._evidencesLoaded;
    item._actorsLoading = !item._actorsLoaded;
    item._processTreesLoading = !item._processTreesLoaded;
    item._ruleSummaryLoading = !item._ruleSummaryLoaded;

    if (item.investigation_rrn) {
      item._investigation = item._investigation && typeof item._investigation === 'object'
        ? item._investigation
        : { rrn: item.investigation_rrn };
      item._investigationLoading = !item._investigationLoaded;
    } else {
      item._investigation = null;
      item._investigationError = '';
      item._investigationLoaded = true;
      item._investigationLoading = false;
    }
  },

  isCurrentInvestigationDetail(item, investigationRef = '') {
    const currentDetail = this.data.currentDetail;
    if (currentDetail?.type !== 'investigation') return false;
    if (currentDetail.item === item) return true;

    const normalizedCurrentRef = this.getInvestigationRequestRef(currentDetail.item);
    const normalizedRequestedRef = String(investigationRef || '').trim();

    if (normalizedCurrentRef && normalizedRequestedRef && normalizedCurrentRef === normalizedRequestedRef) {
      return true;
    }

    const currentRrn = String(currentDetail.item?.rrn || '').trim();
    return Boolean(currentRrn && currentRrn === normalizedRequestedRef);
  },

  isInvestigationCommentComposerDirty() {
    const form = document.getElementById('createInvestigationCommentForm');
    if (!form) return false;

    const bodyField = form.querySelector('#investigationCommentBody');
    const attachmentField = form.querySelector('#investigationCommentAttachments');
    return Boolean(
      String(bodyField?.value || '').trim()
      || (attachmentField?.files?.length || 0) > 0
    );
  },

  isInvestigationResponseFormDirty() {
    const currentInvestigation = this.data.currentDetail?.type === 'investigation'
      ? this.data.currentDetail.item
      : null;
    const form = document.getElementById('updateInvForm');
    if (!currentInvestigation || !form) return false;

    const assigneeEmail = normalizeTextValue(document.getElementById('updateInvAssignee')?.value);
    const nextStatus = normalizeSelectionValue(document.getElementById('updateInvStatus')?.value);
    const nextPriority = normalizeSelectionValue(document.getElementById('updateInvPriority')?.value);
    const nextDisposition = normalizeSelectionValue(document.getElementById('updateInvDisp')?.value);

    return (
      assigneeEmail !== normalizeTextValue(getAssigneeInputValue(currentInvestigation.assignee))
      || nextStatus !== normalizeSelectionValue(currentInvestigation.status)
      || nextPriority !== normalizeSelectionValue(currentInvestigation.priority)
      || nextDisposition !== normalizeSelectionValue(currentInvestigation.disposition)
    );
  },

  refreshCurrentInvestigationDetail(item, investigationRef, options = {}) {
    const {
      resetScroll = false,
      allowDirtyComposer = true,
      allowDirtyForm = true
    } = options;

    if (!this.isCurrentInvestigationDetail(item, investigationRef)) {
      return false;
    }

    if (!allowDirtyComposer && this.isInvestigationCommentComposerDirty()) {
      return false;
    }

    if (!allowDirtyForm && this.isInvestigationResponseFormDirty()) {
      return false;
    }

    this.openDetailView('investigation', item, { pushHistory: false, resetScroll });
    return true;
  },

  createInvestigationDetailRequests(investigationRef, keys = null) {
    const requestEntries = [
      {
        key: 'detail',
        request: fetch(`${API_BASE}/investigations/${encodeURIComponent(investigationRef)}`),
        fallbackMessage: 'Failed to load investigation details.'
      },
      {
        key: 'alerts',
        request: fetch(`${API_BASE}/investigations/${encodeURIComponent(investigationRef)}/alerts`),
        fallbackMessage: 'Failed to load related alerts.'
      },
      {
        key: 'actors',
        request: fetch(`${API_BASE}/investigations/${encodeURIComponent(investigationRef)}/actors`),
        fallbackMessage: 'Failed to load related actors.'
      },
      {
        key: 'comments',
        request: fetch(`${API_BASE}/investigations/${encodeURIComponent(investigationRef)}/comments`),
        fallbackMessage: 'Failed to load investigation comments.'
      },
      {
        key: 'attachments',
        request: fetch(`${API_BASE}/investigations/${encodeURIComponent(investigationRef)}/attachments`),
        fallbackMessage: 'Failed to load investigation attachments.'
      }
    ];

    if (!Array.isArray(keys) || keys.length === 0) {
      return requestEntries;
    }

    const requestedKeys = new Set(keys);
    return requestEntries.filter(entry => requestedKeys.has(entry.key));
  },

  async resolveRequestEntries(requestEntries) {
    const settledResults = await Promise.allSettled(requestEntries.map(entry => entry.request));
    const normalizedResults = await Promise.all(
      settledResults.map((result, index) => this.describeFetchResult(result, requestEntries[index].fallbackMessage))
    );

    return normalizedResults.reduce((lookup, result, index) => {
      lookup[requestEntries[index].key] = result;
      return lookup;
    }, {});
  },

  applyInvestigationRequestResults(item, resultMap = {}) {
    if (!item || typeof item !== 'object') return;

    const applyCollectionResult = key => {
      const result = resultMap[key];
      if (!result) return;

      item[`_${key}Loaded`] = true;
      item[`_${key}Loading`] = false;
      item[`_${key}Error`] = result.ok ? '' : result.error || '';

      if (result.ok) {
        item[`_${key}`] = result.payload?.data || [];
      }
    };

    const detailResult = resultMap.detail;
    if (detailResult) {
      item._detailLoaded = true;
      item._detailLoading = false;
      item._detailError = detailResult.ok ? '' : detailResult.error || '';

      if (detailResult.ok && detailResult.payload && typeof detailResult.payload === 'object') {
        Object.assign(item, detailResult.payload);
      }
    }

    applyCollectionResult('alerts');
    applyCollectionResult('actors');
    applyCollectionResult('comments');
    applyCollectionResult('attachments');
  },

  closeCurrentDetailOverlay() {
    if (this.data.detailHistory.length > 0) {
      const previousDetail = this.data.detailHistory.pop();
      this.openDetailView(previousDetail.type, previousDetail.item, { pushHistory: false });
      return;
    }

    this.stopInvestigationOpenTimer();
    this.overlayEl.classList.remove('active');
    this.overlayEl.setAttribute('aria-hidden', 'true');
    this.setAppShellInert(false);
    this.data.currentDetail = null;
    this.data.detailHistory = [];

    if (this.overlayReturnFocusEl && this.overlayReturnFocusEl.isConnected) {
      this.overlayReturnFocusEl.focus({ preventScroll: true });
    }

    this.overlayReturnFocusEl = null;
  },

  isCurrentAlertDetail(item, alertRef = '') {
    const currentDetail = this.data.currentDetail;
    if (currentDetail?.type !== 'alert') return false;
    if (currentDetail.item === item) return true;

    const currentRef = this.getAlertRequestRef(currentDetail.item);
    const requestedRef = String(alertRef || '').trim();
    return Boolean(currentRef && requestedRef && currentRef === requestedRef);
  },

  isAlertResponseFormDirty() {
    const currentAlert = this.data.currentDetail?.type === 'alert'
      ? this.data.currentDetail.item
      : null;
    const form = document.getElementById('updateAlertForm');
    if (!currentAlert || !form) return false;

    const assigneeId = normalizeTextValue(document.getElementById('updateAlertAssignee')?.value);
    const nextStatus = normalizeSelectionValue(document.getElementById('updateAlertStatus')?.value);
    const nextPriority = normalizeSelectionValue(document.getElementById('updateAlertPriority')?.value);
    const nextDisposition = normalizeSelectionValue(document.getElementById('updateAlertDisp')?.value);

    return (
      assigneeId !== normalizeTextValue(getAssigneeInputValue(currentAlert.assignee))
      || nextStatus !== normalizeSelectionValue(currentAlert.status)
      || nextPriority !== normalizeSelectionValue(currentAlert.priority)
      || nextDisposition !== normalizeSelectionValue(currentAlert.disposition)
    );
  },

  refreshCurrentAlertDetail(item, alertRef, options = {}) {
    const {
      resetScroll = false,
      allowDirtyForm = true
    } = options;

    if (!this.isCurrentAlertDetail(item, alertRef)) {
      return false;
    }

    if (!allowDirtyForm && this.isAlertResponseFormDirty()) {
      return false;
    }

    this.openDetailView('alert', item, { pushHistory: false, resetScroll });
    return true;
  },

  createAlertDetailRequests(item, alertRef, keys = null) {
    const requestEntries = [
      {
        key: 'evidences',
        request: fetch(`${API_BASE}/alerts/${encodeURIComponent(alertRef)}/evidences`),
        fallbackMessage: 'Failed to load alert evidences.'
      },
      {
        key: 'actors',
        request: fetch(`${API_BASE}/alerts/${encodeURIComponent(alertRef)}/actors`),
        fallbackMessage: 'Failed to load alert actors.'
      },
      {
        key: 'processTrees',
        request: fetch(`${API_BASE}/alerts/${encodeURIComponent(alertRef)}/process-trees`),
        fallbackMessage: 'Failed to load alert process trees.'
      }
    ];

    if (item?.investigation_rrn) {
      requestEntries.push({
        key: 'investigation',
        request: fetch(`${API_BASE}/investigations/${encodeURIComponent(item.investigation_rrn)}`),
        fallbackMessage: 'Failed to load the linked investigation.'
      });
    }

    if (!Array.isArray(keys) || keys.length === 0) {
      return requestEntries;
    }

    const requestedKeys = new Set(keys);
    return requestEntries.filter(entry => requestedKeys.has(entry.key));
  },

  applyAlertRequestResults(item, resultMap = {}) {
    if (!item || typeof item !== 'object') return;

    const collectionLoaders = {
      evidences: payload => payload?.data || payload?.evidences || [],
      actors: payload => payload?.data || [],
      processTrees: payload => payload?.data || []
    };

    Object.entries(collectionLoaders).forEach(([key, extractor]) => {
      const result = resultMap[key];
      if (!result) return;

      item[`_${key}Loaded`] = true;
      item[`_${key}Loading`] = false;
      item[`_${key}Error`] = result.ok ? '' : result.error || '';

      if (result.ok) {
        item[`_${key}`] = extractor(result.payload);
      }
    });

    if (Object.prototype.hasOwnProperty.call(resultMap, 'investigation')) {
      const investigationResult = resultMap.investigation;
      item._investigationLoaded = true;
      item._investigationLoading = false;
      item._investigationError = investigationResult?.ok ? '' : investigationResult?.error || '';
      item._investigation = investigationResult?.ok && investigationResult.payload && typeof investigationResult.payload === 'object'
        ? investigationResult.payload
        : (item.investigation_rrn ? { rrn: item.investigation_rrn } : null);
    } else if (!item.investigation_rrn) {
      item._investigationLoaded = true;
      item._investigationLoading = false;
      item._investigationError = '';
      item._investigation = null;
    }
  },

  syncAlertAsyncMetadata(item) {
    if (!this.isCurrentAlertDetail(item) || !this.overlayEl?.classList.contains('active')) {
      return;
    }

    const contentEl = document.getElementById('overlay-content');
    if (!contentEl) return;

    const eventSourceValueEl = contentEl.querySelector('.js-alert-event-source-value');
    if (eventSourceValueEl) {
      eventSourceValueEl.textContent = item._eventSourceName || eventSourceValueEl.dataset.fallbackValue || 'N/A';
    }

    const eventSourceLoaderEl = contentEl.querySelector('.js-alert-event-source-loader');
    if (eventSourceLoaderEl) {
      eventSourceLoaderEl.hidden = !item._eventSourceLoading;
    }

    const eventSourceRrnRow = contentEl.querySelector('.js-alert-event-source-rrn-row');
    if (eventSourceRrnRow) {
      const eventSourceRrn = String(item.triggering_event_source || '').trim();
      eventSourceRrnRow.hidden = !(
        item._eventSourceName
        && eventSourceRrn
        && item._eventSourceName !== eventSourceRrn
      );
    }

    const logsetStateById = this.collectAlertLogDetails(item).reduce((lookup, detail) => {
      const logsetId = String(detail?.logset_id || '').trim();
      if (!logsetId) return lookup;

      const existing = lookup[logsetId] || { label: logsetId, loading: false };
      lookup[logsetId] = {
        label: detail._logsetName || existing.label || logsetId,
        loading: existing.loading || Boolean(detail._logsetLoading)
      };

      return lookup;
    }, {});

    contentEl.querySelectorAll('[data-logset-id]').forEach(logsetEl => {
      const logsetId = String(logsetEl.dataset.logsetId || '').trim();
      const state = logsetStateById[logsetId] || { label: logsetId, loading: false };
      const labelEl = logsetEl.querySelector('.js-logset-label');
      const loaderEl = logsetEl.querySelector('.js-logset-loader');

      if (labelEl) {
        labelEl.textContent = `Logset: ${state.label || logsetId}`;
      }

      logsetEl.classList.toggle('is-loading', Boolean(state.loading));
      if (loaderEl) {
        loaderEl.hidden = !state.loading;
      }
    });
  },

  getCopySourceText(button) {
    const copyScope = button.closest('.meta-row, .copy-shell');
    const copySource = copyScope?.querySelector('.copy-source');

    if (!copySource) return '';
    return copySource.innerText.trim();
  },

  async writeToClipboard(text) {
    if (!text) return false;

    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
      return true;
    }

    const textArea = document.createElement('textarea');
    textArea.value = text;
    textArea.setAttribute('readonly', '');
    textArea.style.position = 'fixed';
    textArea.style.opacity = '0';
    document.body.appendChild(textArea);
    textArea.select();

    try {
      return document.execCommand('copy');
    } finally {
      document.body.removeChild(textArea);
    }
  },

  async handleCopyTrigger(button) {
    const text = this.getCopySourceText(button);
    if (!text) return;

    try {
      const didCopy = await this.writeToClipboard(text);
      if (!didCopy) return;

      button.dataset.copyState = 'copied';
      clearTimeout(button._copyResetTimer);
      button._copyResetTimer = window.setTimeout(() => {
        delete button.dataset.copyState;
      }, 1400);
    } catch (error) {
      console.error('Could not copy field content', error);
    }
  },

  async hydrateInvestigationDetail(item, investigationRef, options = {}) {
    const { progressive = false } = options;
    const requestVersion = (Number(item?._detailRequestVersion) || 0) + 1;
    item._detailRequestVersion = requestVersion;

    const isStale = () => item._detailRequestVersion !== requestVersion;
    this.primeInvestigationDetailState(item);

    if (!progressive) {
      const resultMap = await this.resolveRequestEntries(this.createInvestigationDetailRequests(investigationRef));
      if (isStale()) return item;
      this.applyInvestigationRequestResults(item, resultMap);
      return item;
    }

    const primaryResultMap = await this.resolveRequestEntries(
      this.createInvestigationDetailRequests(investigationRef, ['detail', 'alerts'])
    );
    if (isStale()) return item;

    this.applyInvestigationRequestResults(item, primaryResultMap);
    this.refreshCurrentInvestigationDetail(item, investigationRef, { resetScroll: false });

    this.resolveRequestEntries(
      this.createInvestigationDetailRequests(investigationRef, ['actors', 'comments', 'attachments'])
    ).then(resultMap => {
      if (isStale()) return;
      this.applyInvestigationRequestResults(item, resultMap);
      this.refreshCurrentInvestigationDetail(item, investigationRef, {
        resetScroll: false,
        allowDirtyComposer: false,
        allowDirtyForm: false
      });
    }).catch(error => {
      if (isStale()) return;
      console.error('Could not load investigation collaboration details', error);
    });

    return item;
  },

  async uploadAttachments(files) {
    const normalizedFiles = Array.from(files || []).filter(Boolean);
    if (normalizedFiles.length === 0) return [];

    const formData = new FormData();
    normalizedFiles.forEach(file => {
      formData.append('filedata', file, file.name);
    });

    const response = await fetch(`${API_BASE}/attachments`, {
      method: 'POST',
      body: formData
    });
    const payload = await this.safeJson(response);

    if (!response.ok) {
      throw new Error(this.getErrorMessage(payload, 'Attachment upload failed'));
    }

    return Array.isArray(payload) ? payload : [];
  },

  async fetchInvestigationSummary(investigationRef) {
    const response = await fetch(`${API_BASE}/investigations/${encodeURIComponent(investigationRef)}`);
    const payload = await this.safeJson(response);

    if (!response.ok) {
      throw new Error(this.getErrorMessage(payload, 'Failed to load linked investigation.'));
    }

    return payload && typeof payload === 'object'
      ? payload
      : { rrn: investigationRef };
  },

  async resolveStackLinkedInvestigations(cluster) {
    if (!cluster || cluster._linkedInvestigationsPending) return;

    const linkedInvestigationRefs = uniqueValues(
      cluster?.investigationRefs || (cluster?.alerts || []).map(alert => alert?.investigation_rrn)
    );
    if (!linkedInvestigationRefs.length) return;

    const investigationMap = this.getInvestigationMap();
    const existingByRef = new Map(
      (cluster._linkedInvestigations || [])
        .map(investigation => [String(investigation?.rrn || investigation?.id || '').trim(), investigation])
        .filter(([ref]) => ref)
    );
    const missingRefs = linkedInvestigationRefs.filter(ref => {
      const key = String(ref || '').trim();
      const existing = existingByRef.get(key) || investigationMap.get(key);
      return !existing || !existing.title || !existing.priority;
    });

    cluster._linkedInvestigations = linkedInvestigationRefs
      .map(ref => {
        const key = String(ref || '').trim();
        return existingByRef.get(key) || investigationMap.get(key) || { rrn: ref };
      })
      .filter(investigation => String(investigation?.rrn || investigation?.id || '').trim());

    if (!missingRefs.length) return;

    cluster._linkedInvestigationsPending = true;

    try {
      const settledResults = await Promise.allSettled(
        missingRefs.map(ref => this.fetchInvestigationSummary(ref))
      );

      const resolvedByRef = new Map(
        cluster._linkedInvestigations.map(investigation => [
          String(investigation?.rrn || investigation?.id || '').trim(),
          investigation
        ])
      );

      settledResults.forEach((result, index) => {
        const ref = missingRefs[index];
        const key = String(ref || '').trim();
        if (!key) return;

        if (result.status === 'fulfilled' && result.value) {
          resolvedByRef.set(key, result.value);
        } else if (!resolvedByRef.has(key)) {
          resolvedByRef.set(key, { rrn: ref });
        }
      });

      cluster._linkedInvestigations = linkedInvestigationRefs
        .map(ref => resolvedByRef.get(String(ref || '').trim()) || { rrn: ref })
        .filter(investigation => String(investigation?.rrn || investigation?.id || '').trim());
    } finally {
      cluster._linkedInvestigationsPending = false;
    }

    if (
      this.data.currentDetail?.type === 'alert-stack'
      && this.data.currentDetail.item?.id === cluster.id
      && this.overlayEl?.classList.contains('active')
    ) {
      const scrollTop = this.overlayContentEl?.scrollTop || 0;
      this.openDetailView('alert-stack', cluster, { resetScroll: false });
      if (this.overlayContentEl) {
        this.overlayContentEl.scrollTop = scrollTop;
      }
    }
  },

  async hydrateAlertDetail(item, alertRef, options = {}) {
    const { progressive = false } = options;
    const requestVersion = (Number(item?._alertDetailRequestVersion) || 0) + 1;
    item._alertDetailRequestVersion = requestVersion;

    const isStale = () => item._alertDetailRequestVersion !== requestVersion;
    const refreshOptions = {
      resetScroll: false,
      allowDirtyForm: false
    };

    this.primeAlertDetailState(item);

    const loadAlertSections = async () => {
      const resultMap = await this.resolveRequestEntries(this.createAlertDetailRequests(item, alertRef));
      if (isStale()) return;

      this.applyAlertRequestResults(item, resultMap);
      this.refreshCurrentAlertDetail(item, alertRef, refreshOptions);
    };

    const loadRuleSummary = async () => {
      const ruleRrn = this.getAlertRuleRrn(item);

      if (!ruleRrn) {
        item._ruleSummary = null;
        item._ruleSummaryError = '';
        item._ruleSummaryLoaded = true;
        item._ruleSummaryLoading = false;
        item._mitreLookup = {};
        this.refreshCurrentAlertDetail(item, alertRef, refreshOptions);
        return;
      }

      const ruleParams = new URLSearchParams();
      [
        'NAME',
        'DESCRIPTION',
        'RECOMMENDATION',
        'EVENT_TYPES',
        'TACTIC_CODES',
        'TECHNIQUE_CODES',
        'PRIORITY_LEVEL',
        'DETECTION_COUNT',
        'STATE'
      ].forEach(itemName => ruleParams.append('item', itemName));

      try {
        const ruleRes = await fetch(
          `${API_BASE}/rules/${encodeURIComponent(ruleRrn)}/summary?${ruleParams.toString()}`
        );
        const rulePayload = await this.safeJson(ruleRes);
        if (isStale()) return;

        if (!ruleRes.ok) {
          item._ruleSummary = null;
          item._ruleSummaryError = this.getErrorMessage(rulePayload, 'Failed to load detection rule summary.');
          item._mitreLookup = {};
        } else {
          item._ruleSummary = rulePayload;
          item._ruleSummaryError = '';
          item._mitreLookup = {};
          this.applyMitreLookupToAlert(item);
        }

        item._ruleSummaryLoaded = true;
        item._ruleSummaryLoading = false;
        this.refreshCurrentAlertDetail(item, alertRef, refreshOptions);

        if (!ruleRes.ok) {
          return;
        }

        await this.resolveRuleMitreDetails(item);
        if (isStale()) return;
        this.refreshCurrentAlertDetail(item, alertRef, refreshOptions);
      } catch (error) {
        if (isStale()) return;
        item._ruleSummary = null;
        item._ruleSummaryError = error.message || 'Failed to load detection rule summary.';
        item._ruleSummaryLoaded = true;
        item._ruleSummaryLoading = false;
        item._mitreLookup = {};
        this.refreshCurrentAlertDetail(item, alertRef, refreshOptions);
      }
    };

    if (!progressive) {
      await Promise.all([
        loadAlertSections(),
        loadRuleSummary()
      ]);
      return item;
    }

    loadAlertSections().catch(error => {
      if (isStale()) return;
      console.error('Could not load alert detail sections', error);
    });

    loadRuleSummary().catch(error => {
      if (isStale()) return;
      console.error('Could not load alert rule summary', error);
    });

    return item;
  },

  getAlertRuleRrn(item) {
    const ruleRefObj = item.detection_rule_rrn;
    return typeof ruleRefObj === 'string'
      ? ruleRefObj
      : (ruleRefObj?.rule_rrn || ruleRefObj?.rrn || item.rule?.rrn || null);
  },

  collectRuleMitreCodes(ruleSummary) {
    if (!ruleSummary || typeof ruleSummary !== 'object') return [];

    const tacticCodes = Array.isArray(ruleSummary.tactic_codes)
      ? ruleSummary.tactic_codes
      : (Array.isArray(ruleSummary.TACTIC_CODES) ? ruleSummary.TACTIC_CODES : []);
    const techniqueCodes = Array.isArray(ruleSummary.technique_codes)
      ? ruleSummary.technique_codes
      : (Array.isArray(ruleSummary.TECHNIQUE_CODES) ? ruleSummary.TECHNIQUE_CODES : []);

    return Array.from(new Set(
      [...tacticCodes, ...techniqueCodes]
        .map(code => String(code || '').trim().toUpperCase())
        .filter(Boolean)
    ));
  },

  applyMitreLookupToAlert(item) {
    const codes = this.collectRuleMitreCodes(item?._ruleSummary);
    item._mitreLookup = codes.reduce((lookup, code) => {
      if (this.data.mitreByCode[code]) {
        lookup[code] = this.data.mitreByCode[code];
      }
      return lookup;
    }, {});
  },

  async resolveRuleMitreDetails(item) {
    if (!item?._ruleSummary) {
      item._mitreLookup = {};
      return;
    }

    const codes = this.collectRuleMitreCodes(item._ruleSummary);
    if (codes.length === 0) {
      item._mitreLookup = {};
      return;
    }

    this.applyMitreLookupToAlert(item);

    const unresolvedCodes = codes.filter(code => !this.data.mitreByCode[code]);
    if (unresolvedCodes.length === 0) {
      return;
    }

    const params = new URLSearchParams();
    unresolvedCodes.forEach(code => params.append('code', code));

    try {
      const response = await fetch(`${API_BASE}/mitre/resolve?${params.toString()}`);
      const payload = await this.safeJson(response);

      if (response.ok && Array.isArray(payload?.data)) {
        payload.data.forEach(entry => {
          if (entry?.code) {
            this.data.mitreByCode[String(entry.code).trim().toUpperCase()] = entry;
          }
        });
      }
    } catch (error) {
      console.error('Could not resolve MITRE ATT&CK codes', error);
    } finally {
      this.applyMitreLookupToAlert(item);
      this.refreshCurrentAlertDetail(item, this.getAlertRequestRef(item), {
        resetScroll: false,
        allowDirtyForm: false
      });
    }
  },

  collectAlertLogDetails(item) {
    const topLevelLogDetails = Array.isArray(item?.log_details) ? item.log_details : [];
    const evidenceLogDetails = (item?._evidences || [])
      .flatMap(evidence => Array.isArray(evidence?.log_details) ? evidence.log_details : []);

    return [...topLevelLogDetails, ...evidenceLogDetails];
  },

  collectAlertEventSourceRrns(item) {
    const candidateValues = [
      item?.triggering_event_source
    ];

    return Array.from(new Set(
      candidateValues
        .map(value => String(value || '').trim())
        .filter(value => value.startsWith('rrn:collection:') && value.includes(':eventsource:'))
    ));
  },

  applyLogsetNamesToAlert(item) {
    this.collectAlertLogDetails(item).forEach(detail => {
      const logsetId = detail?.logset_id;
      if (!logsetId) return;

      const resolvedName = this.data.logsetNameById[logsetId];
      detail._logsetName = resolvedName || null;
      detail._logsetLoading = !resolvedName && Boolean(item?._logsetNamesResolving);
    });
  },

  async resolveAlertLogsetNames(item) {
    if (!item) return;

    const unresolvedIds = Array.from(new Set(
      this.collectAlertLogDetails(item)
        .map(detail => detail?.logset_id)
        .filter(logsetId => logsetId && !this.data.logsetNameById[logsetId])
    ));

    if (unresolvedIds.length === 0 || item._logsetNamesResolving) {
      this.applyLogsetNamesToAlert(item);
      this.syncAlertAsyncMetadata(item);
      return;
    }

    item._logsetNamesResolving = true;
    this.applyLogsetNamesToAlert(item);
    this.syncAlertAsyncMetadata(item);

    const params = new URLSearchParams();
    unresolvedIds.forEach(id => params.append('ids', id));

    try {
      const res = await fetch(`${API_BASE}/logsets/resolve?${params.toString()}`);
      const payload = await this.safeJson(res);

      if (res.ok && Array.isArray(payload?.data)) {
        payload.data.forEach(entry => {
          if (entry?.id) {
            this.data.logsetNameById[entry.id] = entry.name || entry.id;
          }
        });
      }
    } catch (error) {
      console.error('Could not resolve logset names', error);
    } finally {
      item._logsetNamesResolving = false;
      this.applyLogsetNamesToAlert(item);
      this.syncAlertAsyncMetadata(item);
    }
  },

  applyEventSourceNamesToAlert(item) {
    if (!item) return;

    const eventSourceRrn = String(item.triggering_event_source || '').trim();
    if (!eventSourceRrn) {
      item._eventSourceName = null;
      item._eventSourceLoading = false;
      return;
    }

    const resolvedName = this.data.eventSourceNameByRrn[eventSourceRrn];
    item._eventSourceName = resolvedName || null;
    item._eventSourceLoading = !resolvedName && Boolean(item._eventSourceNamesResolving);
  },

  async resolveAlertEventSourceNames(item) {
    if (!item) return;

    const unresolvedRrns = this.collectAlertEventSourceRrns(item)
      .filter(rrn => !this.data.eventSourceNameByRrn[rrn]);
    const logIds = Array.from(new Set(
      this.collectAlertLogDetails(item)
        .map(detail => String(detail?.log_id || '').trim())
        .filter(Boolean)
    ));

    if (unresolvedRrns.length === 0 || item._eventSourceNamesResolving) {
      this.applyEventSourceNamesToAlert(item);
      this.syncAlertAsyncMetadata(item);
      return;
    }

    item._eventSourceNamesResolving = true;
    this.applyEventSourceNamesToAlert(item);
    this.syncAlertAsyncMetadata(item);

    const params = new URLSearchParams();
    unresolvedRrns.forEach(rrn => params.append('rrn', rrn));
    logIds.forEach(logId => params.append('log_id', logId));

    try {
      const res = await fetch(`${API_BASE}/event-sources/resolve?${params.toString()}`);
      const payload = await this.safeJson(res);

      if (res.ok && Array.isArray(payload?.data)) {
        payload.data.forEach(entry => {
          if (entry?.rrn) {
            this.data.eventSourceNameByRrn[entry.rrn] = entry.name || entry.rrn;
          }
        });
      }
    } catch (error) {
      console.error('Could not resolve event source names', error);
    } finally {
      item._eventSourceNamesResolving = false;
      this.applyEventSourceNamesToAlert(item);
      this.syncAlertAsyncMetadata(item);
    }
  },

  async handleCardSelection(card) {
    const id = (card.dataset.id || '').trim();
    const type = card.dataset.type;

    this.setPendingCard(card);
    await waitForNextPaint();

    try {
      if (type === 'alert' || type === 'alert-related' || type === 'alert-stack-alert') {
        await this.openAlertFromCard(id, type);
      } else if (type === 'investigation' || type === 'investigation-related') {
        await this.openInvestigationFromCard(id, type);
      }
    } finally {
      this.clearPendingCard(card);
    }
  },

  async openInvestigationFromCard(id, type = 'investigation') {
    if (!id) return;

    let item = this.data.investigations.find(inv => String(inv.rrn || inv.id) === String(id));

    if (!item && type === 'investigation-related' && this.data.currentDetail?.type === 'alert') {
      const linkedInvestigation = this.data.currentDetail.item._investigation;
      if (linkedInvestigation && String(linkedInvestigation.rrn || linkedInvestigation.id || '') === String(id)) {
        item = linkedInvestigation;
      }
    }

    if (!item && type === 'investigation-related' && this.data.currentDetail?.type === 'alert-stack') {
      item = (this.data.currentDetail.item._linkedInvestigations || [])
        .find(inv => String(inv?.rrn || inv?.id || '') === String(id));
    }

    if (!item) {
      item = { rrn: id };
    }

    const investigationRef = this.getInvestigationRequestRef(item, id);
    this.primeInvestigationDetailState(item);
    this.openDetailView('investigation', item, {
      pushHistory: (
        type === 'investigation-related'
        && (
          this.data.currentDetail?.type === 'alert'
          || this.data.currentDetail?.type === 'alert-stack'
        )
      )
    });

    try {
      await this.hydrateInvestigationDetail(item, investigationRef, { progressive: true });
    } catch (error) {
      console.error('Could not fetch investigation details', error);
      item._alerts = item._alerts || [];
      item._actors = item._actors || [];
      item._comments = item._comments || [];
      item._attachments = item._attachments || [];
    }
  },

  async openAlertFromCard(id, type = 'alert') {
    if (!id) return;

    let item = this.data.alertByKey[id]
      || this.data.alerts.find(alert => String(alert.rrn || alert.id || '') === id);

    if (!item && type === 'alert-related' && this.data.currentDetail?.type === 'investigation') {
      item = (this.data.currentDetail.item._alerts || []).find(alert => String(alert.rrn || alert.id || '') === id);
    }

    if (!item) return;

    const alertRef = this.getAlertRequestRef(item, id);
    const shouldPushHistory = (
      (type === 'alert-related' && this.data.currentDetail?.type === 'investigation')
      || (type === 'alert-stack-alert' && this.data.currentDetail?.type === 'alert-stack')
    );

    this.primeAlertDetailState(item);
    item._logsetNamesResolving = false;
    item._eventSourceNamesResolving = false;
    this.applyLogsetNamesToAlert(item);
    this.applyEventSourceNamesToAlert(item);
    this.openDetailView('alert', item, {
      pushHistory: shouldPushHistory
    });

    try {
      await this.hydrateAlertDetail(item, alertRef, { progressive: true });
    } catch (error) {
      console.error('Could not fetch alert details', error);
      item._evidences = item._evidences || [];
      item._actors = item._actors || [];
      item._processTrees = item._processTrees || [];
    }
  },

  syncConfigForm() {
    const apiKeyEl = document.getElementById('configApiKey');
    const regionEl = document.getElementById('configRegion');
    const forgetButtonEl = document.getElementById('btnForgetApiKey');
    const alertRangeEl = document.getElementById('filterAlertRange');
    const alertGroupingEl = document.getElementById('filterAlertGrouping');
    const investigationRangeEl = document.getElementById('filterInvRange');

    if (apiKeyEl) {
      apiKeyEl.placeholder = this.data.config.hasApiKey
        ? 'Configured. Enter to rotate key.'
        : 'Enter Command Platform API Key';
      apiKeyEl.required = !this.data.config.hasApiKey;
    }

    if (forgetButtonEl) {
      forgetButtonEl.disabled = !(this.data.config.hasApiKey || this.data.config.hasPlatformUserApiKey);
    }

    if (this.data.config.region) {
      regionEl.value = this.data.config.region;
    }

    if (alertRangeEl) {
      alertRangeEl.value = this.data.alertRange;
    }

    if (alertGroupingEl) {
      alertGroupingEl.value = this.data.alertGroupingMode;
    }

    if (investigationRangeEl) {
      investigationRangeEl.value = this.data.investigationRange;
    }
  },

  refreshShellState() {
    this.updateConnectionState();

    const settingsApiState = document.getElementById('settingsApiState');
    const settingsRegionValue = document.getElementById('settingsRegionValue');

    if (settingsApiState) {
      settingsApiState.textContent = this.data.config.hasApiKey ? 'Online' : 'Offline';
    }

    if (settingsRegionValue) {
      settingsRegionValue.textContent = this.data.config.region
        ? this.data.config.region.toUpperCase()
        : 'Not Set';
    }

    this.updateAlertMetrics();
    this.updateInvestigationMetrics();
    this.updateHealthMetrics();
  },

  updateConnectionState() {
    const isOnline = Boolean(this.data.config.hasApiKey);
    this.connectionStatusEl.classList.toggle('is-online', isOnline);
    this.connectionStatusTextEl.textContent = isOnline ? 'Sensor Online' : 'Sensor Offline';
    this.connectionRegionEl.textContent = this.data.config.region
      ? `Region ${String(this.data.config.region).toUpperCase()}`
      : 'No region configured';
  },

  formatSyncTime(date) {
    if (!date) return '--:--';
    return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  },

  formatPercent(count, total) {
    if (!total) return '0%';
    return `${Math.round((count / total) * 100)}%`;
  },

  formatMetricTotalMeta(count, total, singular, plural = `${singular}s`) {
    return `of ${formatCountLabel(total, singular, plural)}`;
  },

  formatMetricPercentMeta(count, total, singular, plural = `${singular}s`) {
    return `${this.formatMetricTotalMeta(count, total, singular, plural)} • ${this.formatPercent(count, total)}`;
  },

  setText(id, value) {
    const el = document.getElementById(id);
    if (el) el.textContent = value;
  },

  getStatusFilterValue(selectId) {
    return document.getElementById(selectId)?.value || 'ACTIVE';
  },

  matchesStatusFilter(item, filterValue) {
    const status = String(item?.status || '').toUpperCase();

    if (filterValue === 'ACTIVE') return status !== 'CLOSED';
    if (filterValue === 'CLOSED') return status === 'CLOSED';
    if (filterValue === 'INVESTIGATING') return status === 'INVESTIGATING';
    return true;
  },

  getFilteredItems(items, filterValue) {
    return (items || []).filter(item => this.matchesStatusFilter(item, filterValue));
  },

  getQueueSummary(count, entityName, filterValue) {
    const entityLabel = count === 1 ? entityName : `${entityName}s`;

    if (filterValue === 'ALL') return `${count} ${entityLabel} in total`;
    if (filterValue === 'CLOSED') return `${count} ${entityLabel} closed`;
    if (filterValue === 'INVESTIGATING') return `${count} ${entityLabel} under investigation`;
    return `${count} active ${entityLabel}`;
  },

  getAlertGroupingLabel(mode = this.data.alertGroupingMode) {
    return ALERT_GROUPING_MODE_LABELS[mode] || ALERT_GROUPING_MODE_LABELS.HYBRID;
  },

  getInvestigationMap() {
    return (this.data.investigations || []).reduce((lookup, investigation) => {
      const rrn = String(investigation?.rrn || '').trim();
      const id = String(investigation?.id || '').trim();
      if (rrn) lookup.set(rrn, investigation);
      if (id) lookup.set(id, investigation);
      return lookup;
    }, new Map());
  },

  getAlertRequestRef(alert, fallback = '') {
    return String(alert?.rrn || alert?.id || fallback || '').trim();
  },

  getInvestigationRequestRef(investigation, fallback = '') {
    return String(investigation?.id || investigation?.rrn || fallback || '').trim();
  },

  findAlertClusterById(clusterId) {
    if (!clusterId) return null;
    return this.buildAlertViewModel().clusters.find(cluster => cluster.id === clusterId) || null;
  },

  buildAlertClusters(alerts, mode = this.data.alertGroupingMode) {
    if (mode === 'STREAM') {
      return (alerts || [])
        .map(alert => {
          const meta = alert._stackMeta || buildAlertStackMeta(alert);
          const descriptor = {
            key: `stream:${alert._uiKey || alert.rrn || `${meta.titleKey}:${meta.timestampMs || '0'}`}`,
            label: meta.title,
            reason: 'stacking disabled',
            signals: meta.primaryEntity?.signals || []
          };

          return buildAlertCluster({
            id: `STREAM::${descriptor.key}`,
            descriptor,
            alerts: [alert]
          }, mode);
        })
        .sort((a, b) => {
          const scoreDelta = b.riskScore - a.riskScore;
          if (scoreDelta !== 0) return scoreDelta;
          return b.latestTimestampMs - a.latestTimestampMs;
        });
    }

    if (mode === 'ATTACK_PATH') {
      const clusterMap = new Map();

      (alerts || []).forEach(alert => {
        const descriptor = buildAttackPathDescriptor(alert);
        const id = `${mode}::${descriptor.key}`;

        if (!clusterMap.has(id)) {
          clusterMap.set(id, {
            id,
            descriptor,
            alerts: []
          });
        }

        clusterMap.get(id).alerts.push(alert);
      });

      return [...clusterMap.values()]
        .map(entry => buildAttackPathCluster(entry))
        .sort((a, b) => {
          const scoreDelta = b.riskScore - a.riskScore;
          if (scoreDelta !== 0) return scoreDelta;
          return b.latestTimestampMs - a.latestTimestampMs;
        });
    }

    const clusterMap = new Map();
    const investigationLookup = mode === 'INVESTIGATION'
      ? this.getInvestigationMap()
      : null;

    (alerts || []).forEach(alert => {
      const descriptor = buildClusterDescriptor(alert, mode, { investigationLookup });
      const id = `${mode}::${descriptor.key}`;

      if (!clusterMap.has(id)) {
        clusterMap.set(id, {
          id,
          descriptor,
          alerts: []
        });
      }

      clusterMap.get(id).alerts.push(alert);
    });

    return [...clusterMap.values()]
      .map(entry => buildAlertCluster(entry, mode))
      .sort((a, b) => {
        const scoreDelta = b.riskScore - a.riskScore;
        if (scoreDelta !== 0) return scoreDelta;
        return b.latestTimestampMs - a.latestTimestampMs;
      });
  },

  buildAlertViewModel(filterValue = this.getStatusFilterValue('filterAlertStatus')) {
    const totalAlerts = this.data.alerts || [];
    const filteredAlerts = this.getFilteredItems(totalAlerts, filterValue);
    const mode = this.data.alertGroupingMode;
    const clusters = this.buildAlertClusters(filteredAlerts, mode);
    const isStreamMode = mode === 'STREAM';

    return {
      mode,
      modeLabel: this.getAlertGroupingLabel(mode),
      countLabel: isStreamMode
        ? formatCountLabel(clusters.length, 'alert')
        : mode === 'ATTACK_PATH'
          ? formatCountLabel(clusters.length, 'path')
          : formatCountLabel(clusters.length, 'work unit'),
      filterValue,
      totalAlerts,
      filteredAlerts,
      clusters,
      workUnitCount: clusters.length,
      stackedAlertCount: isStreamMode ? 0 : Math.max(0, filteredAlerts.length - clusters.length)
    };
  },

  getAlertPanelNote(alertView) {
    if (!alertView.filteredAlerts.length) {
      return 'No alerts match the current filter.';
    }

    const baseSummary = this.getQueueSummary(alertView.filteredAlerts.length, 'alert', alertView.filterValue);
    if (alertView.mode === 'STREAM') {
      return `${alertView.modeLabel}: ${baseSummary}`;
    }

    const workUnitLabel = alertView.countLabel || formatCountLabel(alertView.workUnitCount, 'work unit');
    const collapsedLabel = alertView.stackedAlertCount
      ? ` • ${formatCountLabel(alertView.stackedAlertCount, 'alert')} collapsed`
      : '';

    return `${alertView.modeLabel}: ${workUnitLabel} built from ${baseSummary}${collapsedLabel}`;
  },

  updateAlertMetrics(alertView = this.buildAlertViewModel()) {
    const alerts = this.data.alerts || [];
    const active = alerts.filter(alert => alert.status !== 'CLOSED').length;
    const critical = alerts.filter(alert => String(alert.priority || '').toUpperCase() === 'CRITICAL').length;
    const assigned = alerts.filter(alert => alert.assignee).length;
    const totalAlerts = alerts.length;
    const activeMeta = totalAlerts
      ? this.formatMetricPercentMeta(active, totalAlerts, 'alert')
      : 'Awaiting sync';
    const criticalMeta = totalAlerts
      ? this.formatMetricPercentMeta(critical, totalAlerts, 'alert')
      : 'Immediate analyst focus';
    const assignedMeta = totalAlerts
      ? this.formatMetricPercentMeta(assigned, totalAlerts, 'alert')
      : 'Owner-linked detections';

    this.setText('alertsMetricActive', String(active));
    this.setText('alertsMetricCritical', String(critical));
    this.setText('alertsMetricAssigned', String(assigned));
    this.setText('alertsMetricCoverage', activeMeta);
    this.setText('alertsMetricCriticalMeta', criticalMeta);
    this.setText('alertsMetricAssignedMeta', assignedMeta);
    this.setText('alertsMetricSync', this.formatSyncTime(this.data.lastAlertSyncAt));
    this.setText(
      'alertsPanelNote',
      alerts.length ? this.getAlertPanelNote(alertView) : 'No alerts in current feed'
    );
  },

  updateInvestigationMetrics() {
    const investigations = this.data.investigations || [];
    const filterValue = this.getStatusFilterValue('filterInvStatus');
    const filteredInvestigations = this.getFilteredItems(investigations, filterValue);
    const open = investigations.filter(inv => inv.status !== 'CLOSED').length;
    const critical = investigations.filter(inv => String(inv.priority || '').toUpperCase() === 'CRITICAL').length;
    const assigned = investigations.filter(inv => inv.assignee).length;
    const totalInvestigations = investigations.length;
    const openMeta = totalInvestigations
      ? this.formatMetricPercentMeta(open, totalInvestigations, 'case')
      : 'Currently under review';
    const criticalMeta = totalInvestigations
      ? this.formatMetricPercentMeta(critical, totalInvestigations, 'case')
      : 'Priority escalation band';
    const assignedMeta = totalInvestigations
      ? this.formatMetricPercentMeta(assigned, totalInvestigations, 'case')
      : 'Analyst ownership';

    this.setText('invMetricOpen', String(open));
    this.setText('invMetricCritical', String(critical));
    this.setText('invMetricAssigned', String(assigned));
    this.setText('invMetricOpenMeta', openMeta);
    this.setText('invMetricCriticalMeta', criticalMeta);
    this.setText('invMetricAssignedMeta', assignedMeta);
    this.setText('invMetricSync', this.formatSyncTime(this.data.lastInvestigationSyncAt));
    this.setText(
      'invPanelNote',
      investigations.length
        ? this.getQueueSummary(filteredInvestigations.length, 'investigation', filterValue)
        : 'No investigations available'
    );
  },

  updateHealthMetrics() {
    const overview = this.data.healthOverview?.overview || null;
    const agentSummary = overview?.agent_summary || {};
    const monitoredResources = overview?.monitored_resources || 0;
    const reportingFamilies = overview?.reporting_families || 0;
    const licensedFamilies = overview?.licensed_families || 0;
    const attentionResources = overview?.attention_resources || 0;
    const agentTotal = agentSummary.total || 0;
    const agentAttention = (agentSummary.offline || 0) + (agentSummary.stale || 0);
    const healthError = this.data.healthError || '';

    this.setText('healthMetricMonitored', String(monitoredResources));
    this.setText(
      'healthMetricCoverage',
      healthError
        ? healthError
        : `${reportingFamilies}/${licensedFamilies || 0} families reporting`
    );
    this.setText('healthMetricAttention', String(attentionResources));
    this.setText(
      'healthMetricAttentionMeta',
      attentionResources > 0
        ? `${attentionResources} resources need follow-up`
        : 'No follow-up items'
    );
    this.setText('healthMetricAgents', String(agentTotal));
    this.setText(
      'healthMetricAgentsMeta',
      agentTotal
        ? `${agentSummary.online || 0} online, ${agentAttention} needing attention`
        : 'Summary-only posture'
    );
    this.setText('healthMetricSync', this.formatSyncTime(this.data.lastHealthSyncAt));
    this.setText(
      'healthPanelNote',
      healthError
        ? healthError
        : monitoredResources
          ? `${monitoredResources} monitored resources across the tenant`
          : 'No health telemetry returned'
    );
  },

  async fetchConfig() {
    try {
      const res = await fetch(`${API_BASE}/config`);
      this.data.config = await res.json();
    } catch (error) {
      console.error(error);
    }

    if (document.getElementById('settingsView')) {
      this.syncConfigForm();
      this.refreshShellState();
    } else {
      this.updateConnectionState();
    }
  },

  switchView(viewId) {
    if (!document.getElementById(viewId)) {
      this.injectViews();
    }

    document.querySelectorAll('.view').forEach(view => view.classList.remove('active'));
    document.getElementById(viewId).classList.add('active');
    document.body.dataset.view = viewId;
    this.syncViewControls(viewId);

    if (viewId === 'alertsView') this.fetchAlerts();
    if (viewId === 'investigationsView') this.fetchInvestigations();
    if (viewId === 'healthView') this.fetchHealthOverview();
  },

  syncViewControls(viewId) {
    document.querySelectorAll('.nav-btn').forEach(btn => {
      btn.classList.toggle('active', btn.dataset.target === viewId);
    });

    const healthButton = document.getElementById('btn-health');
    const settingsButton = document.getElementById('btn-settings');

    if (healthButton) {
      healthButton.classList.toggle('is-active', viewId === 'healthView');
    }

    if (settingsButton) {
      settingsButton.classList.toggle('is-active', viewId === 'settingsView');
    }
  },

  resetAnalystDirectory() {
    this.data.analysts = [];
    this.data.analystsLoaded = false;
    this.data.analystsLoading = false;
    this.data.analystQuery = '';
    this.analystsRequestPromise = null;
  },

  resetOperationalData() {
    if (this.alertsRequestController) {
      this.alertsRequestController.abort();
      this.alertsRequestController = null;
    }

    if (this.investigationsRequestController) {
      this.investigationsRequestController.abort();
      this.investigationsRequestController = null;
    }

    this.alertRequestToken += 1;
    this.investigationRequestToken += 1;
    this.stopInvestigationOpenTimer();

    if (this.overlayEl) {
      this.overlayEl.classList.remove('active');
      this.overlayEl.setAttribute('aria-hidden', 'true');
    }
    this.setAppShellInert(false);
    this.overlayReturnFocusEl = null;

    this.data.alerts = [];
    this.data.alertByKey = {};
    this.data.investigations = [];
    this.data.healthOverview = null;
    this.data.healthError = '';
    this.data.logsetNameById = {};
    this.data.eventSourceNameByRrn = {};
    this.data.mitreByCode = {};
    this.data.currentDetail = null;
    this.data.detailHistory = [];
    this.data.lastAlertSyncAt = null;
    this.data.lastInvestigationSyncAt = null;
    this.data.lastHealthSyncAt = null;

    this.renderAlerts();
    this.renderInvestigations();
    this.renderHealth();
    this.refreshShellState();
  },

  async saveConfigForm(formEl) {
    const apiKey = document.getElementById('configApiKey').value;
    const region = document.getElementById('configRegion').value;
    const payload = { region };

    if (apiKey) payload.apiKey = apiKey;

    try {
      const res = await fetch(`${API_BASE}/config`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      const responsePayload = await this.safeJson(res);

      if (!res.ok) {
        throw new Error(this.getErrorMessage(responsePayload, 'Failed to save configuration.'));
      }

      formEl?.reset();
      await this.fetchConfig();
      this.resetAnalystDirectory();
      await this.fetchInvestigations();
      this.switchView('alertsView');
    } catch (error) {
      alert(error.message || 'Failed to save configuration.');
    }
  },

  async forgetStoredApiKey() {
    try {
      const res = await fetch(`${API_BASE}/config/clear`, {
        method: 'POST'
      });
      const responsePayload = await this.safeJson(res);

      if (!res.ok) {
        throw new Error(this.getErrorMessage(responsePayload, 'Failed to forget stored API key.'));
      }

      document.getElementById('configForm')?.reset();
      this.resetAnalystDirectory();
      this.resetOperationalData();
      await this.fetchConfig();
      this.switchView('settingsView');
    } catch (error) {
      alert(error.message || 'Failed to forget stored API key.');
    }
  },

  async ensureAnalystsLoaded(options = {}) {
    const {
      force = false,
      query = ''
    } = options;
    const normalizedQuery = String(query || '').trim();

    if (this.data.analystsLoaded && this.data.analystQuery === normalizedQuery && !force) {
      return this.data.analysts;
    }

    if (this.analystsRequestPromise && !force) {
      return this.analystsRequestPromise;
    }

    this.data.analystsLoading = true;
    const params = new URLSearchParams();
    if (normalizedQuery) {
      params.set('q', normalizedQuery);
    }

    const request = fetch(`${API_BASE}/analysts?${params.toString()}`)
      .then(async res => {
        const payload = await res.json();
        if (!res.ok) {
          throw new Error(payload?.error || 'Failed to load analysts');
        }

        this.data.analysts = Array.isArray(payload.data) ? payload.data : [];
        this.data.analystsLoaded = true;
        this.data.analystQuery = normalizedQuery;
        return this.data.analysts;
      })
      .catch(error => {
        console.error('Failed to load analysts', error);
        return this.data.analysts;
      })
      .finally(() => {
        this.data.analystsLoading = false;
        this.analystsRequestPromise = null;
        this.refreshAnalystSuggestions();
      });

    this.analystsRequestPromise = request;
    this.refreshAnalystSuggestions();
    return request;
  },

  handleAnalystFieldInput(value) {
    const query = String(value || '').trim();
    if (this.data.currentDetail?.item) {
      this.data.currentDetail.item._assigneeDraft = value;
    }

    if (this.analystSearchTimer) {
      window.clearTimeout(this.analystSearchTimer);
    }

    if (query.length < 1) {
      this.data.analysts = [];
      this.data.analystsLoaded = false;
      this.data.analystQuery = '';
      this.data.analystsLoading = false;
      this.refreshAnalystSuggestions();
      return;
    }

    // Manual entry is the primary path. Suggestions are best-effort only.
    this.analystSearchTimer = window.setTimeout(() => {
      this.ensureAnalystsLoaded({ force: true, query });
    }, 220);
  },

  refreshAnalystSuggestions() {
    const activeField = document.getElementById('updateAlertAssignee')
      || document.getElementById('updateInvAssignee');
    if (!activeField) return;

    const listId = activeField.getAttribute('list');
    const suggestionsEl = listId ? document.getElementById(listId) : null;
    if (suggestionsEl) {
      suggestionsEl.innerHTML = (this.data.analysts || []).map(analyst => `
        <option value="${escapeHtml(analyst.value || analyst.email || analyst.rrn || '')}" label="${escapeHtml(analyst.label || analyst.value || '')}"></option>
      `).join('');
    }

    const labelEl = activeField
      .closest('.form-group')
      ?.querySelector('.assignee-label');
    if (labelEl) {
      labelEl.classList.toggle('is-loading', this.data.analystsLoading);
    }
  },

  stopInvestigationOpenTimer() {
    if (this.investigationOpenTimerId) {
      window.clearInterval(this.investigationOpenTimerId);
      this.investigationOpenTimerId = null;
    }
  },

  refreshInvestigationOpenTimer() {
    const timerEl = document.querySelector('.js-investigation-open-timer');
    if (!timerEl) return;

    timerEl.textContent = formatInvestigationOpenDuration(timerEl.dataset.openedAt);
  },

  startInvestigationOpenTimer() {
    this.stopInvestigationOpenTimer();
    this.refreshInvestigationOpenTimer();

    const timerEl = document.querySelector('.js-investigation-open-timer');
    if (!timerEl || !timerEl.dataset.openedAt) return;

    this.investigationOpenTimerId = window.setInterval(() => {
      this.refreshInvestigationOpenTimer();
    }, 1000);
  },

  renderAlerts() {
    const container = document.getElementById('alertsContainer');
    if (!container) return;

    const alertView = this.buildAlertViewModel();
    container.innerHTML = renderAlertList(alertView);
    this.updateAlertMetrics(alertView);
  },

  renderInvestigations() {
    const container = document.getElementById('invContainer');
    if (!container) return;

    const filterValue = this.getStatusFilterValue('filterInvStatus');
    container.innerHTML = renderInvestigationList(this.data.investigations, filterValue);
    this.updateInvestigationMetrics();
  },

  renderHealth() {
    const container = document.getElementById('healthContainer');
    if (!container) return;

    if (this.data.healthError) {
      container.innerHTML = `
        <div class="empty-state error">
          <div class="empty-orb"></div>
          <p>${escapeHtml(this.data.healthError)}</p>
        </div>
      `;
      this.updateHealthMetrics();
      return;
    }

    container.innerHTML = renderHealthOverview(this.data.healthOverview);
    this.updateHealthMetrics();
  },

  async fetchAlerts() {
    const container = document.getElementById('alertsContainer');
    if (container) {
      container.innerHTML = '<div class="loading"><div class="loader-spinner"></div></div>';
    }

    if (this.alertsRequestController) {
      this.alertsRequestController.abort();
    }

    const requestToken = ++this.alertRequestToken;
    const controller = new AbortController();
    this.alertsRequestController = controller;

    try {
      const res = await fetch(`${API_BASE}/alerts?range=${encodeURIComponent(this.data.alertRange)}`, {
        signal: controller.signal
      });
      const data = await this.safeJson(res);

      if (!res.ok) {
        throw new Error(this.getErrorMessage(data, 'Error loading alerts.'));
      }

      if (requestToken !== this.alertRequestToken) {
        return;
      }

      const alertData = Array.isArray(data?.data) ? data.data : [];
      this.data.alerts = alertData.map((alert, idx) => ({
        ...alert,
        _uiKey: `${alert.rrn || alert.id || 'no-id'}::${alert.created_at || alert.alerted_at || alert.created_time || alert.createdTime || ''}::${idx}`,
        _stackMeta: buildAlertStackMeta(alert)
      }));
      this.data.alertByKey = this.data.alerts.reduce((acc, alert) => {
        acc[alert._uiKey] = alert;
        return acc;
      }, {});
      this.data.lastAlertSyncAt = new Date();
      this.renderAlerts();
    } catch (error) {
      if (error.name === 'AbortError' || requestToken !== this.alertRequestToken) {
        return;
      }

      if (container) {
        container.innerHTML = `<p class="loading error-state">${escapeHtml(error.message || 'Error loading alerts.')}</p>`;
      }
      this.setText('alertsPanelNote', error.message || 'Alert feed unavailable');
    } finally {
      if (this.alertsRequestController === controller) {
        this.alertsRequestController = null;
      }
    }
  },

  async fetchInvestigations() {
    const container = document.getElementById('invContainer');
    if (container) {
      container.innerHTML = '<div class="loading"><div class="loader-spinner"></div></div>';
    }

    if (this.investigationsRequestController) {
      this.investigationsRequestController.abort();
    }

    const requestToken = ++this.investigationRequestToken;
    const controller = new AbortController();
    this.investigationsRequestController = controller;

    try {
      const res = await fetch(`${API_BASE}/investigations?range=${encodeURIComponent(this.data.investigationRange)}`, {
        signal: controller.signal
      });
      const data = await this.safeJson(res);

      if (!res.ok) {
        throw new Error(this.getErrorMessage(data, 'Error loading investigations.'));
      }

      if (requestToken !== this.investigationRequestToken) {
        return;
      }

      this.data.investigations = Array.isArray(data?.data) ? data.data : [];
      this.data.lastInvestigationSyncAt = new Date();
      this.renderInvestigations();

      if (this.data.alertGroupingMode === 'INVESTIGATION') {
        this.renderAlerts();
      }
    } catch (error) {
      if (error.name === 'AbortError' || requestToken !== this.investigationRequestToken) {
        return;
      }

      if (container) {
        container.innerHTML = `<p class="loading error-state">${escapeHtml(error.message || 'Error loading investigations.')}</p>`;
      }
      this.setText('invPanelNote', error.message || 'Investigation feed unavailable');
    } finally {
      if (this.investigationsRequestController === controller) {
        this.investigationsRequestController = null;
      }
    }
  },

  async fetchHealthOverview() {
    const container = document.getElementById('healthContainer');
    if (container) {
      container.innerHTML = '<div class="loading"><div class="loader-spinner"></div></div>';
    }

    try {
      const res = await fetch(`${API_BASE}/health-metrics/overview`);
      const payload = await res.json();

      if (!res.ok) {
        throw new Error(payload?.error || payload?.message || 'Error loading health metrics.');
      }

      this.data.healthOverview = payload?.data || null;
      this.data.healthError = '';
      this.data.lastHealthSyncAt = new Date();
      this.renderHealth();
    } catch (error) {
      this.data.healthOverview = null;
      this.data.healthError = error.message || 'Error loading health metrics.';
      this.renderHealth();
    }
  },

  openDetailView(type, item, options = {}) {
    const {
      pushHistory = false,
      resetScroll = true
    } = options;
    const overlayWasActive = this.overlayEl.classList.contains('active');

    if (type === 'alert-stack') {
      const investigationMap = this.getInvestigationMap();
      const existingLinkedInvestigations = Array.isArray(item?._linkedInvestigations)
        ? item._linkedInvestigations
        : [];
      const existingLinkedLookup = existingLinkedInvestigations.reduce((lookup, investigation) => {
        const rrn = String(investigation?.rrn || '').trim();
        const id = String(investigation?.id || '').trim();
        if (rrn) lookup.set(rrn, investigation);
        if (id) lookup.set(id, investigation);
        return lookup;
      }, new Map());
      const linkedInvestigationRefs = uniqueValues(
        item?.investigationRefs || (item?.alerts || []).map(alert => alert?.investigation_rrn)
      );

      item = {
        ...item,
        _linkedInvestigations: linkedInvestigationRefs
          .map(ref => {
            const key = String(ref || '').trim();
            return existingLinkedLookup.get(key) || investigationMap.get(key) || { rrn: ref };
          })
          .filter(linkedItem => String(linkedItem?.rrn || linkedItem?.id || '').trim())
      };
    }

    if (pushHistory && this.data.currentDetail) {
      this.data.detailHistory.push({
        type: this.data.currentDetail.type,
        item: this.data.currentDetail.item
      });
    }

    if (!overlayWasActive) {
      const activeElement = document.activeElement;
      this.overlayReturnFocusEl = activeElement instanceof HTMLElement
        ? activeElement
        : null;
    }

    this.stopInvestigationOpenTimer();
    this.data.currentDetail = { type, item };
    const contentEl = document.getElementById('overlay-content');
    const titleEl = document.getElementById('overlay-title');
    const kickerEl = document.getElementById('overlay-kicker');

    if (type === 'alert') {
      kickerEl.textContent = 'Threat Intelligence';
      titleEl.textContent = 'Alert Details';
      contentEl.innerHTML = renderAlertDetail(item, {
        analysts: this.data.analysts,
        analystsLoading: this.data.analystsLoading
      });
      this.resolveAlertLogsetNames(item);
      this.resolveAlertEventSourceNames(item);

      setTimeout(() => {
        const createInvBtn = document.getElementById('btn-create-inv');
        if (createInvBtn) {
          createInvBtn.addEventListener('click', () => {
            contentEl.innerHTML = `
              <section class="detail-stack">
                <div class="section-heading">
                  <p class="eyebrow">Response Escalation</p>
                  <h3>Create investigation</h3>
                </div>
                <form id="createInvForm" class="glass-panel detail-form">
                  <div class="form-group">
                    <label for="invTitle">Title</label>
                    <input
                      type="text"
                      id="invTitle"
                      class="control-input"
                      value="${escapeHtml(`Investigating: ${item.title || 'Alert'}`)}"
                      required
                    />
                  </div>
                  <div class="form-group">
                    <label for="invPri">Priority</label>
                    <select id="invPri" class="control-input">
                      <option value="CRITICAL">Critical</option>
                      <option value="HIGH" selected>High</option>
                      <option value="MEDIUM">Medium</option>
                      <option value="LOW">Low</option>
                    </select>
                  </div>
                  <button class="btn mt-4" type="submit">Create Investigation</button>
                </form>
              </section>
            `;
          });
        }
      }, 0);
    } else if (type === 'alert-stack') {
      kickerEl.textContent = item?.mode === 'ATTACK_PATH' ? 'Attack Pathing' : 'Queue Intelligence';
      titleEl.textContent = item?.mode === 'ATTACK_PATH' ? 'Path Details' : 'Stack Details';
      contentEl.innerHTML = renderAlertStackDetail(item, {
        modeLabel: this.getAlertGroupingLabel(item?.mode)
      });
      this.resolveStackLinkedInvestigations(item);
    } else {
      kickerEl.textContent = 'Case Management';
      titleEl.textContent = 'Investigation Details';
      contentEl.innerHTML = renderInvestigationDetail(item, {
        analysts: this.data.analysts.filter(analyst => analyst.email),
        analystsLoading: this.data.analystsLoading
      });
      this.startInvestigationOpenTimer();
    }

    if (resetScroll) {
      contentEl.scrollTop = 0;
    }

    this.setAppShellInert(true);
    this.overlayEl.classList.add('active');
    this.overlayEl.setAttribute('aria-hidden', 'false');
    requestAnimationFrame(() => {
      contentEl.focus({ preventScroll: true });
    });
  },

  async submitAlertUpdate() {
    const currentAlert = this.data.currentDetail?.item;
    if (!currentAlert) return;

    const alertId = currentAlert.id || currentAlert.rrn;
    const assigneeId = normalizeTextValue(document.getElementById('updateAlertAssignee')?.value);
    const nextStatus = normalizeSelectionValue(document.getElementById('updateAlertStatus')?.value);
    const nextPriority = normalizeSelectionValue(document.getElementById('updateAlertPriority')?.value);
    const nextDisposition = normalizeSelectionValue(document.getElementById('updateAlertDisp')?.value);
    const payload = {};

    if (nextStatus !== normalizeSelectionValue(currentAlert.status)) {
      payload.status = nextStatus;
    }

    if (nextPriority !== normalizeSelectionValue(currentAlert.priority)) {
      payload.priority = nextPriority;
    }

    if (nextDisposition !== normalizeSelectionValue(currentAlert.disposition)) {
      payload.disposition = nextDisposition;
    }

    const currentAssigneeId = normalizeTextValue(getAssigneeInputValue(currentAlert.assignee));
    if (assigneeId !== currentAssigneeId) {
      if (!assigneeId) {
        alert('Alert unassignment is not supported by the Alert Triage API.');
        return;
      }
      payload.assignee_id = assigneeId;
    }

    if (Object.keys(payload).length === 0) {
      alert('No alert changes to save.');
      return;
    }

    try {
      const res = await fetch(`${API_BASE}/alerts/${encodeURIComponent(alertId)}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      const responsePayload = await this.safeJson(res);

      if (!res.ok) {
        throw new Error(this.getErrorMessage(responsePayload, 'Failed to update alert.'));
      }

      const selectedAnalyst = this.data.analysts.find(analyst =>
        String(analyst.rrn || '').trim() === assigneeId || String(analyst.email || '').trim() === assigneeId
      );

      delete currentAlert._assigneeDraft;

      if (payload.status) currentAlert.status = payload.status;
      if (payload.priority) currentAlert.priority = payload.priority;
      if (payload.disposition) currentAlert.disposition = payload.disposition;
      if (payload.assignee_id !== undefined) {
        currentAlert.assignee = selectedAnalyst
          ? { name: selectedAnalyst.name, email: selectedAnalyst.email || selectedAnalyst.rrn, rrn: selectedAnalyst.rrn }
          : payload.assignee_id;
      }

      this.openDetailView('alert', currentAlert);
      await this.fetchAlerts();
    } catch (error) {
      alert(error.message || 'Failed to update alert.');
    }
  },

  async submitCreateInv() {
    const title = document.getElementById('invTitle').value;
    const priority = document.getElementById('invPri').value;
    const alertId = this.data.currentDetail.item.id || this.data.currentDetail.item.rrn;

    try {
      const res = await fetch(`${API_BASE}/alerts/${encodeURIComponent(alertId)}/investigate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          title,
          priority,
          status: 'OPEN',
          disposition: 'UNDECIDED',
          organization_id: this.data.currentDetail.item.organization?.id
        })
      });
      const payload = await this.safeJson(res);

      if (!res.ok) {
        throw new Error(this.getErrorMessage(payload, 'Failed to create investigation.'));
      }

      alert('Investigation creation started and alert association is in progress.');
      await Promise.all([this.fetchAlerts(), this.fetchInvestigations()]);
      this.overlayEl.classList.remove('active');
      document.querySelectorAll('.nav-btn')[1].click();
    } catch (error) {
      alert(error.message || 'Failed to create investigation.');
    }
  },

  async submitInvUpdate() {
    const currentInvestigation = this.data.currentDetail?.item;
    if (!currentInvestigation) return;

    const invId = this.getInvestigationRequestRef(currentInvestigation);
    const assigneeEmail = normalizeTextValue(document.getElementById('updateInvAssignee')?.value);
    const nextStatus = normalizeSelectionValue(document.getElementById('updateInvStatus')?.value);
    const nextPriority = normalizeSelectionValue(document.getElementById('updateInvPriority')?.value);
    const nextDisposition = normalizeSelectionValue(document.getElementById('updateInvDisp')?.value);
    const payload = {};

    if (nextStatus !== normalizeSelectionValue(currentInvestigation.status)) {
      payload.status = nextStatus;
    }

    if (nextPriority !== normalizeSelectionValue(currentInvestigation.priority)) {
      payload.priority = nextPriority;
    }

    const currentDisposition = normalizeSelectionValue(currentInvestigation.disposition);
    if (
      INVESTIGATION_DISPOSITION_UPDATE_OPTIONS.has(nextDisposition)
      && (nextDisposition !== currentDisposition || payload.status === 'CLOSED')
    ) {
      payload.disposition = nextDisposition;
    }

    const currentAssigneeEmail = normalizeTextValue(getAssigneeInputValue(currentInvestigation.assignee));
    if (assigneeEmail !== currentAssigneeEmail) {
      payload.assignee_email = assigneeEmail;
    }

    if (Object.keys(payload).length === 0) {
      alert('No investigation changes to save.');
      return;
    }

    try {
      const res = await fetch(`${API_BASE}/investigations/${encodeURIComponent(invId)}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      const responsePayload = await this.safeJson(res);

      if (!res.ok) {
        throw new Error(this.getErrorMessage(responsePayload, 'Failed to update investigation.'));
      }

      const selectedAnalyst = this.data.analysts.find(analyst =>
        String(analyst.email || '').trim() === assigneeEmail
      );

      delete currentInvestigation._assigneeDraft;

      if (payload.status) currentInvestigation.status = payload.status;
      if (payload.priority) currentInvestigation.priority = payload.priority;
      if (payload.disposition) currentInvestigation.disposition = payload.disposition;
      if (Object.prototype.hasOwnProperty.call(payload, 'assignee_email')) {
        currentInvestigation.assignee = selectedAnalyst
          ? { name: selectedAnalyst.name, email: selectedAnalyst.email }
          : (assigneeEmail ? { name: assigneeEmail, email: assigneeEmail } : null);
      }

      this.openDetailView('investigation', currentInvestigation);
      await this.fetchInvestigations();
    } catch (error) {
      alert(error.message || 'Failed to update investigation.');
    }
  },

  async submitInvestigationComment(form) {
    const currentInvestigation = this.data.currentDetail?.item;
    const investigationRef = this.getInvestigationRequestRef(currentInvestigation);
    if (!currentInvestigation || !investigationRef || !form) return;

    const bodyField = form.querySelector('#investigationCommentBody');
    const attachmentField = form.querySelector('#investigationCommentAttachments');
    const submitButton = form.querySelector('button[type="submit"]');
    const body = (bodyField?.value || '').trim();
    const files = Array.from(attachmentField?.files || []);

    if (!body && files.length === 0) {
      alert('Enter a comment or attach at least one file.');
      return;
    }

    if (submitButton) {
      submitButton.disabled = true;
      submitButton.textContent = files.length > 0 ? 'Uploading Files...' : 'Posting Comment...';
    }

    try {
      const uploadedAttachments = await this.uploadAttachments(files);
      const attachmentRrns = uploadedAttachments
        .map(attachment => attachment?.rrn)
        .filter(Boolean);

      if (files.length > 0 && attachmentRrns.length === 0) {
        throw new Error('Attachment upload completed without usable attachment references');
      }

      const response = await fetch(`${API_BASE}/investigations/${encodeURIComponent(investigationRef)}/comments`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          body,
          attachments: attachmentRrns
        })
      });
      const payload = await this.safeJson(response);

      if (!response.ok) {
        throw new Error(this.getErrorMessage(payload, 'Failed to create comment'));
      }

      await this.hydrateInvestigationDetail(currentInvestigation, investigationRef);
      this.openDetailView('investigation', currentInvestigation);
      this.fetchInvestigations();
    } catch (error) {
      alert(error.message || 'Failed to create comment');
    } finally {
      if (submitButton) {
        submitButton.disabled = false;
        submitButton.textContent = 'Post Comment';
      }
    }
  }
};

document.addEventListener('DOMContentLoaded', () => {
  MainApp.init();
});
