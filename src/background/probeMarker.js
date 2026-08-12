/**
 * Probe marker header.
 *
 * Every extension-initiated scan/probe request carries a marker header so that
 * the user can filter this traffic out in Burp / proxy tools while probing still
 * works normally. The request is still sent (and still visible on the wire) — the
 * marker just lets the proxy UI hide it, decluttering manual-testing sessions.
 *
 * Default: `X-Nothing-Probe: 1`. Configurable via settings:
 *   settings.probeMarker       (boolean, default true — set false to disable)
 *   settings.probeMarkerName   (string, default 'X-Nothing-Probe')
 *   settings.probeMarkerValue  (string, default '1')
 */

const DEFAULT_NAME = 'X-Nothing-Probe';
const DEFAULT_VALUE = '1';

let enabled = true;
let markerName = DEFAULT_NAME;
let markerValue = DEFAULT_VALUE;

function loadConfig() {
  try {
    chrome.storage.local.get('settings', (data) => {
      const s = data.settings || {};
      enabled = s.probeMarker !== false;
      markerName = (typeof s.probeMarkerName === 'string' && s.probeMarkerName.trim())
        ? s.probeMarkerName.trim() : DEFAULT_NAME;
      markerValue = (typeof s.probeMarkerValue === 'string' && s.probeMarkerValue.trim())
        ? s.probeMarkerValue.trim() : DEFAULT_VALUE;
    });
  } catch {}
}

loadConfig();

chrome.storage.onChanged.addListener((changes, area) => {
  if (area === 'local' && changes.settings) loadConfig();
});

/**
 * Return the marker header as a plain object, ready to spread into fetch headers.
 * Returns {} when disabled.
 * @returns {Record<string,string>}
 */
export function getProbeHeaders() {
  if (!enabled) return {};
  return { [markerName]: markerValue };
}

/**
 * Merge the probe marker into an existing fetch headers object/init.
 * @param {Record<string,string>} [headers]
 * @returns {Record<string,string>}
 */
export function withProbeHeaders(headers = {}) {
  return { ...headers, ...getProbeHeaders() };
}
