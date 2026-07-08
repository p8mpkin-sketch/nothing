/**
 * Append a log entry to storage.
 * @param {string} ruleName 
 * @param {string} url 
 * @param {string} type - 'match', 'info', 'error'
 * @param {string} message 
 */
export async function addLog(ruleName, url, type, message = '') {
    const data = await chrome.storage.local.get('logs');
    const logs = data.logs || [];

    const newLog = {
        timestamp: Date.now(),
        ruleName,
        url,
        type,
        message
    };

    // Keep last 100 logs
    const updatedLogs = [...logs, newLog].slice(-100);

    await chrome.storage.local.set({ logs: updatedLogs });
}
