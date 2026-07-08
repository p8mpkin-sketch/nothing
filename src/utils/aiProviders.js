// Shared AI provider registry.
// Used by both the popup settings UI and the background request builder (callAI),
// so adding a new provider only requires one entry here.
//
// style: 'anthropic' -> POST {base}{chatPath} with x-api-key + Messages API body
//        'openai'    -> POST {base}{chatPath} with Bearer + Chat Completions body
// base:  official endpoint used when the user leaves the proxy field empty
// chatPath: appended to base (or to the user proxy) to form the final URL
export const AI_PROVIDERS = {
  openai: {
    label: 'OpenAI',
    style: 'openai',
    base: 'https://api.openai.com',
    chatPath: '/v1/chat/completions',
    defaultModel: 'gpt-4o-mini',
    keyPlaceholder: 'sk-...',
    modelPlaceholder: 'gpt-4o-mini',
    allowProxy: false,
  },
  anthropic: {
    label: 'Anthropic',
    style: 'anthropic',
    base: 'https://api.anthropic.com',
    chatPath: '/v1/messages',
    defaultModel: 'claude-haiku-4-5-20251001',
    keyPlaceholder: 'sk-ant-...',
    modelPlaceholder: 'claude-haiku-4-5-20251001',
    allowProxy: true,
  },
  deepseek: {
    label: 'DeepSeek',
    style: 'openai',
    base: 'https://api.deepseek.com',
    chatPath: '/v1/chat/completions',
    defaultModel: 'deepseek-chat',
    keyPlaceholder: 'sk-...',
    modelPlaceholder: 'deepseek-chat / deepseek-reasoner',
    allowProxy: true,
  },
  glm: {
    label: '智谱 GLM',
    style: 'openai',
    base: 'https://open.bigmodel.cn/api/paas/v4',
    chatPath: '/chat/completions',
    defaultModel: 'glm-4-flash',
    keyPlaceholder: '{id}.{secret}',
    modelPlaceholder: 'glm-4-flash / glm-4-plus / glm-4.6',
    allowProxy: true,
  },
  custom: {
    label: '自定义 (OpenAI兼容)',
    style: 'openai',
    // Falls back to OpenAI's host if the user leaves the endpoint empty,
    // matching the previous behaviour.
    base: 'https://api.openai.com',
    chatPath: '/v1/chat/completions',
    defaultModel: '',
    keyPlaceholder: 'sk-...',
    modelPlaceholder: 'gpt-4o-mini',
    allowProxy: true,
    proxyRequired: true,
  },
};

export function getProvider(id) {
  return AI_PROVIDERS[id] || AI_PROVIDERS.openai;
}

// Build the final request URL for a provider, honouring an optional user proxy.
export function resolveAiUrl(providerId, endpoint) {
  const p = getProvider(providerId);
  const proxy = endpoint ? endpoint.replace(/\/+$/, '') : '';
  return (proxy || p.base) + p.chatPath;
}
