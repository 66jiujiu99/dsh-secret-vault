window.__ModuleLoader__.load({
	id: 'dsh-secret-vault',
	factory(require) {
		const React = require('react');
		const h = React.createElement;
		const useState = React.useState;
		const useEffect = React.useEffect;
		const useCallback = React.useCallback;
		const useRef = React.useRef;

		/** Same-origin route the Host half registers for the settings page. */
		const ENDPOINT = '/vault/api';
		/** One management call must settle well before a user gives up on the page. */
		const CALL_TIMEOUT_MS = 15000;
		/** The stylesheet tag identity, used by idempotent injection and its cleanup. */
		const STYLE_ID = 'sv-styles';

		/**
		 * Read the per-boot management token the Host injects into the authenticated
		 * page as a meta tag. The vault route rejects calls without it, so a local
		 * process (including the model's shell) cannot change credential policy.
		 * @returns the token, or an empty string when the page was not injected.
		 */
		function readUiToken() {
			try {
				const meta = document.querySelector('meta[name="dsh-secret-vault-token"]');
				return meta !== null ? meta.getAttribute('content') || '' : '';
			} catch (error) {
				return '';
			}
		}

		const HTTP_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'];
		const AUTH_TYPES = ['bearer', 'basic', 'header', 'query'];
		const KINDS = ['token', 'api-key', 'password', 'cookie', 'cloud', 'other'];

		/**
		 * Create-time presets. They only prefill the form; the user still supplies
		 * the secret, and policy fields stay immutable after the first save.
		 */
		const PRESETS = [
			{
				id: 'custom', labelKey: 'preset.custom', itemId: '', level: 'controlled',
				kind: 'token', authType: 'bearer', hosts: '', methods: ['GET'], commands: '',
			},
			{
				id: 'github-read', labelKey: 'preset.github-read', itemId: 'github-read', level: 'sealed',
				kind: 'token', authType: 'bearer', hosts: 'api.github.com', methods: ['GET'], commands: '',
				maxUses: '0', ttlMinutes: '0',
			},
			{
				id: 'github-manage', labelKey: 'preset.github-manage', itemId: 'github-manage', level: 'sealed',
				kind: 'token', authType: 'bearer', hosts: 'api.github.com',
				methods: ['GET', 'POST', 'PATCH', 'DELETE'], commands: '',
			},
			{
				id: 'github-cli', labelKey: 'preset.github-cli', itemId: 'github-git', level: 'controlled',
				kind: 'token', authType: 'bearer', hosts: 'github.com, api.github.com',
				methods: ['GET'], commands: '$env:gh_token, gh, git',
			},
			{
				id: 'cloudflare-api', labelKey: 'preset.cloudflare-api', itemId: 'cloudflare-api', level: 'sealed',
				kind: 'cloud', authType: 'bearer', hosts: 'api.cloudflare.com',
				methods: ['GET', 'POST', 'PATCH', 'DELETE'], commands: '',
			},
			{
				id: 'cloudflare-wrangler', labelKey: 'preset.cloudflare-wrangler', itemId: 'cloudflare-deploy', level: 'controlled',
				kind: 'cloud', authType: 'bearer', hosts: 'api.cloudflare.com',
				methods: ['GET'], commands: '$env:cloudflare_api_token, wrangler',
			},
			{
				id: 'cloud-api', labelKey: 'preset.cloud-api', itemId: 'cloud-api', level: 'sealed',
				kind: 'cloud', authType: 'bearer', hosts: '', methods: ['GET', 'POST'], commands: '',
			},
		];

		/** Every privacy level, its badge label key and its one-line explanation key. */
		const LEVELS = [
			{ id: 'controlled', badgeKey: 'level.controlled', helpKey: 'level.controlled.help' },
			{ id: 'sealed', badgeKey: 'level.sealed', helpKey: 'level.sealed.help' },
			{ id: 'ephemeral', badgeKey: 'level.ephemeral', helpKey: 'level.ephemeral.help' },
		];
		const LEVEL_BY_ID = {
			controlled: LEVELS[0],
			sealed: LEVELS[1],
			ephemeral: LEVELS[2],
		};

		/* ------------------------------------------------------------------ *
		 * Styles. Only --dsw-alias-* theme tokens are used for colour, border *
		 * and background so light/dark switching and host theming keep working.*
		 * ------------------------------------------------------------------ */
		const STYLES = `
.sv-root {
  display: flex;
  flex-direction: column;
  gap: 14px;
  max-width: 880px;
  padding: 2px 2px 28px;
  color: var(--dsw-alias-label-primary);
  font-size: 13px;
  line-height: 1.55;
}
.sv-header { display: flex; flex-direction: column; gap: 6px; }
.sv-heading-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  flex-wrap: wrap;
}
.sv-title { margin: 0; font-size: 18px; font-weight: 600; }
.sv-desc { margin: 0; color: var(--dsw-alias-label-secondary); }
.sv-vaultline {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 4px 18px;
  color: var(--dsw-alias-label-secondary);
  font-size: 12px;
}
.sv-vaultline strong { color: var(--dsw-alias-label-primary); font-weight: 600; }
.sv-path {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;
  word-break: break-all;
}
.sv-actions { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.sv-btn {
  appearance: none;
  border: 1px solid var(--dsw-alias-border-l2);
  border-radius: 6px;
  background: var(--dsw-alias-bg-layer-1);
  color: var(--dsw-alias-label-primary);
  padding: 5px 12px;
  font: inherit;
  font-size: 12px;
  line-height: 20px;
  cursor: pointer;
  white-space: nowrap;
}
.sv-btn:hover:not(:disabled) { background: var(--dsw-alias-bg-layer-2); }
.sv-btn:focus-visible {
  outline: 2px solid var(--dsw-alias-brand-primary);
  outline-offset: 1px;
}
.sv-btn:disabled { opacity: 0.55; cursor: default; }
.sv-btn--primary {
  border-color: var(--dsw-alias-brand-primary);
  color: var(--dsw-alias-brand-primary);
}
.sv-btn--danger {
  border-color: var(--dsw-alias-state-error-primary);
  color: var(--dsw-alias-state-error-primary);
}
.sv-btn--sm { padding: 3px 9px; font-size: 12px; }
.sv-legend {
  display: flex;
  flex-direction: column;
  gap: 6px;
  padding: 10px 12px;
  border: 1px solid var(--dsw-alias-border-l1);
  border-radius: 8px;
  background: var(--dsw-alias-bg-layer-1);
}
.sv-legend-row { display: flex; align-items: baseline; gap: 8px; flex-wrap: wrap; }
.sv-legend-text { color: var(--dsw-alias-label-secondary); }
.sv-notice {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 8px 12px;
  border: 1px solid var(--dsw-alias-border-l2);
  border-radius: 6px;
  background: var(--dsw-alias-bg-layer-1);
}
.sv-notice--ok {
  border-color: var(--dsw-alias-state-success-primary);
  color: var(--dsw-alias-state-success-primary);
}
.sv-notice--error {
  border-color: var(--dsw-alias-state-error-primary);
  color: var(--dsw-alias-state-error-primary);
}
.sv-notice-text { min-width: 0; word-break: break-word; }
.sv-empty {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 8px;
  padding: 28px 16px;
  border: 1px dashed var(--dsw-alias-border-l2);
  border-radius: 8px;
  color: var(--dsw-alias-label-secondary);
  text-align: center;
}
.sv-empty-title { font-size: 14px; font-weight: 600; color: var(--dsw-alias-label-primary); }
.sv-list { display: flex; flex-direction: column; gap: 8px; }
.sv-item {
  display: flex;
  flex-direction: column;
  gap: 8px;
  padding: 12px;
  border: 1px solid var(--dsw-alias-border-l1);
  border-radius: 8px;
  background: var(--dsw-alias-bg-layer-1);
}
.sv-item-head { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.sv-item-label { font-weight: 600; font-size: 13px; }
.sv-item-id {
  color: var(--dsw-alias-label-secondary);
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;
  font-size: 12px;
}
.sv-item-secret { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
.sv-mask {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;
  color: var(--dsw-alias-label-primary);
  letter-spacing: 0.04em;
}
.sv-badge {
  display: inline-flex;
  align-items: center;
  border: 1px solid var(--dsw-alias-border-l2);
  border-radius: 999px;
  padding: 0 8px;
  font-size: 11px;
  line-height: 18px;
  color: var(--dsw-alias-label-secondary);
  background: var(--dsw-alias-bg-layer-2);
  white-space: nowrap;
}
.sv-badge--controlled {
  border-color: var(--dsw-alias-brand-primary);
  color: var(--dsw-alias-brand-primary);
}
.sv-badge--sealed {
  border-color: var(--dsw-alias-state-warn-primary);
  color: var(--dsw-alias-state-warn-primary);
}
.sv-badge--ephemeral {
  border-color: var(--dsw-alias-state-error-primary);
  color: var(--dsw-alias-state-error-primary);
}
.sv-badge--expired {
  border-color: var(--dsw-alias-state-error-primary);
  color: var(--dsw-alias-state-error-primary);
}
.sv-meta {
  display: flex;
  flex-wrap: wrap;
  gap: 3px 16px;
  font-size: 12px;
  color: var(--dsw-alias-label-secondary);
}
.sv-meta strong { color: var(--dsw-alias-label-primary); font-weight: 500; }
.sv-item-actions {
  display: flex;
  align-items: center;
  justify-content: flex-end;
  gap: 8px;
  flex-wrap: wrap;
}
.sv-form {
  display: flex;
  flex-direction: column;
  gap: 12px;
  padding: 14px;
  border: 1px solid var(--dsw-alias-border-l1);
  border-radius: 8px;
  background: var(--dsw-alias-bg-layer-1);
}
.sv-form-head { display: flex; flex-direction: column; gap: 3px; }
.sv-form-title { margin: 0; font-size: 14px; font-weight: 600; }
.sv-form-hint { margin: 0; }
.sv-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 12px;
}
.sv-field { display: flex; flex-direction: column; gap: 4px; min-width: 0; }
.sv-field--wide { grid-column: 1 / -1; }
.sv-label { font-size: 12px; color: var(--dsw-alias-label-secondary); }
.sv-input, .sv-select {
  box-sizing: border-box;
  width: 100%;
  border: 1px solid var(--dsw-alias-border-l2);
  border-radius: 6px;
  background: var(--dsw-alias-bg-base);
  color: var(--dsw-alias-label-primary);
  padding: 6px 9px;
  font: inherit;
  font-size: 13px;
  line-height: 20px;
}
.sv-input:focus, .sv-select:focus {
  outline: 2px solid var(--dsw-alias-brand-primary);
  outline-offset: -1px;
  border-color: var(--dsw-alias-brand-primary);
}
.sv-input:read-only {
  background: var(--dsw-alias-bg-layer-2);
  color: var(--dsw-alias-label-secondary);
}
.sv-hint { font-size: 11px; color: var(--dsw-alias-label-secondary); }
.sv-choices { display: flex; flex-wrap: wrap; gap: 6px 16px; }
.sv-choice {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-size: 13px;
  cursor: pointer;
}
.sv-choice input, .sv-level input {
  margin: 0;
  accent-color: var(--dsw-alias-brand-primary);
}
.sv-levels {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 8px;
}
.sv-level {
  display: flex;
  flex-direction: column;
  gap: 2px;
  padding: 8px 10px;
  border: 1px solid var(--dsw-alias-border-l2);
  border-radius: 6px;
  background: var(--dsw-alias-bg-base);
  cursor: pointer;
}
.sv-level--active {
  border-color: var(--dsw-alias-brand-primary);
  background: var(--dsw-alias-bg-layer-2);
}
.sv-level-head { display: flex; align-items: center; gap: 6px; }
.sv-level-name { font-size: 13px; font-weight: 500; }
.sv-error { color: var(--dsw-alias-state-error-primary); font-size: 12px; }
.sv-form-actions {
  display: flex;
  align-items: center;
  justify-content: flex-end;
  gap: 8px;
  flex-wrap: wrap;
}
.sv-note {
  margin: 0;
  padding-top: 2px;
  color: var(--dsw-alias-label-secondary);
  font-size: 11px;
  line-height: 1.6;
}
.sv-subgrid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 10px;
}
`;

		/** Idempotently add the stylesheet; a no-op when it is already present. */
		function ensureStyles() {
			if (typeof document === 'undefined') return;
			if (document.getElementById(STYLE_ID) !== null) return;
			const node = document.createElement('style');
			node.id = STYLE_ID;
			node.textContent = STYLES;
			document.head.appendChild(node);
		}

		/** Remove only the stylesheet this plugin injected. */
		function removeStyles() {
			if (typeof document === 'undefined') return;
			const node = document.getElementById(STYLE_ID);
			if (node !== null && node.parentNode !== null) node.parentNode.removeChild(node);
		}

		/* ------------------------------------------------------------------ *
		 * Locale dictionaries. Chinese is the product copy; English is the    *
		 * parallel fallback. Plain t(key) only: interpolation is not assumed. *
		 * ------------------------------------------------------------------ */
		const zh = {
			'nav': '凭证保险库',
			'page.title': '凭证保险库',
			'page.desc': '凭证只用于使用、不能被读回：保存后界面只显示掩码，忘记值只能轮换（覆盖）。',
			'page.pathLabel': '存储位置',
			'page.countLabel': '凭证数量',
			'page.locked': '未解锁',
			'page.unknownPath': '（尚未读取）',
			'page.securityNote': '说明：DPAPI 只防止其他 OS 用户或离线捡到磁盘；同一用户下的任何进程都能解密，不构成隔离边界。高价值凭证请使用密封或一次性等级。',
			'action.refresh': '刷新',
			'action.refreshing': '刷新中…',
			'action.add': '新增凭证',
			'action.edit': '编辑',
			'action.delete': '删除',
			'action.confirmDelete': '确认删除？',
			'action.confirmDeleteAria': '再次点击确认删除 ',
			'action.deleteAria': '删除 ',
			'action.cancel': '取消',
			'action.save': '保存',
			'action.saving': '保存中…',
			'action.deleting': '删除中…',
			'action.retry': '重试',
			'level.controlled': '受控 · L1',
			'level.sealed': '密封 · L2',
			'level.ephemeral': '一次性 · L3',
			'level.controlled.help': 'L1 受控：命令里用占位符 [[vault:<id>]]，预执行时替换成真值；值会进入一次子进程，适合低风险 PAT。',
			'level.sealed.help': 'L2 密封：值不进入子进程，只由 Host 在进程内发起 HTTP；必须填写域名与 HTTP 方法。',
			'level.ephemeral.help': 'L3 一次性：同密封，但每次使用都要在当前会话中由你确认；子代理不能使用。',
			'status.expired': '已过期',
			'item.maskedHint': '仅显示掩码，明文保存后不可查看',
			'item.maskedAria': '已掩码的凭证值',
			'meta.kind': '类型：',
			'meta.auth': '注入：',
			'meta.hosts': '域名：',
			'meta.methods': '方法：',
			'meta.usesPrefix': '使用 ',
			'meta.usesSuffix': ' 次',
			'meta.lastUsed': '最近使用：',
			'meta.never': '从未',
			'meta.ttl': '有效期：',
			'meta.ttlUnit': ' 分钟',
			'meta.commands': '命令：',
			'state.loading': '正在读取保险库…',
			'state.unavailable': '暂时无法读取保险库，修复后点击上方「重试」。',
			'state.emptyTitle': '还没有凭证',
			'state.emptyBody': '新增一条凭证后，模型只能按等级使用它，永远读不回明文。',
			'notice.loadFailed': '读取失败：',
			'notice.deleteFailed': '删除失败：',
			'notice.created': '凭证已保存',
			'notice.updated': '凭证已更新',
			'notice.deleted': '凭证已删除',
			'error.timeout': '请求超时（15 秒），请确认插件宿主端可用后重试',
			'error.network': '无法连接插件宿主端：',
			'error.http': '管理接口返回 HTTP ',
			'error.badResponse': '管理接口返回了无法解析的响应',
			'error.rejected': '请求被拒绝',
			'error.unknown': '未知错误',
			'error.id': 'ID 必须以小写字母或数字开头，只能包含 a-z、0-9、.、_、-，最长 64 位',
			'error.label': '名称不能为空',
			'error.secretRequired': '新增凭证时必须填写凭证值',
			'error.secretShort': '凭证值至少 8 个字符（太短无法可靠脱敏）',
			'error.hostsRequired': '密封 / 一次性等级必须至少填写一个域名',
			'error.methodsRequired': '至少选择一个 HTTP 方法',
			'error.maxUses': '使用次数上限必须是 0 或正整数',
			'error.ttl': '有效期必须是 0 或正整数分钟',
			'error.authName': '请填写要注入的 Header / Query 名称',
			'error.authUsername': '请填写 Basic 用户名',
			'error.level': '请选择私密等级',
			'error.authType': '请选择注入方式',
			'form.createTitle': '新增凭证',
			'form.editTitle': '编辑凭证',
			'form.editHint': '凭证值不会回显；留空表示继续使用现有值，填写新值即轮换。',
			'form.policyLocked': '等级、认证方式、hosts、methods、commands 创建后不可修改；如需变更请删除后重建。',
			'form.preset': '预设',
			'form.presetHint': '选择 GitHub / Cloudflare 等预设会自动填好等级、认证方式、hosts、methods；保存后策略字段不可再改。',
			'kind.token': 'token',
			'kind.api-key': 'api-key',
			'kind.password': 'password',
			'kind.cookie': 'cookie',
			'kind.cloud': 'cloud（云服务）',
			'kind.other': 'other',
			'preset.custom': '自定义',
			'preset.github-read': 'GitHub API · 只读（sealed）',
			'preset.github-manage': 'GitHub API · 建/删仓（sealed）',
			'preset.github-cli': 'GitHub CLI / git（controlled）',
			'preset.cloudflare-api': 'Cloudflare API（sealed）',
			'preset.cloudflare-wrangler': 'Cloudflare Wrangler 部署（controlled）',
			'preset.cloud-api': '通用 Cloud API（sealed，自定义域名）',
			'form.id': 'ID',
			'form.idHint': '小写字母或数字开头，只含 a-z 0-9 . _ -，最长 64 位；保存后不可修改',
			'form.label': '名称',
			'form.labelPlaceholder': '例如：GitHub 只读 PAT',
			'form.level': '私密等级',
			'form.kind': '类型',
			'form.kindPlaceholder': '例如：token / api-key / password',
			'form.secret': '凭证值',
			'form.secretPlaceholderCreate': '粘贴凭证值（只写不读）',
			'form.secretPlaceholderEdit': '留空表示不轮换',
			'form.secretHint': '保存后不可再查看，只能轮换；界面上永远只显示掩码。',
			'form.auth': '注入方式',
			'form.auth.name': 'Header / Query 名称',
			'form.auth.namePlaceholder': '例如：X-Api-Key',
			'form.auth.username': 'Basic 用户名',
			'form.authHint.bearer': '以 Authorization: Bearer <凭证值> 发送。',
			'form.authHint.basic': '把「用户名 + 凭证值」编码后放进 Authorization 头。',
			'form.authHint.header': '把凭证值放进指定名称的自定义请求头。',
			'form.authHint.query': '把凭证值作为指定名称的查询参数附加到 URL。',
			'form.hosts': '允许的域名',
			'form.hostsPlaceholder': 'api.github.com, *.example.com（逗号分隔）',
			'form.hostsHint': '密封 / 一次性等级必填；仅允许访问这些域名。',
			'form.methods': '允许的 HTTP 方法',
			'form.commands': '允许的命令前缀',
			'form.commandsPlaceholder': 'git, gh, npm（逗号分隔）',
			'form.commandsHint': '仅受控等级用占位符时校验；留空表示不限制（不推荐）。',
			'form.maxUses': '使用次数上限',
			'form.maxUsesHint': '0 表示不限制',
			'form.ttl': '有效期（分钟）',
			'form.ttlHint': '0 表示不过期',
			'form.burnAfterUse': '最后一次使用后自动删除',
			'form.burnAfterUseHint': '仅在一次性等级可用。',
			'auth.bearer': 'Bearer 头',
			'auth.basic': 'Basic 认证',
			'auth.header': '自定义 Header',
			'auth.query': '查询参数',
		};

		const en = {
			'nav': 'Secret Vault',
			'page.title': 'Secret Vault',
			'page.desc': 'Credentials are use-only and never read back: after saving, the page shows only a mask; a forgotten value can only be rotated (overwritten).',
			'page.pathLabel': 'Location',
			'page.countLabel': 'Credentials',
			'page.locked': 'Locked',
			'page.unknownPath': '(not read yet)',
			'page.securityNote': 'Note: DPAPI only protects against other OS users or an offline disk. Any process under the same user can decrypt, so this is not an isolation boundary. Use sealed or ephemeral levels for high-value credentials.',
			'action.refresh': 'Refresh',
			'action.refreshing': 'Refreshing…',
			'action.add': 'New credential',
			'action.edit': 'Edit',
			'action.delete': 'Delete',
			'action.confirmDelete': 'Confirm delete?',
			'action.confirmDeleteAria': 'Click again to delete ',
			'action.deleteAria': 'Delete ',
			'action.cancel': 'Cancel',
			'action.save': 'Save',
			'action.saving': 'Saving…',
			'action.deleting': 'Deleting…',
			'action.retry': 'Retry',
			'level.controlled': 'Controlled · L1',
			'level.sealed': 'Sealed · L2',
			'level.ephemeral': 'Ephemeral · L3',
			'level.controlled.help': 'L1 controlled: put the placeholder [[vault:<id>]] in a command and it is replaced just before execution; the value enters one child process, so use it for low-risk PATs.',
			'level.sealed.help': 'L2 sealed: the value never enters a child process; only the Host sends HTTP in-process. Allowed hosts and methods are required.',
			'level.ephemeral.help': 'L3 ephemeral: like sealed, but every use needs your confirmation in the current session; subagents cannot use it.',
			'status.expired': 'Expired',
			'item.maskedHint': 'mask only; plaintext cannot be viewed after saving',
			'item.maskedAria': 'Masked credential value',
			'meta.kind': 'Kind: ',
			'meta.auth': 'Auth: ',
			'meta.hosts': 'Hosts: ',
			'meta.methods': 'Methods: ',
			'meta.usesPrefix': 'Uses: ',
			'meta.usesSuffix': '',
			'meta.lastUsed': 'Last used: ',
			'meta.never': 'never',
			'meta.ttl': 'TTL: ',
			'meta.ttlUnit': ' min',
			'meta.commands': 'Commands: ',
			'state.loading': 'Reading the vault…',
			'state.unavailable': 'The vault cannot be read right now; use Retry above after fixing the cause.',
			'state.emptyTitle': 'No credentials yet',
			'state.emptyBody': 'Once a credential is added, the model can only use it according to its level and never read the plaintext.',
			'notice.loadFailed': 'Failed to load: ',
			'notice.deleteFailed': 'Delete failed: ',
			'notice.created': 'Credential saved',
			'notice.updated': 'Credential updated',
			'notice.deleted': 'Credential deleted',
			'error.timeout': 'The request timed out (15 s); confirm the plugin Host side is reachable and retry',
			'error.network': 'Cannot reach the plugin Host: ',
			'error.http': 'Management API returned HTTP ',
			'error.badResponse': 'The management API returned an unreadable response',
			'error.rejected': 'The request was rejected',
			'error.unknown': 'Unknown error',
			'error.id': 'ID must start with a lowercase letter or digit and contain only a-z, 0-9, ., _, - (max 64 characters)',
			'error.label': 'Name cannot be empty',
			'error.secretRequired': 'A new credential needs a value',
			'error.secretShort': 'The value must be at least 8 characters (shorter values cannot be redacted reliably)',
			'error.hostsRequired': 'Sealed / ephemeral levels need at least one allowed host',
			'error.methodsRequired': 'Select at least one HTTP method',
			'error.maxUses': 'Use limit must be 0 or a positive integer',
			'error.ttl': 'TTL must be 0 or a positive whole number of minutes',
			'error.authName': 'Enter the header / query name to inject',
			'error.authUsername': 'Enter the Basic username',
			'error.level': 'Select a privacy level',
			'error.authType': 'Select an injection method',
			'form.createTitle': 'New credential',
			'form.editTitle': 'Edit credential',
			'form.editHint': 'The value is never echoed; leave it empty to keep the current value, or enter a new value to rotate.',
			'form.policyLocked': 'Level, authentication, hosts, methods and commands are immutable after creation; delete and recreate to change them.',
			'form.preset': 'Preset',
			'form.presetHint': 'Presets fill level, auth, hosts and methods for GitHub / Cloudflare / generic cloud; policy fields stay immutable after saving.',
			'kind.token': 'token',
			'kind.api-key': 'api-key',
			'kind.password': 'password',
			'kind.cookie': 'cookie',
			'kind.cloud': 'cloud',
			'kind.other': 'other',
			'preset.custom': 'Custom',
			'preset.github-read': 'GitHub API · read-only (sealed)',
			'preset.github-manage': 'GitHub API · repo create/delete (sealed)',
			'preset.github-cli': 'GitHub CLI / git (controlled)',
			'preset.cloudflare-api': 'Cloudflare API (sealed)',
			'preset.cloudflare-wrangler': 'Cloudflare Wrangler deploy (controlled)',
			'preset.cloud-api': 'Generic Cloud API (sealed, custom hosts)',
			'form.id': 'ID',
			'form.idHint': 'Starts with a lowercase letter or digit; only a-z 0-9 . _ - (max 64); immutable after saving',
			'form.label': 'Name',
			'form.labelPlaceholder': 'e.g. GitHub read-only PAT',
			'form.level': 'Privacy level',
			'form.kind': 'Kind',
			'form.kindPlaceholder': 'e.g. token / api-key / password',
			'form.secret': 'Credential value',
			'form.secretPlaceholderCreate': 'Paste the credential value (write-only)',
			'form.secretPlaceholderEdit': 'Leave empty to keep the current value',
			'form.secretHint': 'Cannot be viewed after saving and can only be rotated; the page always shows a mask.',
			'form.auth': 'Injection method',
			'form.auth.name': 'Header / query name',
			'form.auth.namePlaceholder': 'e.g. X-Api-Key',
			'form.auth.username': 'Basic username',
			'form.authHint.bearer': 'Sent as Authorization: Bearer <value>.',
			'form.authHint.basic': 'Sends the username and value base64-encoded in the Authorization header.',
			'form.authHint.header': 'Sends the value in a custom header with the given name.',
			'form.authHint.query': 'Appends the value to the URL as a query parameter with the given name.',
			'form.hosts': 'Allowed hosts',
			'form.hostsPlaceholder': 'api.github.com, *.example.com (comma separated)',
			'form.hostsHint': 'Required for sealed / ephemeral; only these hosts are allowed.',
			'form.methods': 'Allowed HTTP methods',
			'form.commands': 'Allowed command prefixes',
			'form.commandsPlaceholder': 'git, gh, npm (comma separated)',
			'form.commandsHint': 'Checked only for controlled placeholders; empty means no restriction (not recommended).',
			'form.maxUses': 'Use limit',
			'form.maxUsesHint': '0 means unlimited',
			'form.ttl': 'TTL (minutes)',
			'form.ttlHint': '0 means no expiry',
			'form.burnAfterUse': 'Delete after the last use',
			'form.burnAfterUseHint': 'Only available for the ephemeral level.',
			'auth.bearer': 'Bearer header',
			'auth.basic': 'Basic auth',
			'auth.header': 'Custom header',
			'auth.query': 'Query parameter',
		};

		/* ------------------------------------------------------------------ *
		 * Small pure helpers.                                                 *
		 * ------------------------------------------------------------------ */
		function errorText(value) {
			if (typeof value === 'string' && value.trim() !== '') return value;
			if (value && typeof value === 'object' && typeof value.message === 'string' && value.message !== '') return value.message;
			return '';
		}

		function errorMessage(error, t) {
			if (error && typeof error.message === 'string' && error.message !== '') return error.message;
			if (typeof error === 'string' && error !== '') return error;
			return t('error.unknown');
		}

		function normalizeLevel(value) {
			const text = String(value === null || value === undefined ? '' : value).toLowerCase();
			if (text === 'sealed' || text === 'l2') return 'sealed';
			if (text === 'ephemeral' || text === 'l3') return 'ephemeral';
			return 'controlled';
		}

		function normalizeAuthType(value) {
			const text = String(value === null || value === undefined ? '' : value).toLowerCase();
			if (AUTH_TYPES.indexOf(text) !== -1) return text;
			return 'bearer';
		}

		function normalizeState(value) {
			if (!value || typeof value !== 'object') return { vault: {}, items: [] };
			const vault = value.vault && typeof value.vault === 'object' ? value.vault : {};
			const items = Array.isArray(value.items) ? value.items.filter((item) => item && typeof item === 'object') : [];
			return { vault, items };
		}

		function parseList(value) {
			const text = String(value === null || value === undefined ? '' : value);
			const seen = [];
			const parts = text.split(',');
			for (const part of parts) {
				const trimmed = part.trim();
				if (trimmed !== '' && seen.indexOf(trimmed) === -1) seen.push(trimmed);
			}
			return seen;
		}

		function toCount(value) {
			const text = String(value === null || value === undefined ? '' : value).trim();
			if (text === '') return 0;
			if (!/^\d+$/.test(text)) return null;
			const number = Number(text);
			if (!Number.isSafeInteger(number)) return null;
			return number;
		}

		function pad2(number) {
			return number < 10 ? '0' + number : String(number);
		}

		function formatTime(value) {
			if (value === null || value === undefined || value === '' || value === 0) return null;
			let date;
			if (typeof value === 'number') date = new Date(value);
			else if (typeof value === 'string') {
				const numeric = /^\d+$/.test(value) ? Number(value) : NaN;
				date = Number.isNaN(numeric) ? new Date(value) : new Date(numeric);
			} else date = new Date(value);
			if (!date || Number.isNaN(date.getTime())) return null;
			return date.getFullYear() + '-' + pad2(date.getMonth() + 1) + '-' + pad2(date.getDate()) + ' ' + pad2(date.getHours()) + ':' + pad2(date.getMinutes());
		}

		/* ------------------------------------------------------------------ *
		 * API transport: same-origin POST /vault/api, {method, params} in,    *
		 * {ok, value} or {ok:false, error} out, hard 15 s ceiling.            *
		 * ------------------------------------------------------------------ */
		function createApi(t) {
			async function request(method, params) {
				const controller = typeof AbortController === 'function' ? new AbortController() : null;
				const timer = controller !== null ? setTimeout(() => controller.abort(), CALL_TIMEOUT_MS) : null;
				try {
					const response = await fetch(ENDPOINT, {
						method: 'POST',
						credentials: 'same-origin',
						headers: {
							'content-type': 'application/json',
							'x-secret-vault-token': readUiToken(),
							'x-secret-vault-request': '1',
						},
						body: JSON.stringify({ method, params }),
						signal: controller !== null ? controller.signal : undefined,
					});
					const text = await response.text();
					return { response, text };
				} catch (error) {
					if (error && error.name === 'AbortError') throw new Error(t('error.timeout'));
					throw new Error(t('error.network') + errorMessage(error, t));
				} finally {
					if (timer !== null) clearTimeout(timer);
				}
			}

			async function call(method, params) {
				const outcome = await request(method, params);
				const response = outcome.response;
				let payload = null;
				if (outcome.text !== '') {
					try {
						payload = JSON.parse(outcome.text);
					} catch (error) {
						payload = null;
					}
				}
				if (!payload || typeof payload !== 'object') {
					throw new Error(t('error.badResponse') + ' (HTTP ' + response.status + ')');
				}
				if (payload.ok === true) return payload.value;
				const reason = errorText(payload.error);
				if (!response.ok) throw new Error(t('error.http') + response.status + ' ' + (reason || t('error.rejected')));
				throw new Error(reason || t('error.rejected'));
			}

			return {
				state: () => call('state', {}),
				save: (params) => call('save', params),
				delete: (params) => call('delete', params),
			};
		}

		/* ------------------------------------------------------------------ *
		 * Form model, validation and the save payload.                        *
		 * ------------------------------------------------------------------ */
		function blankForm() {
			return {
				preset: 'custom',
				id: '',
				label: '',
				level: 'controlled',
				kind: 'token',
				secret: '',
				authType: 'bearer',
				authName: '',
				authUsername: '',
				hosts: '',
				methods: ['GET'],
				commands: '',
				maxUses: '0',
				ttlMinutes: '0',
				burnAfterUse: false,
			};
		}

		function formFromItem(item) {
			const auth = item.auth && typeof item.auth === 'object' ? item.auth : {};
			const methods = Array.isArray(item.methods) && item.methods.length > 0
				? item.methods.map((method) => String(method).toUpperCase())
				: ['GET'];
			return {
				preset: 'custom',
				id: typeof item.id === 'string' ? item.id : '',
				label: typeof item.label === 'string' ? item.label : '',
				level: normalizeLevel(item.level),
				kind: typeof item.kind === 'string' ? item.kind : 'token',
				secret: '',
				authType: normalizeAuthType(auth.type),
				authName: typeof auth.name === 'string' ? auth.name : '',
				authUsername: typeof auth.username === 'string' ? auth.username : '',
				hosts: Array.isArray(item.hosts) ? item.hosts.map(String).join(', ') : '',
				methods,
				commands: Array.isArray(item.commands) ? item.commands.map(String).join(', ') : '',
				maxUses: typeof item.maxUses === 'number' && Number.isFinite(item.maxUses) ? String(item.maxUses) : '0',
				ttlMinutes: typeof item.ttlMinutes === 'number' && Number.isFinite(item.ttlMinutes) ? String(item.ttlMinutes) : '0',
				burnAfterUse: item.burnAfterUse === true,
			};
		}

		function validateForm(form, editing, t) {
			const id = form.id.trim();
			if (!/^[a-z0-9][a-z0-9._-]{0,63}$/.test(id)) return t('error.id');
			if (form.label.trim() === '') return t('error.label');
			if (!editing && form.secret === '') return t('error.secretRequired');
			if (form.secret !== '' && form.secret.length < 8) return t('error.secretShort');
			if (!LEVEL_BY_ID[form.level]) return t('error.level');
			if (form.level !== 'controlled' && parseList(form.hosts).length === 0) return t('error.hostsRequired');
			if (form.methods.length === 0) return t('error.methodsRequired');
			if (toCount(form.maxUses) === null) return t('error.maxUses');
			if (toCount(form.ttlMinutes) === null) return t('error.ttl');
			if (AUTH_TYPES.indexOf(form.authType) === -1) return t('error.authType');
			if (form.authType === 'header' && form.authName.trim() === '') return t('error.authName');
			if (form.authType === 'query' && form.authName.trim() === '') return t('error.authName');
			if (form.authType === 'basic' && form.authUsername.trim() === '') return t('error.authUsername');
			return null;
		}

		function buildSaveParams(form, editing) {
			const controlled = form.level === 'controlled';
			const ephemeral = form.level === 'ephemeral';
			const authName = form.authType === 'header' || form.authType === 'query' ? form.authName.trim() : '';
			const username = form.authType === 'basic' ? form.authUsername.trim() : '';
			const chosen = HTTP_METHODS.filter((method) => form.methods.indexOf(method) !== -1);
			const params = {
				id: form.id.trim(),
				label: form.label.trim(),
				level: form.level,
				kind: form.kind.trim() === '' ? 'token' : form.kind.trim(),
				auth: {
					type: form.authType,
					name: authName,
					username,
				},
				hosts: parseList(form.hosts),
				methods: chosen.length > 0 ? chosen : form.methods.slice(),
				commands: controlled ? parseList(form.commands) : [],
				maxUses: toCount(form.maxUses) === null ? 0 : toCount(form.maxUses),
				ttlMinutes: toCount(form.ttlMinutes) === null ? 0 : toCount(form.ttlMinutes),
				burnAfterUse: ephemeral ? form.burnAfterUse === true : false,
			};
			if (form.secret !== '') params.secret = form.secret;
			return params;
		}

		/* ------------------------------------------------------------------ *
		 * Presentational pieces.                                              *
		 * ------------------------------------------------------------------ */
		function LevelBadge(props) {
			const t = props.t;
			const level = normalizeLevel(props.level);
			const meta = LEVEL_BY_ID[level];
			return h('span', {
				className: 'sv-badge sv-badge--' + level,
				title: t(meta.helpKey),
			}, t(meta.badgeKey));
		}

		function VaultItem(props) {
			const t = props.t;
			const item = props.item;
			const level = normalizeLevel(item.level);
			const auth = item.auth && typeof item.auth === 'object' ? item.auth : {};
			const hosts = Array.isArray(item.hosts) ? item.hosts.map(String) : [];
			const methods = Array.isArray(item.methods) ? item.methods.map(String) : [];
			const commands = Array.isArray(item.commands) ? item.commands.map(String) : [];
			const useCount = typeof item.useCount === 'number' && Number.isFinite(item.useCount) ? item.useCount : 0;
			const maxUses = typeof item.maxUses === 'number' && Number.isFinite(item.maxUses) ? item.maxUses : 0;
			const ttlMinutes = typeof item.ttlMinutes === 'number' && Number.isFinite(item.ttlMinutes) ? item.ttlMinutes : 0;
			const masked = typeof item.masked === 'string' && item.masked !== '' ? item.masked : '••••';
			const used = formatTime(item.lastUsedAt);
			const useText = maxUses > 0 ? useCount + ' / ' + maxUses : String(useCount);
			const label = typeof item.label === 'string' && item.label !== '' ? item.label : (typeof item.id === 'string' ? item.id : '—');
			const confirming = props.pendingDelete === item.id;
			const deleting = props.deletingId === item.id;
			const metaCells = [
				h('span', { key: 'kind' }, t('meta.kind'), h('strong', null, item.kind || '—')),
				h('span', { key: 'auth' }, t('meta.auth'), h('strong', null, t('auth.' + normalizeAuthType(auth.type)))),
				h('span', { key: 'hosts' }, t('meta.hosts'), h('strong', null, hosts.length > 0 ? hosts.join(', ') : '—')),
				h('span', { key: 'methods' }, t('meta.methods'), h('strong', null, methods.length > 0 ? methods.join(' ') : '—')),
				h('span', { key: 'uses' }, t('meta.usesPrefix'), h('strong', null, useText), t('meta.usesSuffix')),
				h('span', { key: 'lastUsed' }, t('meta.lastUsed'), h('strong', null, used === null ? t('meta.never') : used)),
			];
			if (ttlMinutes > 0) {
				metaCells.push(h('span', { key: 'ttl' }, t('meta.ttl'), h('strong', null, String(ttlMinutes)), t('meta.ttlUnit')));
			}
			if (level === 'controlled' && commands.length > 0) {
				metaCells.push(h('span', { key: 'commands' }, t('meta.commands'), h('strong', null, commands.join(', '))));
			}
			const deleteButton = confirming
				? h('button', {
					type: 'button',
					className: 'sv-btn sv-btn--sm sv-btn--danger',
					disabled: deleting,
					onClick: () => props.onDelete(item.id),
					'aria-label': t('action.confirmDeleteAria') + label,
				}, deleting ? t('action.deleting') : t('action.confirmDelete'))
				: h('button', {
					type: 'button',
					className: 'sv-btn sv-btn--sm',
					disabled: deleting,
					onClick: () => props.onAskDelete(item.id),
					'aria-label': t('action.deleteAria') + label,
				}, t('action.delete'));
			return h('div', { className: 'sv-item' },
				h('div', { className: 'sv-item-head' },
					h('span', { className: 'sv-item-label' }, label),
					h(LevelBadge, { level, t }),
					item.expired === true ? h('span', { className: 'sv-badge sv-badge--expired' }, t('status.expired')) : null,
					h('span', { className: 'sv-item-id' }, typeof item.id === 'string' ? item.id : ''),
				),
				h('div', { className: 'sv-item-secret' },
					h('span', { className: 'sv-mask', 'aria-label': t('item.maskedAria') }, masked),
					h('span', { className: 'sv-hint' }, t('item.maskedHint')),
				),
				h('div', { className: 'sv-meta' }, metaCells),
				h('div', { className: 'sv-item-actions' },
					h('button', {
						type: 'button',
						className: 'sv-btn sv-btn--sm',
						onClick: () => props.onEdit(item),
					}, t('action.edit')),
					deleteButton,
				),
			);
		}

		/* ------------------------------------------------------------------ *
		 * Inline create / edit form (never a modal).                          *
		 * ------------------------------------------------------------------ */
		function VaultForm(props) {
			const t = props.t;
			const api = props.api;
			const editing = props.mode === 'edit';
			const [form, setForm] = useState(() => (editing && props.item ? formFromItem(props.item) : blankForm()));
			const [problem, setProblem] = useState(null);
			const [saving, setSaving] = useState(false);
			const alive = useRef(true);
			const firstField = useRef(null);

			useEffect(() => {
				alive.current = true;
				return () => {
					alive.current = false;
				};
			}, []);

			useEffect(() => {
				const node = firstField.current;
				if (node && typeof node.focus === 'function') node.focus();
			}, []);

			const patch = (changes) => {
				setForm((current) => Object.assign({}, current, changes));
			};

			const applyPreset = (presetId) => {
				const preset = PRESETS.find((entry) => entry.id === presetId);
				if (preset === undefined) return;
				if (preset.id === 'custom') {
					setForm((current) => Object.assign(blankForm(), { preset: 'custom', secret: current.secret }));
					return;
				}
				setForm((current) => Object.assign({}, current, {
					preset: preset.id,
					id: preset.itemId || current.id,
					label: t(preset.labelKey),
					level: preset.level,
					kind: preset.kind,
					authType: preset.authType,
					authName: '',
					authUsername: '',
					hosts: preset.hosts,
					methods: [...preset.methods],
					commands: preset.commands,
					maxUses: preset.maxUses || '0',
					ttlMinutes: preset.ttlMinutes || '0',
					burnAfterUse: false,
				}));
			};

			const toggleMethod = (method) => {
				setForm((current) => {
					const selected = current.methods.indexOf(method) !== -1;
					if (selected) return Object.assign({}, current, { methods: current.methods.filter((entry) => entry !== method) });
					return Object.assign({}, current, { methods: current.methods.concat([method]) });
				});
			};

			const submit = async (event) => {
				if (event && typeof event.preventDefault === 'function') event.preventDefault();
				if (saving) return;
				const invalid = validateForm(form, editing, t);
				if (invalid !== null) {
					setProblem(invalid);
					return;
				}
				setProblem(null);
				setSaving(true);
				try {
					await api.save(buildSaveParams(form, editing));
					if (!alive.current) return;
					setForm((current) => Object.assign({}, current, { secret: '' }));
					props.onSaved(editing ? t('notice.updated') : t('notice.created'));
				} catch (error) {
					if (!alive.current) return;
					setProblem(errorMessage(error, t));
					setSaving(false);
				}
			};

			const field = (id, labelText, control, hint, wide) => {
				const hintId = hint ? 'sv-hint-' + id : undefined;
				return h('div', { className: 'sv-field' + (wide ? ' sv-field--wide' : '') },
					h('label', { className: 'sv-label', htmlFor: 'sv-field-' + id }, labelText),
					control,
					hint ? h('span', { className: 'sv-hint', id: hintId }, hint) : null,
				);
			};

			const textInput = (id, value, onChange, extra, hintId) => h('input', Object.assign({
				id: 'sv-field-' + id,
				className: 'sv-input',
				type: 'text',
				value,
				onChange: (event) => onChange(event.target.value),
				'aria-describedby': hintId,
			}, extra));

			const authHint = t('form.authHint.' + form.authType);
			const levelMeta = LEVEL_BY_ID[form.level];
			const kindOptions = KINDS.indexOf(form.kind) === -1 ? KINDS.concat([form.kind]) : KINDS;

			return h('form', {
				className: 'sv-form',
				onSubmit: submit,
				noValidate: true,
				'aria-label': editing ? t('form.editTitle') : t('form.createTitle'),
			},
				h('div', { className: 'sv-form-head' },
					h('h3', { className: 'sv-form-title' }, editing ? t('form.editTitle') : t('form.createTitle')),
					editing ? h('p', { className: 'sv-hint sv-form-hint' }, t('form.editHint')) : null,
				),
				h('div', { className: 'sv-grid' },
					editing ? null : h('div', { className: 'sv-field sv-field--wide', key: 'preset' },
						h('label', { className: 'sv-label', htmlFor: 'sv-field-preset' }, t('form.preset')),
						h('select', {
							id: 'sv-field-preset',
							className: 'sv-select',
							value: form.preset,
							onChange: (event) => applyPreset(event.target.value),
						}, PRESETS.map((preset) => h('option', { key: preset.id, value: preset.id }, t(preset.labelKey)))),
						h('span', { className: 'sv-hint' }, t('form.presetHint')),
					),
					field('id', t('form.id'), textInput('id', form.id, (value) => patch({ id: value }), {
						readOnly: editing,
						autoComplete: 'off',
						spellCheck: false,
						placeholder: 'github-pat',
						ref: editing ? undefined : firstField,
					}, 'sv-hint-id'), t('form.idHint'), false),
					field('label', t('form.label'), textInput('label', form.label, (value) => patch({ label: value }), {
						autoComplete: 'off',
						placeholder: t('form.labelPlaceholder'),
						ref: editing ? firstField : undefined,
					}), null, false),
					h('div', { className: 'sv-field sv-field--wide', key: 'level' },
						h('span', { className: 'sv-label' }, t('form.level')),
						h('div', { className: 'sv-levels', role: 'radiogroup', 'aria-label': t('form.level') },
							LEVELS.map((level) => h('label', {
								key: level.id,
								className: 'sv-level' + (form.level === level.id ? ' sv-level--active' : ''),
							},
								h('span', { className: 'sv-level-head' },
									h('input', {
										type: 'radio',
										name: 'sv-level',
										value: level.id,
										checked: form.level === level.id,
										disabled: editing,
										onChange: () => patch({ level: level.id }),
									}),
									h('span', { className: 'sv-level-name' }, t(level.badgeKey)),
								),
								h('span', { className: 'sv-hint' }, t(level.helpKey)),
							)),
						),
						editing ? h('p', { className: 'sv-hint' }, t('form.policyLocked')) : null,
					),
					field('kind', t('form.kind'), h('select', {
						id: 'sv-field-kind',
						className: 'sv-select',
						value: form.kind,
						onChange: (event) => patch({ kind: event.target.value }),
					}, kindOptions.map((kind) => h('option', { key: kind, value: kind }, t('kind.' + kind)))), null, false),
					field('secret', t('form.secret'), h('input', {
						id: 'sv-field-secret',
						className: 'sv-input',
						type: 'password',
						autoComplete: 'new-password',
						spellCheck: false,
						value: form.secret,
						placeholder: editing ? t('form.secretPlaceholderEdit') : t('form.secretPlaceholderCreate'),
						onChange: (event) => patch({ secret: event.target.value }),
						'aria-describedby': 'sv-hint-secret',
					}), t('form.secretHint'), true),
					h('div', { className: 'sv-field sv-field--wide', key: 'auth' },
						h('label', { className: 'sv-label', htmlFor: 'sv-field-authType' }, t('form.auth')),
						h('select', {
							id: 'sv-field-authType',
							className: 'sv-select',
							value: form.authType,
							disabled: editing,
							onChange: (event) => patch({ authType: normalizeAuthType(event.target.value) }),
							'aria-describedby': 'sv-hint-auth',
						}, AUTH_TYPES.map((type) => h('option', { key: type, value: type }, t('auth.' + type)))),
						form.authType === 'header' || form.authType === 'query'
							? h('div', { className: 'sv-subgrid' },
								field('authName', t('form.auth.name'), textInput('authName', form.authName, (value) => patch({ authName: value }), {
									autoComplete: 'off',
									disabled: editing,
									placeholder: t('form.auth.namePlaceholder'),
								}), null, false),
							)
							: null,
						form.authType === 'basic'
							? h('div', { className: 'sv-subgrid' },
								field('authUsername', t('form.auth.username'), textInput('authUsername', form.authUsername, (value) => patch({ authUsername: value }), {
									autoComplete: 'off',
									disabled: editing,
								}), null, false),
							)
							: null,
						h('span', { className: 'sv-hint', id: 'sv-hint-auth' }, authHint),
					),
					field('hosts', t('form.hosts'), textInput('hosts', form.hosts, (value) => patch({ hosts: value }), {
						autoComplete: 'off',
						disabled: editing,
						placeholder: t('form.hostsPlaceholder'),
					}, 'sv-hint-hosts'), t('form.hostsHint'), true),
					h('div', { className: 'sv-field sv-field--wide', key: 'methods' },
						h('span', { className: 'sv-label' }, t('form.methods')),
						h('div', { className: 'sv-choices', role: 'group', 'aria-label': t('form.methods') },
							HTTP_METHODS.map((method) => h('label', { key: method, className: 'sv-choice' },
								h('input', {
									type: 'checkbox',
									checked: form.methods.indexOf(method) !== -1,
									disabled: editing,
									onChange: () => toggleMethod(method),
								}),
								h('span', null, method),
							)),
						),
					),
					levelMeta.id === 'controlled'
						? field('commands', t('form.commands'), textInput('commands', form.commands, (value) => patch({ commands: value }), {
							autoComplete: 'off',
							disabled: editing,
							placeholder: t('form.commandsPlaceholder'),
						}, 'sv-hint-commands'), t('form.commandsHint'), true)
						: null,
					field('maxUses', t('form.maxUses'), textInput('maxUses', form.maxUses, (value) => patch({ maxUses: value }), {
						inputMode: 'numeric',
						autoComplete: 'off',
					}, 'sv-hint-maxUses'), t('form.maxUsesHint'), false),
					field('ttlMinutes', t('form.ttl'), textInput('ttlMinutes', form.ttlMinutes, (value) => patch({ ttlMinutes: value }), {
						inputMode: 'numeric',
						autoComplete: 'off',
					}, 'sv-hint-ttlMinutes'), t('form.ttlHint'), false),
					levelMeta.id === 'ephemeral'
						? h('div', { className: 'sv-field sv-field--wide', key: 'burn' },
							h('label', { className: 'sv-choice' },
								h('input', {
									type: 'checkbox',
									checked: form.burnAfterUse,
									onChange: (event) => patch({ burnAfterUse: event.target.checked }),
								}),
								h('span', null, t('form.burnAfterUse')),
							),
							h('span', { className: 'sv-hint' }, t('form.burnAfterUseHint')),
						)
						: null,
				),
				problem !== null ? h('div', { className: 'sv-error', role: 'alert' }, problem) : null,
				h('div', { className: 'sv-form-actions' },
					h('button', {
						type: 'button',
						className: 'sv-btn',
						disabled: saving,
						onClick: props.onCancel,
					}, t('action.cancel')),
					h('button', {
						type: 'submit',
						className: 'sv-btn sv-btn--primary',
						disabled: saving,
					}, saving ? t('action.saving') : t('action.save')),
				),
			);
		}

		/* ------------------------------------------------------------------ *
		 * The settings section page.                                          *
		 * ------------------------------------------------------------------ */
		function createVaultPage(t, api) {
			function VaultPage() {
				const [data, setData] = useState(null);
				const [loading, setLoading] = useState(true);
				const [refreshing, setRefreshing] = useState(false);
				const [loadError, setLoadError] = useState(null);
				const [notice, setNotice] = useState(null);
				const [editing, setEditing] = useState(null);
				const [pendingDelete, setPendingDelete] = useState(null);
				const [deletingId, setDeletingId] = useState(null);
				const alive = useRef(true);

				useEffect(() => {
					alive.current = true;
					return () => {
						alive.current = false;
					};
				}, []);

				const load = useCallback(async () => {
					setRefreshing(true);
					setPendingDelete(null);
					try {
						const value = await api.state();
						if (!alive.current) return;
						setData(normalizeState(value));
						setLoadError(null);
					} catch (error) {
						if (!alive.current) return;
						setLoadError(errorMessage(error, t));
					} finally {
						if (alive.current) {
							setLoading(false);
							setRefreshing(false);
						}
					}
				}, []);

				useEffect(() => {
					void load();
				}, [load]);

				useEffect(() => {
					if (!notice || notice.kind !== 'ok') return undefined;
					const timer = setTimeout(() => {
						if (alive.current) setNotice(null);
					}, 6000);
					return () => clearTimeout(timer);
				}, [notice]);

				const openCreate = useCallback(() => {
					setPendingDelete(null);
					setEditing({ mode: 'create', item: null });
				}, []);

				const openEdit = useCallback((item) => {
					setPendingDelete(null);
					setEditing({ mode: 'edit', item });
				}, []);

				const closeForm = useCallback(() => {
					setEditing(null);
				}, []);

				const handleSaved = useCallback((message) => {
					setEditing(null);
					setNotice({ kind: 'ok', text: message });
					void load();
				}, [load]);

				const askDelete = useCallback((id) => {
					setPendingDelete(id);
				}, []);

				const confirmDelete = useCallback(async (id) => {
					if (deletingId !== null) return;
					setDeletingId(id);
					try {
						await api.delete({ id });
						if (!alive.current) return;
						setNotice({ kind: 'ok', text: t('notice.deleted') });
						await load();
					} catch (error) {
						if (!alive.current) return;
						setNotice({ kind: 'error', text: t('notice.deleteFailed') + errorMessage(error, t) });
					} finally {
						if (alive.current) setDeletingId(null);
					}
				}, [deletingId, load]);

				const vault = data && data.vault ? data.vault : {};
				const items = data && Array.isArray(data.items) ? data.items : [];
				const count = typeof vault.itemCount === 'number' && Number.isFinite(vault.itemCount) ? vault.itemCount : items.length;
				const vaultPath = typeof vault.path === 'string' && vault.path !== '' ? vault.path : t('page.unknownPath');
				const banner = loadError !== null
					? { kind: 'error', text: t('notice.loadFailed') + loadError, retry: true }
					: notice !== null
						? { kind: notice.kind, text: notice.text, retry: false }
						: null;
				const busy = refreshing || loading || deletingId !== null;

				const header = h('div', { className: 'sv-header' },
					h('div', { className: 'sv-heading-row' },
						h('h2', { className: 'sv-title' }, t('page.title')),
						h('div', { className: 'sv-actions' },
							h('button', {
								type: 'button',
								className: 'sv-btn',
								disabled: busy,
								'aria-busy': refreshing ? 'true' : undefined,
								onClick: () => {
									setPendingDelete(null);
									void load();
								},
							}, refreshing ? t('action.refreshing') : t('action.refresh')),
							h('button', {
								type: 'button',
								className: 'sv-btn sv-btn--primary',
								disabled: editing !== null && editing.mode === 'create',
								onClick: openCreate,
							}, t('action.add')),
						),
					),
					h('p', { className: 'sv-desc' }, t('page.desc')),
					h('div', { className: 'sv-vaultline' },
						h('span', null, t('page.pathLabel'), ' ', h('span', { className: 'sv-path' }, vaultPath)),
						h('span', null, t('page.countLabel'), ' ', h('strong', null, String(count))),
						vault.unlocked === false ? h('span', { className: 'sv-badge' }, t('page.locked')) : null,
					),
				);

				const legend = h('div', { className: 'sv-legend' },
					LEVELS.map((level) => h('div', { key: level.id, className: 'sv-legend-row' },
						h(LevelBadge, { level: level.id, t }),
						h('span', { className: 'sv-legend-text' }, t(level.helpKey)),
					)),
				);

				const bannerNode = banner === null ? null : h('div', {
					className: 'sv-notice sv-notice--' + banner.kind,
					role: banner.kind === 'error' ? 'alert' : 'status',
					'aria-live': banner.kind === 'error' ? 'assertive' : 'polite',
				},
					h('span', { className: 'sv-notice-text' }, banner.text),
					banner.retry
						? h('button', {
							type: 'button',
							className: 'sv-btn sv-btn--sm',
							disabled: refreshing,
							onClick: () => {
								void load();
							},
						}, t('action.retry'))
						: null,
				);

				const formNode = editing === null ? null : h(VaultForm, {
					key: editing.mode === 'edit' && editing.item ? 'edit:' + editing.item.id : 'create',
					mode: editing.mode,
					item: editing.item,
					t,
					api,
					onSaved: handleSaved,
					onCancel: closeForm,
				});

				let body;
				if (loading && data === null) {
					body = h('div', { className: 'sv-empty' }, h('span', null, t('state.loading')));
				} else if (data === null) {
					body = h('div', { className: 'sv-empty' }, h('span', null, t('state.unavailable')));
				} else if (items.length === 0) {
					body = h('div', { className: 'sv-empty' },
						h('span', { className: 'sv-empty-title' }, t('state.emptyTitle')),
						h('span', null, t('state.emptyBody')),
						h('button', {
							type: 'button',
							className: 'sv-btn sv-btn--primary',
							onClick: openCreate,
						}, t('action.add')),
					);
				} else {
					body = h('div', { className: 'sv-list' },
						items.map((item, index) => h(VaultItem, {
							key: typeof item.id === 'string' && item.id !== '' ? item.id : 'item-' + index,
							item,
							t,
							pendingDelete,
							deletingId,
							onEdit: openEdit,
							onAskDelete: askDelete,
							onDelete: confirmDelete,
						})),
					);
				}

				return h('div', { className: 'sv-root' },
					header,
					legend,
					bannerNode,
					formNode,
					body,
					h('p', { className: 'sv-note' }, t('page.securityNote')),
				);
			}

			return VaultPage;
		}

		return {
			inject: ['slots', 'locale'],
			apply(ctx) {
				ctx.effect(() => {
					ensureStyles();
					return () => {
						removeStyles();
					};
				}, 'secret-vault: styles');

				ctx.effect(() => ctx.locale.register('secretVault', { zh, en }), 'secret-vault: locale dictionaries');
				const t = ctx.locale.bind('secretVault');
				const api = createApi(t);
				const VaultPage = createVaultPage(t, api);

				ctx.effect(() => ctx.slots.inject('settings.section', () => ctx.slots.register({
					name: 'settings.section',
					id: 'secret-vault',
					order: 25,
					label: () => t('nav'),
				}, VaultPage)), 'secret-vault: settings page');
			},
		};
	},
});
