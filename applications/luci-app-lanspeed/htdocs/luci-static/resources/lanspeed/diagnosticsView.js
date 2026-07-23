'use strict';
'require baseclass';
'require lanspeed.rpc as lsRpc';
'require lanspeed.version as lsVersion';
'require lanspeed.diagnosticsModel as diagnosticsModel';
'require lanspeed.diagnosticsShell as diagnosticsShell';
'require lanspeed.diagnosticsRefresh as diagnosticsRefresh';

var RPC_CALLS = [
	{ key: 'diagnostics', call: function() { return lsRpc.diagnostics(); } },
	{ key: 'status', call: function() { return lsRpc.status(); } },
	{ key: 'health', call: function() { return lsRpc.health(); } },
	{ key: 'clients', call: function() { return lsRpc.clients(); } },
	{ key: 'interfaces', call: function() { return lsRpc.interfaces(); } },
	{ key: 'overview', call: function() { return lsRpc.overview(); } }
];

function loadingResource(key, requestId, previous) {
	return {
		key: key,
		phase: 'loading',
		previousPhase: previous && previous.phase || null,
		value: previous && previous.value || diagnosticsModel.emptyValue(key),
		usable: !!(previous && previous.usable),
		retained: !!(previous && previous.retained),
		fetchedAt: previous && previous.fetchedAt !== undefined ? previous.fetchedAt : null,
		producedAt: previous && previous.producedAt !== undefined ? previous.producedAt : null,
		retainedFrom: previous && previous.retainedFrom !== undefined ? previous.retainedFrom : null,
		ageMs: previous && previous.ageMs === 0 ? 0 : previous && previous.ageMs || null,
		requestId: requestId,
		error: null,
		attempt: 'loading'
	};
}

function createLoadingState(previous, requestId) {
	var state = {
		resources: {},
		rpc: {},
		errors: [],
		error: null,
		checkedAt: previous && previous.checkedAt !== undefined ? previous.checkedAt : null,
		requestId: requestId || 0,
		pageState: 'loading',
		observation: previous && previous.observation || null,
		progress: previous && previous.progress || { checked: false, stale: false, lagging: false, sources: [] }
	};
	diagnosticsModel.RPC_KEYS.forEach(function(key) {
		var prior = previous && previous.resources && previous.resources[key];
		var resource = loadingResource(key, state.requestId, prior);
		state.resources[key] = resource;
		state[key] = resource.value;
		state.rpc[key] = {
			ok: false,
			retained: resource.retained,
			phase: 'loading',
			error: null,
			requestId: state.requestId,
			fetchedAt: resource.fetchedAt,
			producedAt: resource.producedAt,
			ageMs: resource.ageMs
		};
	});
	return state;
}

function runCall(item, timeoutMs) {
	return diagnosticsModel.runCall(item, timeoutMs);
}

function loadAll(timeoutMs) {
	return Promise.all(RPC_CALLS.map(function(item) {
		return runCall(item, timeoutMs);
	}));
}

function normalizeResults(results, previous, checkedAt, requestId) {
	return diagnosticsModel.normalizeResults(results, previous, checkedAt, requestId);
}

function applyData(target, data) {
	[ 'diagnostics', 'status', 'health', 'clients', 'interfaces', 'overview',
		'resources', 'rpc', 'errors', 'error', 'checkedAt', 'requestId', 'pageState',
		'observation', 'progress' ].forEach(function(key) {
		target[key] = data[key];
	});
}

function snapshotData(state) {
	var snapshot = {};
	applyData(snapshot, state);
	return snapshot;
}

function fallbackCopy(text) {
	return new Promise(function(resolve, reject) {
		if (typeof document === 'undefined' || !document.body || !document.createElement) {
			reject(new Error(_('浏览器不支持复制诊断报告')));
			return;
		}
		var textarea = document.createElement('textarea');
		textarea.value = text;
		textarea.setAttribute('readonly', 'readonly');
		textarea.setAttribute('aria-hidden', 'true');
		textarea.style.position = 'fixed';
		textarea.style.opacity = '0';
		document.body.appendChild(textarea);
		textarea.select();
		var copied = false;
		try { copied = document.execCommand('copy'); } catch (error) {}
		document.body.removeChild(textarea);
		if (copied) resolve();
		else reject(new Error(_('浏览器拒绝复制诊断报告')));
	});
}

function copyText(text) {
	if (typeof navigator !== 'undefined' && navigator.clipboard &&
		typeof navigator.clipboard.writeText === 'function') {
		return navigator.clipboard.writeText(text).catch(function() {
			return fallbackCopy(text);
		});
	}
	return fallbackCopy(text);
}

function setCopyFeedback(refs, label, state) {
	if (!refs || !refs.btnCopy) return;
	refs.btnCopy.textContent = label;
	refs.btnCopy.setAttribute('data-state', state || 'neutral');
	if (refs.reportFeedback) {
		refs.reportFeedback.textContent = label;
		refs.reportFeedback.setAttribute('data-state', state || 'neutral');
	}
}

function resetCopyFeedback(refs) {
	if (!refs || !refs.btnCopy) return;
	refs.btnCopy.textContent = _('复制脱敏报告');
	refs.btnCopy.setAttribute('data-state', 'neutral');
	if (refs.reportFeedback) {
		refs.reportFeedback.textContent = _('报告仅包含白名单状态与计数，不复制客户端或接口身份。');
		refs.reportFeedback.setAttribute('data-state', 'neutral');
	}
}

function setRestartFeedback(refs, title, text, state) {
	if (!refs || !refs.restartFeedback) return;
	refs.restartFeedback.hidden = false;
	refs.restartFeedback.setAttribute('aria-hidden', 'false');
	refs.restartFeedback.setAttribute('data-state', state || 'loading');
	refs.restartFeedbackTitle.textContent = title;
	refs.restartFeedbackText.textContent = text;
}

function resetRestartFeedback(refs) {
	if (!refs || !refs.restartFeedback) return;
	refs.restartFeedback.hidden = true;
	refs.restartFeedback.setAttribute('aria-hidden', 'true');
	refs.restartFeedbackTitle.textContent = '';
	refs.restartFeedbackText.textContent = '';
}

function waitForRestart(viewState) {
	var delay = Math.max(0, Number(viewState.restartDelayMs) || 0);
	if (!delay) return Promise.resolve();
	return new Promise(function(resolve) {
		if (typeof window !== 'undefined' && typeof window.setTimeout === 'function')
			window.setTimeout(resolve, delay);
		else
			resolve();
	});
}

function restoreControls(viewState, requestId) {
	if (!viewState.refs || requestId !== viewState.requestId) return;
	var loading = viewState.pageState === 'loading';
	var restarting = viewState.restartPending === true;
	viewState.refs.btnRefresh.disabled = loading || restarting;
	viewState.refs.btnRefresh.textContent = _('重新检查');
	if (viewState.refs.btnRestart) {
		viewState.refs.btnRestart.disabled = loading || restarting;
		viewState.refs.btnRestart.textContent = restarting ? _('正在重启…') : _('重启服务');
	}
	if (viewState.refs.btnCopy)
		viewState.refs.btnCopy.disabled = loading || restarting || viewState.copyPending === true;
	if (viewState.refs.root)
		viewState.refs.root.setAttribute('aria-busy', loading || restarting ? 'true' : 'false');
}

function unexpectedResults(error) {
	return diagnosticsModel.RPC_KEYS.map(function(key) {
		return {
			key: key,
			ok: false,
			error: diagnosticsModel.rpcErrorInfo(error, 'client')
		};
	});
}

function scheduleInitial(viewState) {
	var start = function() {
		if (viewState.refs && viewState.refs.root) viewState.reload({ initial: true });
	};
	if (typeof window !== 'undefined' && typeof window.setTimeout === 'function')
		window.setTimeout(start, 0);
	else
		Promise.resolve().then(start);
}

return baseclass.extend({
	RPC_CALLS: RPC_CALLS,
	createLoadingState: createLoadingState,
	loadAll: loadAll,
	normalizeResults: normalizeResults,

	load: function() {
		/* LuCI renders this immediately; RPC starts only after the shell exists. */
		return createLoadingState(null, 0);
	},

	render: function(data) {
		var initial = data && data.resources ? data : createLoadingState(null, 0);
		var viewState = {
			refs: null,
			requestId: initial.requestId || 0,
			rpcTimeoutMs: diagnosticsModel.DEFAULT_RPC_TIMEOUT_MS,
			autoStart: data && data.autoStart === false ? false : true,
			copyPending: false,
			restartPending: false,
			restartPromise: null,
			restartDelayMs: 1000,

			reload: function() {
				var self = this;
				var requestId = (self.requestId || 0) + 1;
				var previous = snapshotData(self);
				var startError = null;
				applyData(self, createLoadingState(previous, requestId));
				self.requestId = requestId;
				if (self.refs) {
					resetCopyFeedback(self.refs);
					if (!self.restartPending) resetRestartFeedback(self.refs);
					self.refs.btnRefresh.disabled = true;
					self.refs.btnRefresh.textContent = _('检查中…');
					if (self.refs.btnCopy) self.refs.btnCopy.disabled = true;
					self.refs.root.setAttribute('aria-busy', 'true');
					try { diagnosticsRefresh.refresh(self); } catch (error) { startError = error; }
				}

				return (startError ? Promise.reject(startError) : Promise.resolve().then(function() {
					return loadAll(self.rpcTimeoutMs);
				})).then(function(results) {
					if (requestId !== self.requestId) return { ignored: true, requestId: requestId };
					applyData(self, normalizeResults(results, previous, Date.now(), requestId));
					diagnosticsRefresh.refresh(self);
					return { ignored: false, requestId: requestId, state: self.pageState };
				}, function(error) {
					if (requestId !== self.requestId) return { ignored: true, requestId: requestId };
					applyData(self, normalizeResults(unexpectedResults(error), previous, Date.now(), requestId));
					diagnosticsRefresh.refresh(self);
					return { ignored: false, requestId: requestId, state: self.pageState, error: error };
				}).then(function(result) {
					restoreControls(self, requestId);
					return result;
				}, function(error) {
					restoreControls(self, requestId);
					throw error;
				});
			},

			restartService: function() {
				var self = this;
				if (self.restartPromise) return self.restartPromise;
				if (self.pageState === 'loading') return Promise.resolve({ ok: false, busy: true });

				self.restartPending = true;
				if (self.refs) {
					setRestartFeedback(self.refs, _('正在重启服务'),
						_('只重启 LAN Speed 服务，完成后会自动重新运行诊断。'), 'loading');
					self.refs.btnRestart.disabled = true;
					self.refs.btnRestart.textContent = _('正在重启…');
					self.refs.btnRefresh.disabled = true;
					if (self.refs.btnCopy) self.refs.btnCopy.disabled = true;
					self.refs.root.setAttribute('aria-busy', 'true');
				}

				var operation = Promise.resolve().then(function() {
					return lsRpc.restartService();
				}).then(function(ok) {
					if (ok !== true) throw new Error('LAN Speed service restart was rejected');
					return waitForRestart(self);
				}).then(function() {
					return self.reload();
				}).then(function(result) {
					var recovered = !result || result.state !== 'error';
					setRestartFeedback(self.refs, _('服务重启完成'), recovered
						? _('诊断数据已重新检查并更新。')
						: _('服务已重启，但诊断接口暂未恢复，请稍后重新检查。'),
						recovered ? 'ready' : 'degraded');
					return { ok: true, diagnosticsReady: recovered, result: result };
				}, function() {
					setRestartFeedback(self.refs, _('服务重启失败'),
						_('请检查当前会话权限或服务日志后重试。'), 'error');
					return { ok: false };
				});

				self.restartPromise = operation.then(function(result) {
					self.restartPending = false;
					self.restartPromise = null;
					restoreControls(self, self.requestId);
					return result;
				});
				return self.restartPromise;
			},

			copyReport: function() {
				var self = this;
				if (self.copyPending) return Promise.resolve(false);
				if (self.restartPending) {
					setCopyFeedback(self.refs, _('请等待服务重启完成'), 'warning');
					return Promise.resolve(false);
				}
				if (self.pageState === 'loading') {
					setCopyFeedback(self.refs, _('请等待检查完成'), 'warning');
					return Promise.resolve(false);
				}
				var report;
				try {
					report = diagnosticsModel.buildReport(self, lsVersion.FULL_VERSION);
				} catch (error) {
					setCopyFeedback(self.refs, _('报告生成失败'), 'error');
					return Promise.resolve(false);
				}
				if (self.refs && self.refs.reportPreview)
					self.refs.reportPreview.textContent = report;
				self.copyPending = true;
				if (self.refs && self.refs.btnCopy) self.refs.btnCopy.disabled = true;
				setCopyFeedback(self.refs, _('复制中…'), 'loading');
				return copyText(report).then(function() {
					setCopyFeedback(self.refs, _('已复制'), 'success');
					return true;
				}, function(error) {
					setCopyFeedback(self.refs, _('复制失败，请手动选择报告内容'), 'error');
					return false;
				}).then(function(result) {
					self.copyPending = false;
					if (self.refs && self.refs.btnCopy) self.refs.btnCopy.disabled = self.pageState === 'loading';
					return result;
				});
			}
		};
		applyData(viewState, initial);

		var built = diagnosticsShell.buildShell(viewState);
		viewState.refs = built.refs;
		built.root.__lanspeedDiagnosticsState = viewState;
		diagnosticsRefresh.refresh(viewState);
		if (viewState.autoStart) scheduleInitial(viewState);
		return built.root;
	},

	handleSave: null,
	handleSaveApply: null,
	handleReset: null
});
