async page => {
	const configKey = 'lanspeed.browser.audit.v1';
	const startedAt = new Date().toISOString();
	const checks = [];
	const failures = [];
	const consoleMessages = [];
	const pageErrors = [];
	const responseErrors = [];
	const requestErrors = [];
	const ignoredRequestErrors = [];
	let config = null;
	let screenshotSaved = false;
	const screenshotSegments = [];
	let overviewPreferenceSnapshot = null;

	function errorText(error) {
		return String(error && (error.stack || error.message) || error);
	}

	function addCheck(name, ok, details) {
		const entry = { name: name, ok: ok === true, details: details === undefined ? null : details };
		checks.push(entry);
		if (!entry.ok) failures.push(entry);
		return entry.ok;
	}

	async function captureScreenshots() {
		if (!config || !config.screenshotPath) return;
		const positions = await page.evaluate(theme => {
			window.scrollTo(0, 0);
			const scroller = theme === 'argon' ? document.querySelector('.main-right') : null;
			if (!scroller) return [ { name: 'top', top: 0 } ];
			scroller.scrollTop = 0;
			const maximum = Math.max(0, scroller.scrollHeight - scroller.clientHeight);
			if (!maximum) return [ { name: 'top', top: 0 } ];
			return [
				{ name: 'top', top: 0 },
				{ name: 'middle', top: Math.round(maximum / 2) },
				{ name: 'bottom', top: maximum }
			];
		}, config.expectedTheme);
		for (const position of positions) {
			await page.evaluate(args => {
				window.scrollTo(0, args.name === 'top' ? 0 : window.scrollY);
				const scroller = args.theme === 'argon' ? document.querySelector('.main-right') : null;
				if (scroller) scroller.scrollTop = args.top;
			}, { theme: config.expectedTheme, name: position.name, top: position.top });
			await page.waitForTimeout(100);
			const path = position.name === 'top' ? config.screenshotPath :
				config.screenshotPath.replace(/\.png$/i, '-' + position.name + '.png');
			await page.screenshot({ path: path, fullPage: true });
			screenshotSegments.push({ name: position.name, path: path, scrollTop: position.top });
		}
		screenshotSaved = true;
		addCheck('screenshot', true, screenshotSegments);
	}

	function parseRgb(value) {
		const source = String(value || '').trim();
		const rgb = source.match(/^rgba?\((.*)\)$/i);
		const srgb = source.match(/^color\(srgb\s+(.+)\)$/i);
		let parts;
		let scale;
		if (rgb) {
			parts = rgb[1].replace(/\//g, ' ').split(/[\s,]+/).filter(Boolean);
			scale = 255;
		} else if (srgb) {
			parts = srgb[1].replace(/\//g, ' ').split(/[\s,]+/).filter(Boolean);
			scale = 1;
		} else {
			return null;
		}
		if (parts.length < 3) return null;
		function component(part, outputScale) {
			const percent = /%$/.test(part);
			const number = Number(String(part).replace(/%$/, ''));
			if (!isFinite(number)) return null;
			const normalized = percent ? number / 100 : number / scale;
			return Math.max(0, Math.min(outputScale, normalized * outputScale));
		}
		function alpha(part) {
			if (part === undefined) return 1;
			const percent = /%$/.test(part);
			const number = Number(String(part).replace(/%$/, ''));
			if (!isFinite(number)) return null;
			return Math.max(0, Math.min(1, percent ? number / 100 : number));
		}
		const parsed = {
			r: component(parts[0], 255),
			g: component(parts[1], 255),
			b: component(parts[2], 255),
			a: alpha(parts[3])
		};
		return Object.keys(parsed).every(key => parsed[key] !== null) ? parsed : null;
	}

	function colorsNear(left, right, tolerance) {
		const a = parseRgb(left);
		const b = parseRgb(right);
		if (!a || !b) return false;
		const delta = Math.max(
			Math.abs(a.r - b.r),
			Math.abs(a.g - b.g),
			Math.abs(a.b - b.b),
			Math.abs(a.a - b.a) * 255
		);
		return delta <= (tolerance || 3);
	}

	function colorChannelsNear(left, right, tolerance) {
		const a = parseRgb(left);
		const b = parseRgb(right);
		if (!a || !b) return false;
		return Math.max(
			Math.abs(a.r - b.r),
			Math.abs(a.g - b.g),
			Math.abs(a.b - b.b)
		) <= (tolerance || 3);
	}

	function compositeRgb(top, bottom) {
		const alpha = top.a + bottom.a * (1 - top.a);
		if (alpha <= 0) return { r: 255, g: 255, b: 255, a: 1 };
		return {
			r: (top.r * top.a + bottom.r * bottom.a * (1 - top.a)) / alpha,
			g: (top.g * top.a + bottom.g * bottom.a * (1 - top.a)) / alpha,
			b: (top.b * top.a + bottom.b * bottom.a * (1 - top.a)) / alpha,
			a: alpha
		};
	}

	function effectiveBackgroundColor(layers) {
		let background = { r: 255, g: 255, b: 255, a: 1 };
		layers.slice().reverse().forEach(value => {
			const parsed = parseRgb(value);
			if (parsed && parsed.a > 0) background = compositeRgb(parsed, background);
		});
		return 'rgba(' + [ background.r, background.g, background.b, background.a ].join(',') + ')';
	}

	function colorContrastRatio(foreground, background) {
		const front = parseRgb(foreground);
		const back = parseRgb(background);
		if (!front || !back) return null;
		function luminance(color) {
			function channel(value) {
				const normalized = value / 255;
				return normalized <= 0.03928 ? normalized / 12.92 :
					Math.pow((normalized + 0.055) / 1.055, 2.4);
			}
			return channel(color.r) * 0.2126 + channel(color.g) * 0.7152 +
				channel(color.b) * 0.0722;
		}
		const opaqueBack = back.a < 1 ? compositeRgb(back, { r: 255, g: 255, b: 255, a: 1 }) : back;
		const renderedFront = compositeRgb(front, opaqueBack);
		const frontLuminance = luminance(renderedFront);
		const backLuminance = luminance(opaqueBack);
		return (Math.max(frontLuminance, backLuminance) + 0.05) /
			(Math.min(frontLuminance, backLuminance) + 0.05);
	}

	function mixedColor(left, right, leftWeight) {
		const a = parseRgb(left);
		const b = parseRgb(right);
		if (!a || !b) return null;
		return 'rgba(' + [
			a.r * leftWeight + b.r * (1 - leftWeight),
			a.g * leftWeight + b.g * (1 - leftWeight),
			a.b * leftWeight + b.b * (1 - leftWeight),
			a.a * leftWeight + b.a * (1 - leftWeight)
		].join(',') + ')';
	}

	try {
		const rawConfig = await page.evaluate(key => {
			try { return window.localStorage.getItem(key); }
			catch (error) { return null; }
		}, configKey);
		if (!rawConfig) {
			addCheck('audit-config', false, 'Missing localStorage audit configuration');
			return {
				schemaVersion: 1,
				ok: false,
				startedAt: startedAt,
				finishedAt: new Date().toISOString(),
				url: page.url(),
				checks: checks,
				failures: failures
			};
		}
		config = JSON.parse(rawConfig);
		addCheck('audit-config', true, {
			page: config.pageName,
			theme: config.expectedTheme,
			mode: config.expectedMode,
			viewport: config.viewport
		});
	} catch (error) {
		addCheck('audit-config', false, errorText(error));
		return {
			schemaVersion: 1,
			ok: false,
			startedAt: startedAt,
			finishedAt: new Date().toISOString(),
			url: page.url(),
			checks: checks,
			failures: failures
		};
	}

	const onConsole = message => {
		const type = message.type();
		if (type === 'warning' || type === 'error')
			consoleMessages.push({ type: type, text: message.text() });
	};
	const onPageError = error => pageErrors.push(errorText(error));
	const onResponse = response => {
		if (response.status() >= 400 && !/favicon(?:\.ico)?(?:\?|$)/i.test(response.url())) {
			responseErrors.push({ status: response.status(), url: response.url() });
		}
	};
	const onRequestFailed = request => {
		const entry = {
			url: request.url(),
			failure: request.failure() && request.failure().errorText || 'request failed'
		};
		if (/ERR_ABORTED|NS_BINDING_ABORTED/i.test(entry.failure))
			ignoredRequestErrors.push(entry);
		else
			requestErrors.push(entry);
	};
	page.on('console', onConsole);
	page.on('pageerror', onPageError);
	page.on('response', onResponse);
	page.on('requestfailed', onRequestFailed);

	const evidence = {
		schemaVersion: 1,
		startedAt: startedAt,
		page: config.pageName,
		expected: {
			theme: config.expectedTheme,
			mode: config.expectedMode,
			accent: config.expectedAccent || null,
			viewport: config.viewport,
			urlPath: config.expectedUrlPath
		},
		checks: checks,
		failures: failures,
		observations: {},
		interactions: {},
		browserSignals: {
			console: consoleMessages,
			pageErrors: pageErrors,
				responses: responseErrors,
				requests: requestErrors,
				ignoredRequests: ignoredRequestErrors
		}
	};

	try {
		await page.emulateMedia({ colorScheme: config.expectedMode });
		await page.reload({ waitUntil: 'domcontentloaded', timeout: config.timeoutMs });
		const root = page.locator(config.rootSelector).first();
		await root.waitFor({ state: 'visible', timeout: config.timeoutMs });
			if (config.busySelector) {
				await page.waitForFunction(selector => {
					const node = document.querySelector(selector);
					return node && node.getAttribute('aria-busy') !== 'true';
				}, config.busySelector, { timeout: config.timeoutMs });
			}
			if (config.pageName === 'config') {
				/* Interface discovery is a second asynchronous contract.  The root
				 * busy flag is not authoritative while that request is in flight. */
				await page.waitForFunction(selector => {
					const node = document.querySelector(selector);
					if (!node) return false;
					if (node.querySelector('.lanspeed-page-failure')) return true;
					const status = node.querySelector('.lanspeed-ifcfg .status');
					const state = status && status.getAttribute('data-state');
					return /^(ready|degraded|empty|hard-error)$/.test(state || '');
				}, config.rootSelector, { timeout: config.timeoutMs });
			}
			await page.waitForTimeout(config.settleMs);
			if (config.pageName === 'overview') {
				overviewPreferenceSnapshot = await page.evaluate(() => {
					try { return window.localStorage.getItem('luci-app-lanspeed.prefs.v4'); }
					catch (error) { return null; }
				});
			}
		await page.evaluate(key => {
			try { window.localStorage.removeItem(key); }
			catch (error) {}
		}, configKey);

		evidence.url = page.url();
		evidence.title = await page.title();
		addCheck('url-path', page.url().indexOf(config.expectedUrlPath) !== -1, page.url());

		const themeEvidence = await root.evaluate((node, args) => {
			const computed = getComputedStyle(node);
			const requiredTokens = [
				'--lanspeed-page-bg', '--lanspeed-surface', '--lanspeed-surface-muted',
				'--lanspeed-surface-raised', '--lanspeed-text', '--lanspeed-text-muted',
				'--lanspeed-text-subtle',
				'--lanspeed-border', '--lanspeed-border-strong', '--lanspeed-accent',
				'--lanspeed-accent-soft', '--lanspeed-hover', '--lanspeed-control-bg',
				'--lanspeed-control-border', '--lanspeed-normal', '--lanspeed-warning',
				'--lanspeed-danger', '--lanspeed-focus-color', '--lanspeed-focus-ring',
				'--lanspeed-normal-soft', '--lanspeed-warning-soft', '--lanspeed-danger-soft',
				'--lanspeed-normal-border', '--lanspeed-warning-border', '--lanspeed-danger-border',
				'--lanspeed-action-bg', '--lanspeed-action-hover', '--lanspeed-action-text',
				'--lanspeed-radius-section', '--lanspeed-radius-control', '--lanspeed-radius-input',
				'--lanspeed-radius-button', '--lanspeed-radius-badge', '--lanspeed-shadow-section',
				'--lanspeed-shadow-raised', '--lanspeed-control-height', '--lanspeed-page-gap',
				'--lanspeed-section-x', '--lanspeed-section-y'
			];
			const tokens = {};
			requiredTokens.forEach(name => { tokens[name] = computed.getPropertyValue(name).trim(); });
			const probe = document.createElement('span');
			probe.setAttribute('aria-hidden', 'true');
			probe.style.cssText = 'position:absolute!important;left:-10000px!important;top:-10000px!important;';
			node.appendChild(probe);
			function resolveColor(value) {
				probe.style.color = '';
				probe.style.color = value;
				return getComputedStyle(probe).color;
			}
				const nativeTokenNames = [
					'--brand', '--surface', '--text', '--text-muted', '--hairline', '--control-bg',
					'--primary', '--dark-primary', '--gray',
					'--primary-color-high', '--background-color-high', '--text-color-high',
					'--text-color-medium', '--border-color-low', '--warn-color-high', '--error-color-high'
				];
				const nativeTokens = {};
				nativeTokenNames.forEach(name => {
					nativeTokens[name] = computed.getPropertyValue(name).trim();
				});
				const resolved = {
					accent: resolveColor('var(--lanspeed-accent)'),
					surface: resolveColor('var(--lanspeed-surface)'),
					surfaceMuted: resolveColor('var(--lanspeed-surface-muted)'),
					surfaceRaised: resolveColor('var(--lanspeed-surface-raised)'),
					text: resolveColor('var(--lanspeed-text)'),
					textMuted: resolveColor('var(--lanspeed-text-muted)'),
					textSubtle: resolveColor('var(--lanspeed-text-subtle)'),
					border: resolveColor('var(--lanspeed-border)'),
					controlBackground: resolveColor('var(--lanspeed-control-bg)'),
					controlBorder: resolveColor('var(--lanspeed-control-border)'),
					normal: resolveColor('var(--lanspeed-normal)'),
					warning: resolveColor('var(--lanspeed-warning)'),
					danger: resolveColor('var(--lanspeed-danger)'),
					focus: resolveColor('var(--lanspeed-focus-color)'),
					brand: resolveColor('var(--brand,transparent)'),
					auroraSurface: resolveColor('var(--surface,transparent)'),
					auroraText: resolveColor('var(--text,transparent)'),
					auroraTextMuted: resolveColor('var(--text-muted,transparent)'),
					auroraHairline: resolveColor('var(--hairline,transparent)'),
					auroraControlBackground: resolveColor('var(--control-bg,transparent)'),
					primary: resolveColor('var(--primary,currentColor)'),
					darkPrimary: resolveColor('var(--dark-primary,var(--primary,currentColor))'),
					argonGray: resolveColor('var(--gray,transparent)'),
					bootstrapPrimary: resolveColor('var(--primary-color-high,transparent)'),
					bootstrapSurface: resolveColor('var(--background-color-high,transparent)'),
					bootstrapText: resolveColor('var(--text-color-high,transparent)'),
					bootstrapTextMuted: resolveColor('var(--text-color-medium,transparent)'),
					bootstrapBorder: resolveColor('var(--border-color-low,transparent)'),
					bootstrapWarning: resolveColor('var(--warn-color-high,transparent)'),
					bootstrapDanger: resolveColor('var(--error-color-high,transparent)'),
					expectedAccent: args.expectedAccent && CSS.supports('color', args.expectedAccent)
						? resolveColor(args.expectedAccent) : null
				};
				probe.remove();
				function styleOf(target) {
					const element = typeof target === 'string' ? node.querySelector(target) : target;
				if (!element) return null;
				const style = getComputedStyle(element);
				return {
					tag: element.tagName.toLowerCase(),
					className: element.className || '',
					color: style.color,
					backgroundColor: style.backgroundColor,
					borderColor: style.borderColor,
					borderBottomColor: style.borderBottomColor,
					borderRadius: style.borderRadius,
					boxShadow: style.boxShadow,
					minHeight: style.minHeight,
					paddingTop: style.paddingTop,
					paddingRight: style.paddingRight,
					paddingBottom: style.paddingBottom,
					paddingLeft: style.paddingLeft,
					rowGap: style.rowGap,
					columnGap: style.columnGap,
					fontFamily: style.fontFamily,
					fontSize: style.fontSize,
					fontWeight: style.fontWeight,
					lineHeight: style.lineHeight,
					letterSpacing: style.letterSpacing
				};
			}
			return {
				className: node.className,
				themeClasses: Array.from(node.classList).filter(name => /^lanspeed-theme-/.test(name)),
				themeAttribute: node.getAttribute('data-lanspeed-theme'),
					modeAttribute: node.getAttribute('data-lanspeed-color-mode'),
					tokens: tokens,
					nativeTokens: nativeTokens,
					resolved: resolved,
					rootStyle: styleOf(node),
				sectionStyle: styleOf(':scope > .cbi-section'),
				headerStyle: styleOf(':scope > .cbi-section .lanspeed-header'),
				headingStyle: styleOf(':scope > .cbi-section .lanspeed-header h3'),
				controlStyle: styleOf('input:not([type="hidden"]),select,textarea'),
				buttonStyle: styleOf('.cbi-button,button'),
				badgeStyle: styleOf('.label')
			};
		}, { expectedAccent: config.expectedAccent || '' });
		evidence.observations.theme = themeEvidence;
		const expectedThemeClass = 'lanspeed-theme-' + config.expectedTheme;
		addCheck('theme-class', themeEvidence.themeClasses.length === 1 &&
			themeEvidence.themeClasses[0] === expectedThemeClass, themeEvidence.themeClasses);
		addCheck('theme-attribute', themeEvidence.themeAttribute === config.expectedTheme,
			themeEvidence.themeAttribute);
		addCheck('color-mode', themeEvidence.modeAttribute === config.expectedMode,
			themeEvidence.modeAttribute);
		const missingTokens = Object.keys(themeEvidence.tokens).filter(name => !themeEvidence.tokens[name]);
		addCheck('theme-tokens', missingTokens.length === 0, {
			missing: missingTokens,
			values: themeEvidence.tokens
		});
			addCheck('resolved-theme-colors', !!parseRgb(themeEvidence.resolved.accent) &&
				!!parseRgb(themeEvidence.resolved.surface) && !!parseRgb(themeEvidence.resolved.text) &&
				!!parseRgb(themeEvidence.resolved.textMuted) && !!parseRgb(themeEvidence.resolved.border) &&
				!!parseRgb(themeEvidence.resolved.textSubtle) &&
				!!parseRgb(themeEvidence.resolved.controlBackground) &&
				!!parseRgb(themeEvidence.resolved.warning) && !!parseRgb(themeEvidence.resolved.danger),
				themeEvidence.resolved);
		if (config.expectedAccent) {
			addCheck('expected-accent-valid', !!themeEvidence.resolved.expectedAccent,
				themeEvidence.resolved.expectedAccent);
			addCheck('expected-accent', colorsNear(themeEvidence.resolved.accent,
				themeEvidence.resolved.expectedAccent, 3), {
				actual: themeEvidence.resolved.accent,
				expected: themeEvidence.resolved.expectedAccent
			});
		}
			if (config.expectedTheme === 'argon') {
				const argonTarget = config.expectedMode === 'dark'
					? themeEvidence.resolved.darkPrimary : themeEvidence.resolved.primary;
				const argonNative = ['--primary', '--gray'].filter(name =>
					!themeEvidence.nativeTokens[name]);
				addCheck('argon-native-tokens', argonNative.length === 0, {
					missing: argonNative,
					values: themeEvidence.nativeTokens
				});
				addCheck('argon-native-mapping', colorsNear(themeEvidence.resolved.accent, argonTarget, 3) &&
					colorsNear(themeEvidence.resolved.textMuted, themeEvidence.resolved.text, 3) &&
					colorChannelsNear(themeEvidence.resolved.border, themeEvidence.resolved.argonGray, 3) &&
					colorChannelsNear(themeEvidence.resolved.controlBorder,
						themeEvidence.resolved.argonGray, 3), {
					actual: themeEvidence.resolved.accent,
					target: argonTarget,
					primary: themeEvidence.resolved.primary,
					darkPrimary: themeEvidence.resolved.darkPrimary,
					textMuted: themeEvidence.resolved.textMuted,
					text: themeEvidence.resolved.text,
					border: themeEvidence.resolved.border,
					controlBorder: themeEvidence.resolved.controlBorder,
					gray: themeEvidence.resolved.argonGray
				});
			}
			if (config.expectedTheme === 'aurora') {
				const requiredNative = [ '--brand', '--surface', '--text', '--text-muted', '--hairline', '--control-bg' ];
				const missingNative = requiredNative.filter(name => !themeEvidence.nativeTokens[name]);
				addCheck('aurora-native-tokens', missingNative.length === 0, {
					missing: missingNative,
					values: themeEvidence.nativeTokens
				});
				addCheck('aurora-native-mapping',
					colorsNear(themeEvidence.resolved.accent, themeEvidence.resolved.brand, 3) &&
					colorsNear(themeEvidence.resolved.surface, themeEvidence.resolved.auroraSurface, 3) &&
					colorsNear(themeEvidence.resolved.text, themeEvidence.resolved.auroraText, 3) &&
					colorsNear(themeEvidence.resolved.textMuted, themeEvidence.resolved.auroraTextMuted, 3) &&
					colorsNear(themeEvidence.resolved.border, themeEvidence.resolved.auroraHairline, 3) &&
					colorsNear(themeEvidence.resolved.controlBackground,
						themeEvidence.resolved.auroraControlBackground, 3), themeEvidence.resolved);
			}
			if (config.expectedTheme === 'bootstrap') {
				const requiredNative = [ '--primary-color-high', '--background-color-high',
					'--text-color-high', '--text-color-medium', '--border-color-low',
					'--warn-color-high', '--error-color-high' ];
				const missingNative = requiredNative.filter(name => !themeEvidence.nativeTokens[name]);
				addCheck('bootstrap-native-tokens', missingNative.length === 0, {
					missing: missingNative,
					values: themeEvidence.nativeTokens
				});
				addCheck('bootstrap-native-mapping',
					colorsNear(themeEvidence.resolved.accent, themeEvidence.resolved.bootstrapPrimary, 3) &&
					colorsNear(themeEvidence.resolved.surface, themeEvidence.resolved.bootstrapSurface, 3) &&
					colorsNear(themeEvidence.resolved.text, themeEvidence.resolved.bootstrapText, 3) &&
					colorsNear(themeEvidence.resolved.textMuted, themeEvidence.resolved.bootstrapText, 3) &&
					colorsNear(themeEvidence.resolved.textSubtle, themeEvidence.resolved.bootstrapText, 3) &&
					colorsNear(themeEvidence.resolved.border, themeEvidence.resolved.bootstrapBorder, 3) &&
					colorsNear(themeEvidence.resolved.warning,
						mixedColor(themeEvidence.resolved.bootstrapWarning, themeEvidence.resolved.bootstrapText, .35), 3) &&
					colorsNear(themeEvidence.resolved.danger,
						mixedColor(themeEvidence.resolved.bootstrapDanger, themeEvidence.resolved.bootstrapText, .55), 3),
					themeEvidence.resolved);
			}

			const styleKeys = {
				root: [ 'color', 'backgroundColor', 'fontFamily', 'fontSize', 'lineHeight',
					'rowGap', 'columnGap' ],
				section: [ 'color', 'backgroundColor', 'borderColor', 'borderRadius', 'boxShadow' ],
				header: [ 'color', 'backgroundColor', 'borderBottomColor', 'paddingTop',
					'paddingRight', 'paddingBottom', 'paddingLeft', 'rowGap', 'columnGap' ],
				heading: [ 'color', 'fontFamily', 'fontSize', 'fontWeight', 'lineHeight',
					'letterSpacing' ]
			};
			function styleSignature(style, keys) {
				if (!style) return null;
				const signature = {};
				keys.forEach(key => { signature[key] = style[key]; });
				return signature;
			}
			const shellSignature = {
				tokens: themeEvidence.tokens,
				resolved: {
					accent: themeEvidence.resolved.accent,
					surface: themeEvidence.resolved.surface,
					surfaceMuted: themeEvidence.resolved.surfaceMuted,
					surfaceRaised: themeEvidence.resolved.surfaceRaised,
					text: themeEvidence.resolved.text,
					textMuted: themeEvidence.resolved.textMuted,
					textSubtle: themeEvidence.resolved.textSubtle,
					border: themeEvidence.resolved.border,
					controlBackground: themeEvidence.resolved.controlBackground,
					controlBorder: themeEvidence.resolved.controlBorder,
					normal: themeEvidence.resolved.normal,
					warning: themeEvidence.resolved.warning,
					danger: themeEvidence.resolved.danger,
					focus: themeEvidence.resolved.focus
				},
				root: styleSignature(themeEvidence.rootStyle, styleKeys.root),
				section: styleSignature(themeEvidence.sectionStyle, styleKeys.section),
				header: styleSignature(themeEvidence.headerStyle, styleKeys.header),
				heading: styleSignature(themeEvidence.headingStyle, styleKeys.heading)
			};
			if (config.consistencyKey) {
				const consistency = await page.evaluate(args => {
					const expectedPages = [ 'overview', 'diagnostics', 'config' ];
					const result = { available: true, pages: [], missing: [], mismatches: [], records: {} };
					let records = {};
					try {
						if (args.reset) window.localStorage.removeItem(args.key);
						const raw = window.localStorage.getItem(args.key);
						if (raw) records = JSON.parse(raw);
						records[args.pageName] = args.signature;
						window.localStorage.setItem(args.key, JSON.stringify(records));
					} catch (error) {
						result.available = false;
						result.error = String(error && error.message || error);
						return result;
					}
					result.records = records;
					result.pages = Object.keys(records).sort();
					result.missing = expectedPages.filter(name => !records[name]);
					if (!args.final) return result;
					const baseline = records.overview;
					function compare(left, right, path) {
						if (left === right) return;
						if (!left || !right || typeof left !== 'object' || typeof right !== 'object') {
							result.mismatches.push({ path: path, overview: left, actual: right });
							return;
						}
						const keys = Array.from(new Set(Object.keys(left).concat(Object.keys(right)))).sort();
						keys.forEach(key => compare(left[key], right[key], path ? path + '.' + key : key));
					}
					if (baseline) {
						expectedPages.slice(1).forEach(name => {
							if (records[name]) compare(baseline, records[name], name);
						});
					}
					return result;
				}, {
					key: config.consistencyKey,
					pageName: config.pageName,
					reset: config.consistencyReset === true,
					final: config.consistencyFinal === true,
					signature: shellSignature
				});
				evidence.observations.styleConsistency = consistency;
				addCheck(config.consistencyFinal ? 'three-page-style-consistency' : 'style-signature-recorded',
					consistency.available && (!config.consistencyFinal ||
						(consistency.missing.length === 0 && consistency.mismatches.length === 0)),
					consistency);
			}

		const contentEvidence = await root.evaluate((node, expectedTexts) => {
			function visible(element) {
				const style = getComputedStyle(element);
				const rect = element.getBoundingClientRect();
				return style.display !== 'none' && style.visibility !== 'hidden' &&
					Number(style.opacity) > 0 && rect.width > 0 && rect.height > 0;
			}
			const text = node.innerText.replace(/\s+/g, ' ').trim();
			const controls = Array.from(node.querySelectorAll('button,input,select,textarea,a[href],summary'))
				.filter(visible).map(element => ({
					tag: element.tagName.toLowerCase(),
					type: element.getAttribute('type') || '',
					className: element.className || '',
					name: (element.getAttribute('aria-label') || element.innerText || element.getAttribute('placeholder') || '').trim(),
					disabled: element.disabled === true || element.getAttribute('aria-disabled') === 'true',
					value: 'value' in element ? String(element.value || '') : ''
				}));
			return {
				visibleText: text,
				visibleTextLength: text.length,
				expectedTexts: expectedTexts.map(value => ({ value: value, found: text.indexOf(value) !== -1 })),
				controls: controls,
				headings: Array.from(node.querySelectorAll('h1,h2,h3,h4')).filter(visible)
					.map(element => element.innerText.trim()).filter(Boolean),
				statusBadges: Array.from(node.querySelectorAll('.label')).filter(visible)
					.map(element => ({ text: element.innerText.trim(), className: element.className }))
			};
		}, config.expectedTexts);
		evidence.observations.content = contentEvidence;
		addCheck('visible-content', contentEvidence.visibleTextLength >= 20,
			contentEvidence.visibleTextLength);
		addCheck('expected-text', contentEvidence.expectedTexts.every(item => item.found),
			contentEvidence.expectedTexts);
		addCheck('interactive-controls', contentEvidence.controls.length >= config.minimumControls, {
			minimum: config.minimumControls,
			actual: contentEvidence.controls.length,
			controls: contentEvidence.controls
		});

		const layoutEvidence = await root.evaluate(node => {
			function visible(element) {
				const style = getComputedStyle(element);
				const rect = element.getBoundingClientRect();
				return style.display !== 'none' && style.visibility !== 'hidden' &&
					Number(style.opacity) > 0 && rect.width > 0 && rect.height > 0;
			}
			function descriptor(element) {
				return {
					tag: element.tagName.toLowerCase(),
					className: String(element.className || '').slice(0, 160),
					text: String(element.innerText || element.getAttribute('aria-label') || '').replace(/\s+/g, ' ').trim().slice(0, 100)
				};
			}
			function rectOf(element) {
				const rect = element.getBoundingClientRect();
				return { left: rect.left, top: rect.top, right: rect.right, bottom: rect.bottom,
					width: rect.width, height: rect.height };
			}
				function collect(selector, limit) {
					return Array.from(node.querySelectorAll(selector)).filter(visible).slice(0, limit || 180);
				}
				function horizontalScrollAncestor(element) {
					let current = element.parentElement;
					while (current && current !== node.parentElement) {
						const style = getComputedStyle(current);
						if (/(auto|scroll)/.test(style.overflowX) && current.scrollWidth > current.clientWidth + 1)
							return current;
						if (current === node) break;
						current = current.parentElement;
					}
					return null;
				}
			function overlaps(elements) {
				const result = [];
				for (let leftIndex = 0; leftIndex < elements.length; leftIndex++) {
					for (let rightIndex = leftIndex + 1; rightIndex < elements.length; rightIndex++) {
						const left = elements[leftIndex];
						const right = elements[rightIndex];
						if (left.contains(right) || right.contains(left)) continue;
						const a = left.getBoundingClientRect();
						const b = right.getBoundingClientRect();
						const width = Math.min(a.right, b.right) - Math.max(a.left, b.left);
						const height = Math.min(a.bottom, b.bottom) - Math.max(a.top, b.top);
						if (width > 2 && height > 2) {
							result.push({ left: descriptor(left), right: descriptor(right), width: width, height: height });
							if (result.length >= 30) return result;
						}
					}
				}
				return result;
			}
			const viewport = { width: window.innerWidth, height: window.innerHeight };
			const rootRect = rectOf(node);
			const interactive = collect('button,input:not([type="hidden"]),select,textarea,a[href],summary', 180);
			const structural = collect('.lanspeed-metric,.lanspeed-diagnostic-fact,.lanspeed-diagnostic-stage,.lanspeed-diagnostic-alert,.lanspeed-diagnostics-health-table tbody>tr,.lanspeed-diagnostics-subsystem-table tbody>tr,.lanspeed-diagnostics-rpc-table tbody>tr,.lanspeed-config-subsection,.lanspeed-config-table tbody>tr,.lanspeed-ifcfg-table tbody>tr', 240);
			const boundsTargets = collect('button,input:not([type="hidden"]),select,textarea,.label,h1,h2,h3,h4,.lanspeed-page-summary', 240);
				const outside = boundsTargets.map(element => ({
					element: element,
					rect: element.getBoundingClientRect(),
					scrollAncestor: horizontalScrollAncestor(element)
				})).filter(item => item.rect.left < -1 || item.rect.right > viewport.width + 1);
				const outOfBounds = outside.filter(item => !item.scrollAncestor).slice(0, 30)
					.map(item => ({ element: descriptor(item.element), rect: rectOf(item.element) }));
				const scrollContained = outside.filter(item => item.scrollAncestor).slice(0, 30)
					.map(item => ({
						element: descriptor(item.element),
						rect: rectOf(item.element),
						container: descriptor(item.scrollAncestor),
						containerRect: rectOf(item.scrollAncestor),
						scrollWidth: item.scrollAncestor.scrollWidth,
						clientWidth: item.scrollAncestor.clientWidth
					}));
			const clippingTargets = collect('button,.label,h1,h2,h3,h4,summary,.lanspeed-page-summary', 240);
			const clipped = clippingTargets.filter(element =>
				element.scrollWidth > element.clientWidth + 1 || element.scrollHeight > element.clientHeight + 2)
				.slice(0, 30).map(element => ({
					element: descriptor(element),
					clientWidth: element.clientWidth,
					scrollWidth: element.scrollWidth,
					clientHeight: element.clientHeight,
					scrollHeight: element.scrollHeight
				}));
			return {
				viewport: viewport,
				rootRect: rootRect,
				documentScrollWidth: document.documentElement.scrollWidth,
				bodyScrollWidth: document.body ? document.body.scrollWidth : 0,
				pageOverflowPx: Math.max(document.documentElement.scrollWidth,
					document.body ? document.body.scrollWidth : 0) - viewport.width,
					rootWithinViewport: rootRect.left >= -1 && rootRect.right <= viewport.width + 1,
					outOfBounds: outOfBounds,
					scrollContained: scrollContained,
				overlaps: overlaps(interactive).concat(overlaps(structural)).slice(0, 30),
				clipped: clipped
			};
		});
		evidence.observations.layout = layoutEvidence;
		addCheck('viewport-size', layoutEvidence.viewport.width === config.viewport.width &&
			layoutEvidence.viewport.height === config.viewport.height, layoutEvidence.viewport);
		addCheck('horizontal-overflow', layoutEvidence.pageOverflowPx <= 1, layoutEvidence);
		addCheck('root-bounds', layoutEvidence.rootWithinViewport, layoutEvidence.rootRect);
		addCheck('element-bounds', layoutEvidence.outOfBounds.length === 0, layoutEvidence.outOfBounds);
		addCheck('element-overlap', layoutEvidence.overlaps.length === 0, layoutEvidence.overlaps);
		addCheck('text-clipping', layoutEvidence.clipped.length === 0, layoutEvidence.clipped);
		if (config.viewport.name === 'mobile') {
			const overlayClearance = await root.evaluate(node => {
				function visible(element) {
					let current = element;
					while (current && current.nodeType === 1) {
						const style = getComputedStyle(current);
						if (style.display === 'none' || style.visibility === 'hidden' ||
							Number(style.opacity) === 0) return false;
						current = current.parentElement;
					}
					const rect = element.getBoundingClientRect();
					return rect.width > 0 && rect.height > 0;
				}
				function rect(element) {
					const value = element.getBoundingClientRect();
					return { left: value.left, top: value.top, right: value.right,
						bottom: value.bottom, width: value.width, height: value.height };
				}
				function label(element) {
					return String(element.getAttribute('aria-label') || element.innerText ||
						element.getAttribute('data-label') || element.className || element.tagName)
						.replace(/\s+/g, ' ').trim().slice(0, 100);
				}
				const overlays = Array.from(document.querySelectorAll('#floating-toolbar .toolbar-btn'))
					.filter(visible);
				const targets = Array.from(node.querySelectorAll(
					'input,select,button,a[href],summary>h3,.lanspeed-header>.meta,' +
					'.lanspeed-toggle-label,.lanspeed-active-label,.lanspeed-hint,.hint,.sum,th,td'))
					.filter(visible);
				const overlaps = [];
				overlays.forEach(overlay => targets.forEach(target => {
					const left = overlay.getBoundingClientRect();
					const right = target.getBoundingClientRect();
					const width = Math.min(left.right, right.right) - Math.max(left.left, right.left);
					const height = Math.min(left.bottom, right.bottom) - Math.max(left.top, right.top);
					if (width > 2 && height > 2 && overlaps.length < 30) {
						overlaps.push({ overlay: label(overlay), target: label(target),
							overlayRect: rect(overlay), targetRect: rect(target), width: width, height: height });
					}
				}));
				const rootRect = node.getBoundingClientRect();
				const reserve = overlays.length ? Math.max.apply(null, overlays.map(overlay => {
					const value = overlay.getBoundingClientRect();
					return document.documentElement.clientWidth - value.left;
				})) : 0;
				return {
					overlayCount: overlays.length,
					targetCount: targets.length,
					overlaps: overlaps,
					root: rect(node),
					reserve: reserve,
					rightClearance: document.documentElement.clientWidth - rootRect.right
				};
			});
			evidence.observations.overlayClearance = overlayClearance;
			addCheck('theme-overlay-clearance', overlayClearance.overlaps.length === 0 &&
				(overlayClearance.overlayCount === 0 ||
					overlayClearance.rightClearance >= overlayClearance.reserve - 2), overlayClearance);
		}

			const contrastEvidence = await root.evaluate(node => {
				function parseColor(value) {
					const source = String(value || '').trim();
					const rgb = source.match(/^rgba?\((.*)\)$/i);
					const srgb = source.match(/^color\(srgb\s+(.+)\)$/i);
					let parts;
					let scale;
					if (rgb) {
						parts = rgb[1].replace(/\//g, ' ').split(/[\s,]+/).filter(Boolean);
						scale = 255;
					} else if (srgb) {
						parts = srgb[1].replace(/\//g, ' ').split(/[\s,]+/).filter(Boolean);
						scale = 1;
					} else {
						return null;
					}
					if (parts.length < 3) return null;
					function component(part, outputScale) {
						const percent = /%$/.test(part);
						const number = Number(String(part).replace(/%$/, ''));
						if (!isFinite(number)) return null;
						const normalized = percent ? number / 100 : number / scale;
						return Math.max(0, Math.min(outputScale, normalized * outputScale));
					}
					function alpha(part) {
						if (part === undefined) return 1;
						const percent = /%$/.test(part);
						const number = Number(String(part).replace(/%$/, ''));
						if (!isFinite(number)) return null;
						return Math.max(0, Math.min(1, percent ? number / 100 : number));
					}
					const parsed = {
						r: component(parts[0], 255),
						g: component(parts[1], 255),
						b: component(parts[2], 255),
						a: alpha(parts[3])
					};
					return Object.keys(parsed).every(key => parsed[key] !== null) ? parsed : null;
			}
			function composite(top, bottom) {
				const alpha = top.a + bottom.a * (1 - top.a);
				if (alpha <= 0) return { r: 255, g: 255, b: 255, a: 1 };
				return {
					r: (top.r * top.a + bottom.r * bottom.a * (1 - top.a)) / alpha,
					g: (top.g * top.a + bottom.g * bottom.a * (1 - top.a)) / alpha,
					b: (top.b * top.a + bottom.b * bottom.a * (1 - top.a)) / alpha,
					a: alpha
				};
			}
			function luminance(color) {
				function channel(value) {
					const normalized = value / 255;
					return normalized <= 0.03928 ? normalized / 12.92 : Math.pow((normalized + 0.055) / 1.055, 2.4);
				}
				return channel(color.r) * 0.2126 + channel(color.g) * 0.7152 + channel(color.b) * 0.0722;
			}
			function ratio(left, right) {
				const a = luminance(left);
				const b = luminance(right);
				return (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05);
			}
			function visible(element) {
				const style = getComputedStyle(element);
				const rect = element.getBoundingClientRect();
				return style.display !== 'none' && style.visibility !== 'hidden' &&
					Number(style.opacity) > 0 && rect.width > 0 && rect.height > 0 &&
					element.getAttribute('aria-hidden') !== 'true';
			}
			function effectiveBackground(element) {
				const chain = [];
				let current = element;
				let imageLayers = 0;
				while (current && current.nodeType === 1) {
					chain.push(current);
					current = current.parentElement;
				}
				let background = { r: 255, g: 255, b: 255, a: 1 };
				chain.reverse().forEach(item => {
					const style = getComputedStyle(item);
					const parsed = parseColor(style.backgroundColor);
					if (parsed && parsed.a > 0) background = composite(parsed, background);
					if (style.backgroundImage && style.backgroundImage !== 'none') imageLayers++;
				});
				return { color: background, imageLayers: imageLayers };
			}
			function effectiveOpacity(element) {
				let opacity = 1;
				let current = element;
				while (current && current.nodeType === 1) {
					opacity *= Number(getComputedStyle(current).opacity) || 0;
					current = current.parentElement;
				}
				return opacity;
			}
			const candidates = Array.from(node.querySelectorAll('*')).filter(element => {
				if (!visible(element) || /^(script|style|noscript|option)$/i.test(element.tagName)) return false;
				if (element.disabled === true || element.getAttribute('aria-disabled') === 'true') return false;
				if (/^input$/i.test(element.tagName) &&
					/^(checkbox|radio|range|color)$/i.test(element.type || '')) return false;
				const directText = Array.from(element.childNodes).some(child =>
					child.nodeType === Node.TEXT_NODE && child.textContent.trim());
				return directText || /^(input|select|textarea)$/i.test(element.tagName);
			}).slice(0, 800);
			const violations = [];
			const samples = [];
			let skipped = 0;
			let imageLayerSamples = 0;
			candidates.forEach(element => {
				const style = getComputedStyle(element);
				const isPlaceholder = /^(input|textarea)$/i.test(element.tagName) &&
					!String(element.value || '') && !!element.getAttribute('placeholder');
				const textStyle = isPlaceholder ? getComputedStyle(element, '::placeholder') : style;
				const foreground = parseColor(textStyle.color);
				const backgroundResult = effectiveBackground(element);
				if (!foreground || !backgroundResult.color) { skipped++; return; }
				if (backgroundResult.imageLayers) imageLayerSamples++;
				const pseudoOpacity = isPlaceholder ? Number(textStyle.opacity) : 1;
				const opacity = effectiveOpacity(element) * (isFinite(pseudoOpacity) ? pseudoOpacity : 1);
				const renderedForeground = composite({
					r: foreground.r, g: foreground.g, b: foreground.b, a: foreground.a * opacity
				}, backgroundResult.color);
				const contrast = ratio(renderedForeground, backgroundResult.color);
				const fontSize = parseFloat(textStyle.fontSize) || 0;
				const numericWeight = parseInt(textStyle.fontWeight, 10);
				const weight = isFinite(numericWeight) ? numericWeight : (/bold/i.test(textStyle.fontWeight) ? 700 : 400);
				const large = fontSize >= 24 || (fontSize >= 18.66 && weight >= 700);
				const threshold = large ? 3 : 4.5;
				const text = String(element.innerText || element.value || element.getAttribute('placeholder') || '')
					.replace(/\s+/g, ' ').trim().slice(0, 120);
				const sample = {
					tag: element.tagName.toLowerCase(),
					className: String(element.className || '').slice(0, 160),
					text: text,
					ratio: Math.round(contrast * 100) / 100,
					threshold: threshold,
					fontSize: fontSize,
					fontWeight: weight,
					foreground: textStyle.color,
					opacity: opacity,
					placeholder: isPlaceholder,
					background: backgroundResult.color,
					backgroundImageLayers: backgroundResult.imageLayers
				};
				if (samples.length < 40) samples.push(sample);
				if (contrast + 0.01 < threshold && violations.length < 60) violations.push(sample);
			});
			const nonTextSamples = [];
			const nonTextViolations = [];
			Array.from(node.querySelectorAll('input[type="checkbox"]:checked,input[type="radio"]:checked'))
				.filter(element => visible(element) && !element.disabled).slice(0, 120).forEach(element => {
					const style = getComputedStyle(element);
					const accent = parseColor(style.accentColor);
					const backgroundResult = effectiveBackground(element.parentElement || element);
					if (!accent || !backgroundResult.color) return;
					const renderedAccent = composite(accent, backgroundResult.color);
					const contrast = ratio(renderedAccent, backgroundResult.color);
					const sample = {
						tag: element.tagName.toLowerCase(),
						type: element.type || '',
						className: String(element.className || '').slice(0, 160),
						label: element.getAttribute('aria-label') || '',
						ratio: Math.round(contrast * 100) / 100,
						threshold: 3,
						accentColor: style.accentColor,
						background: backgroundResult.color
					};
					nonTextSamples.push(sample);
					if (contrast + 0.01 < 3) nonTextViolations.push(sample);
				});
			return {
				tested: candidates.length - skipped,
				skipped: skipped,
				imageLayerSamples: imageLayerSamples,
				violations: violations,
				samples: samples,
				nonTextTested: nonTextSamples.length,
				nonTextViolations: nonTextViolations,
				nonTextSamples: nonTextSamples,
				thresholds: { normalText: 4.5, largeText: 3, nonTextControl: 3 }
			};
		});
		evidence.observations.contrast = contrastEvidence;
		addCheck('contrast-sample', contrastEvidence.tested >= 5, contrastEvidence);
		addCheck('wcag-contrast', contrastEvidence.violations.length === 0 &&
			contrastEvidence.nonTextViolations.length === 0, {
				text: contrastEvidence.violations,
				nonText: contrastEvidence.nonTextViolations
			});

		async function computedStyle(locator) {
			return locator.evaluate(element => {
				const style = getComputedStyle(element);
				return {
					color: style.color,
					backgroundColor: style.backgroundColor,
					backgroundImage: style.backgroundImage,
					borderColor: style.borderColor,
					boxShadow: style.boxShadow,
					outlineColor: style.outlineColor,
					outlineStyle: style.outlineStyle,
					outlineWidth: style.outlineWidth,
					transform: style.transform,
					opacity: style.opacity
				};
			});
		}
			function styleChanged(before, after) {
				return Object.keys(before).some(key => before[key] !== after[key]);
			}
			async function exerciseBusyRefresh(refresh, signatureSelector) {
				const marker = '__lanspeedBrowserAuditRefresh';
				await page.evaluate(args => {
					const previous = window[args.marker];
					if (previous && previous.observer) previous.observer.disconnect();
					const node = document.querySelector(args.rootSelector);
					if (!node) return;
					const signatureNode = args.signatureSelector
						? node.querySelector(args.signatureSelector) : null;
					const state = {
						observer: null,
						startedAt: performance.now(),
						seenTrue: node.getAttribute('aria-busy') === 'true',
						seenFalseAfterTrue: false,
						transitions: [],
						beforeSignature: signatureNode ? signatureNode.textContent.trim() : ''
					};
					function record() {
						const busy = node.getAttribute('aria-busy') === 'true';
						state.transitions.push({ busy: busy, elapsedMs: Math.round(performance.now() - state.startedAt) });
						if (busy) state.seenTrue = true;
						else if (state.seenTrue) state.seenFalseAfterTrue = true;
					}
					state.observer = new MutationObserver(record);
					state.observer.observe(node, { attributes: true, attributeFilter: [ 'aria-busy' ] });
					window[args.marker] = state;
				}, {
					marker: marker,
					rootSelector: config.rootSelector,
					signatureSelector: signatureSelector || ''
				});
				await refresh.click();
				let waitError = null;
				try {
					await page.waitForFunction(key => {
						const state = window[key];
						return state && state.seenTrue && state.seenFalseAfterTrue;
					}, marker, { timeout: config.timeoutMs });
				} catch (error) {
					waitError = errorText(error);
				}
				return page.evaluate(args => {
					const state = window[args.marker];
					const node = document.querySelector(args.rootSelector);
					const signatureNode = node && args.signatureSelector
						? node.querySelector(args.signatureSelector) : null;
					if (!state) return { seenTrue: false, seenFalseAfterTrue: false, transitions: [] };
					if (state.observer) state.observer.disconnect();
					const result = {
						seenTrue: state.seenTrue,
						seenFalseAfterTrue: state.seenFalseAfterTrue,
						transitions: state.transitions,
						beforeSignature: state.beforeSignature,
						afterSignature: signatureNode ? signatureNode.textContent.trim() : '',
						durationMs: Math.round(performance.now() - state.startedAt),
						busy: node && node.getAttribute('aria-busy')
					};
					delete window[args.marker];
					return result;
				}, {
					marker: marker,
					rootSelector: config.rootSelector,
					signatureSelector: signatureSelector || ''
				}).then(result => {
					result.waitError = waitError;
					return result;
				});
			}

		const hoverTarget = root.locator('.cbi-button:not(:disabled):visible,button:not(:disabled):visible').first();
		if (await hoverTarget.count()) {
			const before = await computedStyle(hoverTarget);
			await hoverTarget.hover();
			await page.waitForTimeout(180);
			const after = await computedStyle(hoverTarget);
			evidence.interactions.hover = { before: before, after: after };
			addCheck('hover-state', styleChanged(before, after), evidence.interactions.hover);
		} else {
			addCheck('hover-state', false, 'No enabled visible button');
		}

		const actionTarget = root.locator('.cbi-button.cbi-button-action:not(:disabled):visible').first();
		if (await actionTarget.count()) {
			await actionTarget.hover();
			await page.waitForTimeout(80);
			const actionStyle = await computedStyle(actionTarget);
			actionStyle.backgroundLayers = await actionTarget.evaluate(element => {
				const layers = [];
				let current = element;
				while (current && current.nodeType === 1) {
					layers.push(getComputedStyle(current).backgroundColor);
					current = current.parentElement;
				}
				return layers;
			});
			actionStyle.effectiveBackgroundColor = effectiveBackgroundColor(
				actionStyle.backgroundLayers);
			actionStyle.contrastRatio = colorContrastRatio(actionStyle.color,
				actionStyle.effectiveBackgroundColor);
			evidence.interactions.actionVisual = actionStyle;
			addCheck('action-visual-contrast', actionStyle.contrastRatio !== null &&
				actionStyle.contrastRatio >= 4.5 &&
				(config.expectedTheme !== 'bootstrap' || actionStyle.backgroundImage === 'none'),
				actionStyle);
		} else if (config.pageName === 'overview' || config.pageName === 'diagnostics') {
			addCheck('action-visual-contrast', false, 'Visible action button missing');
		}

		const focusTarget = root.locator('input:not([type="hidden"]):not(:disabled):visible,select:not(:disabled):visible,textarea:not(:disabled):visible,button:not(:disabled):visible,a[href]:visible').first();
		if (await focusTarget.count()) {
			const before = await computedStyle(focusTarget);
			await focusTarget.focus();
			await page.waitForTimeout(180);
			const after = await computedStyle(focusTarget);
			const active = await focusTarget.evaluate(element => document.activeElement === element);
			evidence.interactions.focus = { before: before, after: after, active: active };
			addCheck('focus-target', active, evidence.interactions.focus);
			addCheck('focus-state', active && styleChanged(before, after), evidence.interactions.focus);
		} else {
			addCheck('focus-target', false, 'No enabled visible control');
			addCheck('focus-state', false, 'No enabled visible control');
		}

			if (config.pageName === 'overview') {
				if (config.viewport.name === 'mobile') {
					const interfaceLayout = await root.locator('.lanspeed-ifaces-table:visible').first()
						.evaluate(table => {
							const body = table.closest('.lanspeed-details-body');
							const container = (body || table).getBoundingClientRect();
							const rows = Array.from(table.querySelectorAll('tbody>tr')).map(row => ({
								display: getComputedStyle(row).display,
								cells: Array.from(row.children).map(cell => {
									const rect = cell.getBoundingClientRect();
									return { label: cell.getAttribute('data-label') || '', left: rect.left,
										right: rect.right, width: rect.width };
								})
							}));
							return {
								tableClientWidth: table.clientWidth,
								tableScrollWidth: table.scrollWidth,
								container: { left: container.left, right: container.right, width: container.width },
								rows: rows
							};
						});
					evidence.observations.interfaceLayout = interfaceLayout;
					addCheck('overview-mobile-interface-layout', interfaceLayout.rows.length > 0 &&
						interfaceLayout.tableScrollWidth <= interfaceLayout.tableClientWidth + 1 &&
						interfaceLayout.rows.every(row => row.display === 'grid' && row.cells.length === 5 &&
							row.cells.every(cell => cell.label && cell.left >= interfaceLayout.container.left - 1 &&
								cell.right <= interfaceLayout.container.right + 1)), interfaceLayout);
				}
				if (config.viewport.name === 'desktop') {
					const metricCoverage = await root.locator('.lanspeed-metrics:visible').first().evaluate(node => {
						const box = node.getBoundingClientRect();
						const items = Array.from(node.querySelectorAll('.lanspeed-metric')).map(element => {
							const rect = element.getBoundingClientRect();
							return { left: rect.left, top: rect.top, right: rect.right,
								bottom: rect.bottom, width: rect.width, height: rect.height };
						});
						function spread(values) {
							return values.length ? Math.max.apply(null, values) - Math.min.apply(null, values) : null;
						}
						return {
							container: { left: box.left, right: box.right, width: box.width },
							items: items,
							leftGap: items.length ? items[0].left - box.left : null,
							rightGap: items.length ? box.right - items[items.length - 1].right : null,
							topSpread: spread(items.map(item => item.top)),
							widthSpread: spread(items.map(item => item.width))
						};
					});
					evidence.observations.metricCoverage = metricCoverage;
					addCheck('overview-wide-metric-coverage', metricCoverage.items.length === 5 &&
						metricCoverage.leftGap !== null && metricCoverage.rightGap !== null &&
						Math.abs(metricCoverage.leftGap) <= 2 && Math.abs(metricCoverage.rightGap) <= 2 &&
						metricCoverage.topSpread <= 2 && metricCoverage.widthSpread <= 2,
						metricCoverage);
					if (config.expectedTheme === 'argon') {
						const summaryDensity = await root.locator(':scope > .cbi-section').first()
							.evaluate(section => {
								const body = section.querySelector(':scope > .lanspeed-body');
								const metrics = body && body.querySelector('.lanspeed-metrics');
								const error = body && body.querySelector('.lanspeed-status-error');
								const bodyStyle = body && getComputedStyle(body);
								const bodyRect = body && body.getBoundingClientRect();
								const metricsRect = metrics && metrics.getBoundingClientRect();
								const errorVisible = !!error && getComputedStyle(error).display !== 'none' &&
									error.getBoundingClientRect().height > 0;
								return {
									sectionHeight: section.getBoundingClientRect().height,
									bodyHeight: bodyRect && bodyRect.height,
									metricsHeight: metricsRect && metricsRect.height,
									paddingTop: bodyStyle ? parseFloat(bodyStyle.paddingTop) || 0 : null,
									paddingBottom: bodyStyle ? parseFloat(bodyStyle.paddingBottom) || 0 : null,
									emptyAbove: bodyRect && metricsRect && !errorVisible ?
										metricsRect.top - bodyRect.top - (parseFloat(bodyStyle.paddingTop) || 0) : null,
									emptyBelow: bodyRect && metricsRect ? bodyRect.bottom -
										(parseFloat(bodyStyle.paddingBottom) || 0) - metricsRect.bottom : null,
									errorVisible: errorVisible
								};
							});
						evidence.observations.summaryDensity = summaryDensity;
						addCheck('argon-overview-summary-density',
							summaryDensity.metricsHeight > 0 && summaryDensity.metricsHeight <= 90 &&
							summaryDensity.emptyBelow !== null && Math.abs(summaryDensity.emptyBelow) <= 2 &&
							(summaryDensity.errorVisible ||
								(summaryDensity.emptyAbove !== null && Math.abs(summaryDensity.emptyAbove) <= 2 &&
								 summaryDensity.bodyHeight <= summaryDensity.metricsHeight +
									summaryDensity.paddingTop + summaryDensity.paddingBottom + 4)),
							summaryDensity);
					}
				}
				if (config.expectedTheme === 'bootstrap') {
					const metricAlignment = await root.locator('.lanspeed-metric:visible').evaluateAll(nodes => {
						const items = nodes.map((node, index) => {
							const box = node.getBoundingClientRect();
							const style = getComputedStyle(node);
							const bigTops = Array.from(node.querySelectorAll('.big')).map(element =>
								element.getBoundingClientRect().top);
							const hint = node.querySelector('.hint');
							return {
								index: index,
								top: box.top,
								bottom: box.bottom,
								width: box.width,
								height: box.height,
								bigCount: bigTops.length,
								bigTops: bigTops,
								hintTop: hint ? hint.getBoundingClientRect().top : null,
								borderLeftWidth: parseFloat(style.borderLeftWidth) || 0,
								boxShadow: style.boxShadow
							};
						});
						const rows = [];
						items.forEach(item => {
							const row = rows.find(candidate => Math.abs(candidate.top - item.top) <= 2);
							if (row) row.items.push(item);
							else rows.push({ top: item.top, items: [ item ] });
						});
						function spread(values) {
							const finite = values.filter(Number.isFinite);
							return finite.length ? Math.max.apply(null, finite) - Math.min.apply(null, finite) : 0;
						}
						const measuredRows = rows.filter(row => row.items.length > 1).map(row => ({
							count: row.items.length,
							topSpread: spread(row.items.map(item => item.top)),
							bottomSpread: spread(row.items.map(item => item.bottom)),
							widthSpread: spread(row.items.map(item => item.width)),
							heightSpread: spread(row.items.map(item => item.height)),
							bigTopSpread: spread(row.items.map(item => item.bigTops[0])),
							hintTopSpread: spread(row.items.map(item => item.hintTop))
						}));
						return { items: items, rows: measuredRows };
					});
					evidence.observations.metricAlignment = metricAlignment;
					addCheck('bootstrap-overview-metric-alignment', metricAlignment.items.length === 5 &&
						metricAlignment.items.every(item => item.bigCount === 1 &&
							item.borderLeftWidth <= 1.5 && item.boxShadow === 'none') &&
						metricAlignment.rows.length > 0 && metricAlignment.rows.every(row =>
							row.topSpread <= 1.5 && row.bottomSpread <= 1.5 &&
							row.widthSpread <= 1.5 && row.heightSpread <= 1.5 && row.bigTopSpread <= 1.5 &&
							row.hintTopSpread <= 1.5), metricAlignment);
				}
			const refresh = root.locator('.lanspeed-status-refresh:visible').first();
				addCheck('overview-refresh-control', await refresh.count() === 1, null);
				if (await refresh.count()) {
					evidence.interactions.refresh = await exerciseBusyRefresh(refresh, '.lanspeed-header .meta');
					Object.assign(evidence.interactions.refresh, {
						disabled: await refresh.isDisabled(),
						label: (await refresh.innerText()).trim()
					});
					addCheck('overview-refresh', evidence.interactions.refresh.seenTrue &&
						evidence.interactions.refresh.seenFalseAfterTrue &&
						!evidence.interactions.refresh.disabled,
						evidence.interactions.refresh);
				}
			const filter = root.locator('input[type="search"]:visible').first();
			addCheck('overview-filter-control', await filter.count() === 1, null);
			if (await filter.count()) {
				const original = await filter.inputValue();
				await filter.fill('__lanspeed_browser_audit_no_match__');
				await page.waitForTimeout(80);
				const emptyVisible = await root.locator('.lanspeed-empty:visible').count() > 0;
				await filter.fill(original);
				evidence.interactions.filter = { emptyVisible: emptyVisible, restored: await filter.inputValue() === original };
				addCheck('overview-filter', emptyVisible && evidence.interactions.filter.restored,
					evidence.interactions.filter);
			}
			const pause = root.getByRole('button', { name: /^(暂停|恢复)$/ }).first();
			if (await pause.count()) {
				const initial = (await pause.innerText()).trim();
				await pause.click();
				const toggled = (await pause.innerText()).trim();
				await pause.click();
				const restored = (await pause.innerText()).trim();
				evidence.interactions.pause = { initial: initial, toggled: toggled, restored: restored };
				addCheck('overview-pause', initial !== toggled && initial === restored,
					evidence.interactions.pause);
				} else {
					addCheck('overview-pause', false, 'Pause control missing');
				}
				const sort = root.locator('.lanspeed-sort-button:visible').first();
				if (await sort.count()) {
					const header = sort.locator('xpath=..');
					const before = await header.getAttribute('aria-sort');
					await sort.click();
					const after = await header.getAttribute('aria-sort');
					evidence.interactions.sort = { before: before, after: after };
					addCheck('overview-sort', before !== after && /^(none|ascending|descending)$/.test(after || ''),
						evidence.interactions.sort);
				} else {
					addCheck('overview-sort', false, 'Sort control missing');
				}
			const next = root.locator('.lanspeed-page-button[aria-label="下一页"]:visible').first();
			if (await next.count() && !(await next.isDisabled())) {
				const summary = root.locator('.lanspeed-page-summary').first();
				const before = (await summary.innerText()).trim();
				await next.click();
				const after = (await summary.innerText()).trim();
				const first = root.locator('.lanspeed-page-button[aria-label="第一页"]:visible').first();
				if (await first.count()) await first.click();
				evidence.interactions.pagination = { exercised: true, before: before, after: after };
				addCheck('overview-pagination', before !== after, evidence.interactions.pagination);
				} else {
					evidence.interactions.pagination = { exercised: false, reason: 'single page or no clients' };
					addCheck('overview-pagination', true, evidence.interactions.pagination);
				}
				const detailLinks = await root.locator('.lanspeed-connection-link:visible').evaluateAll(links =>
					links.map(link => ({
						href: link.getAttribute('href') || '',
						label: link.getAttribute('aria-label') || link.textContent.trim()
					})));
				evidence.interactions.clientDetails = { links: detailLinks.slice(0, 20) };
				addCheck('overview-client-details', detailLinks.length === 0 || detailLinks.every(link =>
					/[?&]client=/.test(link.href) && link.label),
					evidence.interactions.clientDetails);
			const state = await root.getAttribute('data-state');
			const collectorBadges = await root.locator('.lanspeed-collector-status').allInnerTexts();
			const serviceCount = await root.locator('.lanspeed-service-status').count();
			const freshnessCount = await root.locator('.lanspeed-freshness-status').count();
			const headerText = await root.locator('.lanspeed-header').first().innerText();
			evidence.observations.status = {
				state: state,
				collectorBadges: collectorBadges,
				serviceCount: serviceCount,
				freshnessCount: freshnessCount,
				headerText: headerText
			};
			addCheck('overview-collector-badge', collectorBadges.length === 1 &&
				collectorBadges[0].trim().length > 0, evidence.observations.status);
			addCheck('overview-service-badge-removed', serviceCount === 0, evidence.observations.status);
			addCheck('overview-freshness-badge-removed', freshnessCount === 0, evidence.observations.status);
			const removedHeaderText = [ '服务已响应', '刚刚更新', '检查于' ];
			addCheck('overview-obsolete-header-text-removed', removedHeaderText.every(text =>
				headerText.indexOf(text) === -1),
				evidence.observations.status);
			addCheck('overview-status-contract', /^(good|warning|bad)$/.test(state || '') &&
				collectorBadges.length === 1 && collectorBadges[0].trim().length > 0 &&
				serviceCount === 0 && freshnessCount === 0 &&
				removedHeaderText.every(text => headerText.indexOf(text) === -1),
				evidence.observations.status);
			const activeFilter = root.locator(
				'.lanspeed-active-only>input[type="checkbox"]:visible').first();
			if (await activeFilter.count()) {
				const activeFilterGeometry = await activeFilter.evaluate(element => {
					const rect = element.getBoundingClientRect();
					const label = element.closest('.lanspeed-active-only');
					const caption = label && label.querySelector('.lanspeed-active-label');
					const captionRect = caption ? caption.getBoundingClientRect() : null;
					const style = getComputedStyle(element);
					return {
						id: element.id || '', width: rect.width, height: rect.height,
						centerDelta: captionRect ?
							(rect.y + rect.height / 2) - (captionRect.y + captionRect.height / 2) : null,
						position: style.position, top: style.top, right: style.right,
						outline: style.outline
					};
				});
				evidence.observations.activeFilterGeometry = activeFilterGeometry;
				addCheck('overview-checkbox-alignment', activeFilterGeometry.width >= 10 &&
					activeFilterGeometry.width <= 24 && activeFilterGeometry.height >= 10 &&
					activeFilterGeometry.height <= 24 &&
					(activeFilterGeometry.centerDelta === null ||
						Math.abs(activeFilterGeometry.centerDelta) <= 2), activeFilterGeometry);
				const wasChecked = await activeFilter.isChecked();
				await activeFilter.click();
				await page.waitForTimeout(80);
				const pointerFocus = await activeFilter.evaluate(element => {
					const style = getComputedStyle(element);
					return {
						active: document.activeElement === element,
						focusVisible: element.matches(':focus-visible'),
						outlineStyle: style.outlineStyle,
						outlineWidth: style.outlineWidth
					};
				});
				if ((await activeFilter.isChecked()) !== wasChecked)
					await activeFilter.click();
				evidence.interactions.activeFilterPointerFocus = pointerFocus;
				addCheck('overview-checkbox-pointer-focus', pointerFocus.active &&
					!pointerFocus.focusVisible && (pointerFocus.outlineStyle === 'none' ||
						parseFloat(pointerFocus.outlineWidth) === 0), pointerFocus);
			} else {
				addCheck('overview-checkbox-alignment', false, 'Active-client checkbox missing');
				addCheck('overview-checkbox-pointer-focus', false, 'Active-client checkbox missing');
			}
			if (!config.allowBadState)
				addCheck('overview-no-hard-failure', state !== 'bad', evidence.observations.status);
		}

			if (config.pageName === 'diagnostics') {
				const refresh = root.locator('.lanspeed-diagnostics-refresh:visible').first();
				addCheck('diagnostics-refresh-control', await refresh.count() === 1, null);
				if (await refresh.count()) {
					evidence.interactions.refresh = await exerciseBusyRefresh(refresh,
						'.lanspeed-diagnostics-checked');
					await refresh.waitFor({ state: 'visible', timeout: config.timeoutMs });
					Object.assign(evidence.interactions.refresh, {
						disabled: await refresh.isDisabled(),
						label: (await refresh.innerText()).trim()
					});
					addCheck('diagnostics-refresh', evidence.interactions.refresh.seenTrue &&
						evidence.interactions.refresh.seenFalseAfterTrue &&
						!evidence.interactions.refresh.disabled,
						evidence.interactions.refresh);
				}

				const copy = root.locator('.lanspeed-diagnostics-copy:visible').first();
				addCheck('diagnostics-copy-control', await copy.count() === 1, null);
				if (await copy.count()) {
					const origin = await page.evaluate(() => window.location.origin);
					try {
						await page.context().grantPermissions([ 'clipboard-read', 'clipboard-write' ], { origin: origin });
					} catch (error) {}
					const captureSetup = await page.evaluate(() => {
						const marker = '__lanspeedBrowserAuditClipboard';
						const state = {
							text: '', method: '', installed: false,
							navigatorDescriptor: Object.getOwnPropertyDescriptor(navigator, 'clipboard'),
							originalExecCommand: document.execCommand
						};
						const capture = function(value) {
							state.text = String(value || '');
							return Promise.resolve();
						};
						try {
							Object.defineProperty(navigator, 'clipboard', {
								configurable: true, value: { writeText: capture }
							});
							state.method = 'clipboard.writeText';
							state.installed = navigator.clipboard && navigator.clipboard.writeText === capture;
						} catch (error) {}
						if (!state.installed) {
							try {
								document.execCommand = function(command) {
									if (String(command).toLowerCase() === 'copy') {
										const active = document.activeElement;
										state.text = active && typeof active.value === 'string'
											? active.value.slice(active.selectionStart || 0,
												active.selectionEnd === null ? active.value.length : active.selectionEnd)
											: String(window.getSelection && window.getSelection() || '');
										return true;
									}
									return state.originalExecCommand
										? state.originalExecCommand.apply(document, arguments) : false;
								};
								state.method = 'document.execCommand';
								state.installed = true;
							} catch (error) {}
						}
						window[marker] = state;
						return { installed: state.installed, method: state.method };
					});
					await copy.click();
					await page.waitForFunction(selector => {
						const element = document.querySelector(selector);
						return element && /^(success|error)$/.test(element.getAttribute('data-state') || '');
					}, '.lanspeed-diagnostics-report-feedback', { timeout: config.timeoutMs });
					const feedbackNode = root.locator('.lanspeed-diagnostics-report-feedback').first();
					const feedback = (await feedbackNode.innerText()).trim();
					const feedbackState = await feedbackNode.getAttribute('data-state');
					const reportEvidence = await page.evaluate(() => {
						const marker = '__lanspeedBrowserAuditClipboard';
						const state = window[marker] || {};
						const text = String(state.text || '');
						const requiredFields = [ 'LAN Speed', 'RPC 检查', '采集质量', '数据新鲜度',
							'数据路径', '连接健康', '版本一致性', '接口健康', '隐私说明' ];
						const sensitivePatterns = [];
						if (/\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b/i.test(text) ||
							/\b(?:[0-9a-f]{4}\.){2}[0-9a-f]{4}\b/i.test(text))
							sensitivePatterns.push('mac-address');
						if (/\b(?:\d{1,3}\.){3}\d{1,3}\b/.test(text))
							sensitivePatterns.push('ipv4-address');
						if (/(?:^|[^0-9a-f:])(?:(?:[0-9a-f]{1,4}:){3,}[0-9a-f:]{0,4}|[0-9a-f]{0,4}::[0-9a-f:.%]*)(?:$|[^0-9a-f:])/i.test(text))
							sensitivePatterns.push('ipv6-address');
						if (/\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b/i.test(text))
							sensitivePatterns.push('hostname');
						if (/\b(?:host(?:name)?|client(?:[_-]?(?:name|id|identity|ip|mac|host))?|identity(?:[_-]?(?:key|name|id))?|ip(?:v4|v6)?|mac)\b\s*[:=]\s*(?!\[(?:REDACTED|IP|MAC|HOST|IDENTITY)\])/i.test(text))
							sensitivePatterns.push('sensitive-assignment');
						try {
							if (state.navigatorDescriptor)
								Object.defineProperty(navigator, 'clipboard', state.navigatorDescriptor);
							else
								delete navigator.clipboard;
						} catch (error) {}
						try { document.execCommand = state.originalExecCommand; } catch (error) {}
						delete window[marker];
						return {
							captured: text.length > 0,
							reportLength: text.length,
							firstLine: (text.split(/\r?\n/)[0] || '').slice(0, 120),
							missingFields: requiredFields.filter(field => text.indexOf(field) === -1),
							sensitivePatterns: sensitivePatterns
						};
					});
					evidence.interactions.copy = Object.assign({
						feedback: feedback, feedbackState: feedbackState
					}, captureSetup, reportEvidence);
					addCheck('diagnostics-copy', feedbackState === 'success' && feedback === '已复制' &&
						reportEvidence.captured && reportEvidence.missingFields.length === 0 &&
						reportEvidence.sensitivePatterns.length === 0, evidence.interactions.copy);
				}

				const diagnosticsContract = await root.evaluate(node => {
					function rows(selector) {
						return Array.from(node.querySelectorAll(selector)).map(element => ({
							state: element.getAttribute('data-state') || '',
							cells: Array.from(element.querySelectorAll('th,td')).map(cell =>
								cell.innerText.replace(/\s+/g, ' ').trim()),
							text: element.innerText.replace(/\s+/g, ' ').trim()
						}));
					}
					const sections = Array.from(node.children).filter(element =>
						element.matches && element.matches('.cbi-section')).map(element => ({
						classes: Array.from(element.classList),
						heading: (element.querySelector(':scope > .lanspeed-header h3') || {}).textContent || ''
					}));
					const facts = Array.from(node.querySelectorAll('.lanspeed-diagnostic-fact')).map(element => ({
						state: element.getAttribute('data-state') || '',
						label: (element.querySelector('.lanspeed-diagnostic-fact-label') || {}).textContent || '',
						value: (element.querySelector('.lanspeed-diagnostic-fact-value') || {}).textContent || '',
						meta: (element.querySelector('.lanspeed-diagnostic-fact-meta') || {}).textContent || ''
					}));
					const stages = Array.from(node.querySelectorAll('.lanspeed-diagnostic-stage')).map(element => ({
						state: element.getAttribute('data-state') || '',
						heading: (element.querySelector('h4') || {}).textContent || '',
						badge: (element.querySelector('.lanspeed-diagnostic-stage-badge') || {}).textContent || '',
						value: (element.querySelector('.lanspeed-diagnostic-stage-value') || {}).textContent || '',
						description: (element.querySelector('.lanspeed-diagnostic-stage-description') || {}).textContent || ''
					}));
					const rpcRows = rows('.lanspeed-diagnostics-rpc-table tbody>tr');
					const errorDetails = node.querySelector('.lanspeed-diagnostics-error-details');
					const errors = Array.from(node.querySelectorAll('.lanspeed-diagnostics-error-list>li')).map(element => ({
						state: element.getAttribute('data-state') || '',
						text: element.innerText.replace(/\s+/g, ' ').trim()
					}));
					const importantAlerts = Array.from(node.querySelectorAll('.lanspeed-diagnostic-important-alerts>li'));
					const environmentAlerts = Array.from(node.querySelectorAll('.lanspeed-diagnostic-environment-alerts>li'));
					const report = node.querySelector('.lanspeed-diagnostics-report-preview');
					const summary = node.querySelector('.lanspeed-diagnostics-summary');
					return {
						pageState: node.getAttribute('data-page-state') || '',
						busy: node.getAttribute('aria-busy'),
						summary: summary ? summary.textContent.trim() : '',
						checked: (node.querySelector('.lanspeed-diagnostics-checked') || {}).textContent || '',
						sections: sections,
						facts: facts,
						stages: stages,
						rpcRows: rpcRows,
						interfaceRows: rows('.lanspeed-diagnostics-health-table tbody>tr'),
						subsystemRows: rows('.lanspeed-diagnostics-subsystem-table tbody>tr'),
						errorHidden: !errorDetails || errorDetails.hidden || errorDetails.getAttribute('aria-hidden') === 'true',
						errors: errors,
						importantAlerts: importantAlerts.map(element => ({
							severity: element.getAttribute('data-severity') || '', text: element.innerText.trim()
						})),
						environmentAlerts: environmentAlerts.map(element => ({
							severity: element.getAttribute('data-severity') || '', text: element.innerText.trim()
						})),
						reportLength: report ? report.textContent.length : 0,
						reportFields: report ? [ 'LAN Speed', 'RPC 检查', '采集质量', '数据新鲜度',
							'数据路径', '连接健康', '版本一致性', '接口健康', '隐私说明' ].map(field => ({
								field: field, found: report.textContent.indexOf(field) !== -1
							})) : [],
						nestedSections: node.querySelectorAll('.cbi-section .cbi-section').length,
						legacyPanels: node.querySelectorAll('.lanspeed-diagnostic-card,.lanspeed-diagnostic-panel,.lanspeed-diagnostic-check').length
					};
				});
				evidence.observations.status = diagnosticsContract;
				const expectedSections = [
					'lanspeed-diagnostics-summary-section', 'lanspeed-diagnostics-pipeline-section',
					'lanspeed-diagnostics-health-section', 'lanspeed-diagnostics-support-section'
				];
				const allowedItemState = /^(good|warning|bad|neutral)$/;
				const allowedRowState = /^(good|warning|bad|empty|neutral)$/;
				const allowedErrorState = /^(stale|degraded|error|invalid)$/;
				const allowedPageState = /^(ready|degraded|partial|empty|error)$/;
				const invalidRpcRows = diagnosticsContract.rpcRows.filter(row =>
					!/^(good|warning|bad)$/.test(row.state) || row.cells.length !== 4 ||
					row.cells.some(cell => !cell));
				const rpcFailures = diagnosticsContract.rpcRows.filter(row => row.state === 'bad').length;
				const rpcErrors = diagnosticsContract.rpcRows.filter(row =>
					row.cells[3] && row.cells[3] !== '已返回数据').length;
				const disabledSubsystems = diagnosticsContract.subsystemRows.filter(row =>
					row.cells[1] === '未启用');
				const disabledNss = disabledSubsystems.filter(row => row.cells[0] === 'NSS');
				const disabledNoCollect = disabledSubsystems.filter(row =>
					row.cells[2] === '没有 LAN 接口设为“采集”，客户端实时测速不会启动。');
				const invalidDisabledStates = disabledSubsystems.filter(row =>
					disabledNoCollect.indexOf(row) !== -1 ? row.state !== 'bad' : row.state !== 'neutral');
				const unknownSubsystemCodes = diagnosticsContract.subsystemRows.filter(row =>
					row.cells[2] && row.cells[2].indexOf('未识别的诊断代码') !== -1);
				addCheck('diagnostics-four-section-shell', diagnosticsContract.sections.length === 4 &&
					expectedSections.every(className => diagnosticsContract.sections.some(section =>
						section.classes.indexOf(className) !== -1 && section.heading.trim())) &&
					diagnosticsContract.nestedSections === 0 && diagnosticsContract.legacyPanels === 0,
					diagnosticsContract.sections);
				addCheck('diagnostics-summary-contract', allowedPageState.test(diagnosticsContract.pageState) &&
					diagnosticsContract.busy === 'false' && diagnosticsContract.summary.trim() &&
					diagnosticsContract.checked.trim() && diagnosticsContract.facts.length === 4 &&
					diagnosticsContract.facts.every(item => allowedItemState.test(item.state) &&
						item.label.trim() && item.value.trim()), diagnosticsContract);
				addCheck('diagnostics-pipeline-contract', diagnosticsContract.stages.length === 4 &&
					diagnosticsContract.stages.every(item => allowedItemState.test(item.state) &&
						item.heading.trim() && item.badge.trim() && item.value.trim() && item.description.trim()),
					diagnosticsContract.stages);
				addCheck('diagnostics-six-rpc-contract', diagnosticsContract.rpcRows.length === 6 &&
					invalidRpcRows.length === 0 && diagnosticsContract.errors.length === rpcErrors &&
					diagnosticsContract.errors.every(item => allowedErrorState.test(item.state) && item.text) &&
					(diagnosticsContract.errorHidden === (diagnosticsContract.errors.length === 0)),
					{ rpcRows: diagnosticsContract.rpcRows, errors: diagnosticsContract.errors,
						invalidRpcRows: invalidRpcRows });
				addCheck('diagnostics-health-contract', diagnosticsContract.interfaceRows.length > 0 &&
					diagnosticsContract.subsystemRows.length > 0 &&
					diagnosticsContract.interfaceRows.concat(diagnosticsContract.subsystemRows).every(row =>
						allowedRowState.test(row.state) && row.text), {
						interfaces: diagnosticsContract.interfaceRows,
						subsystems: diagnosticsContract.subsystemRows
					});
				addCheck('diagnostics-subsystem-code-contract', unknownSubsystemCodes.length === 0 &&
					invalidDisabledStates.length === 0 &&
					disabledNss.every(row => row.cells[2] === '当前设备未检测到 NSS，该组件不适用。'), {
						disabled: disabledSubsystems,
						disabledNoCollect: disabledNoCollect,
						invalidDisabledStates: invalidDisabledStates,
						disabledNss: disabledNss,
						unknown: unknownSubsystemCodes
					});
				addCheck('diagnostics-alert-report-contract', diagnosticsContract.importantAlerts.length > 0 &&
					diagnosticsContract.environmentAlerts.length > 0 &&
					diagnosticsContract.importantAlerts.concat(diagnosticsContract.environmentAlerts).every(item =>
						/^(critical|warning|info)$/.test(item.severity) && item.text) &&
					diagnosticsContract.reportLength >= 100 && diagnosticsContract.reportFields.length === 9 &&
					diagnosticsContract.reportFields.every(item => item.found), diagnosticsContract);
				if (!config.allowBadState)
					addCheck('diagnostics-no-hard-failure', diagnosticsContract.pageState !== 'error' &&
						rpcFailures === 0, diagnosticsContract);
			}

			if (config.pageName === 'config') {
				const configContract = await root.evaluate(node => {
					const topSections = Array.from(node.children).filter(element =>
						element.matches && element.matches('.cbi-section'));
					const subsections = Array.from(node.querySelectorAll(
						':scope > .lanspeed-config-page-section > .lanspeed-config-page-body > .lanspeed-config-subsection'));
					const groups = Array.from(node.querySelectorAll('.lanspeed-ifcfg-seg')).map(element => ({
						name: element.getAttribute('data-name') || '',
						buttons: Array.from(element.querySelectorAll('button')).map(button => ({
							mode: button.getAttribute('data-mode') || '',
							checked: button.getAttribute('aria-checked') || '',
							disabled: button.disabled,
							active: button.classList.contains('active')
						}))
					}));
					const interfaceStatus = node.querySelector('.lanspeed-ifcfg .status');
					const interfaceHint = node.querySelector('.lanspeed-ifcfg .lanspeed-hint');
					const pageState = node.querySelector('.lanspeed-config-page-state');
					const failure = node.querySelector('.lanspeed-page-failure');
					const compatibility = node.querySelector('.lanspeed-compatibility');
					return {
						pageState: node.getAttribute('data-state') || '',
						busy: node.getAttribute('aria-busy'),
						pageStateText: pageState ? pageState.textContent.trim() : '',
						failureVisible: !!failure && !failure.hidden,
						failureRole: failure ? failure.getAttribute('role') : null,
						topSections: topSections.map(element => Array.from(element.classList)),
						nestedSections: node.querySelectorAll('.cbi-section .cbi-section').length,
						subsections: subsections.map(element => ({
							classes: Array.from(element.classList),
							heading: (element.querySelector(':scope > .lanspeed-config-subheader h4') || {}).textContent || ''
						})),
							fieldNames: Array.from(node.querySelectorAll('.lanspeed-config-table tbody>tr[data-field]'))
								.map(element => element.getAttribute('data-field')),
							compatibilityVisible: !!compatibility,
							compatibilityTerms: compatibility ? compatibility.querySelectorAll('dt').length : 0,
						compatibilityValues: compatibility ? compatibility.querySelectorAll('dd').length : 0,
						interfaceRows: node.querySelectorAll('.lanspeed-ifcfg-table tbody>tr').length,
						interfaceStatus: interfaceStatus ? interfaceStatus.getAttribute('data-state') || '' : '',
						interfaceStatusText: interfaceStatus ? interfaceStatus.textContent.trim() : '',
						interfaceHint: interfaceHint ? interfaceHint.getAttribute('data-state') || '' : '',
						checkboxes: Array.from(node.querySelectorAll(
							'.lanspeed-config-table input[type="checkbox"]')).map(element => {
							const rect = element.getBoundingClientRect();
							const style = getComputedStyle(element);
							const label = element.closest('.lanspeed-toggle');
							const caption = label && label.querySelector('.lanspeed-toggle-label');
							const captionRect = caption ? caption.getBoundingClientRect() : null;
							return {
								id: element.id || '',
								disabled: element.disabled,
								width: rect.width,
								height: rect.height,
								computedWidth: style.width,
								computedHeight: style.height,
								appearance: style.appearance,
								centerDelta: captionRect ?
									(rect.y + rect.height / 2) - (captionRect.y + captionRect.height / 2) : null
							};
						}),
						groups: groups,
						retryButtons: failure ? failure.querySelectorAll('button').length : 0
					};
				});
				evidence.observations.status = configContract;
				const terminalConfigState = /^(ready|empty|degraded|hard-error)$/;
				addCheck('config-state-contract', terminalConfigState.test(configContract.pageState) &&
					configContract.busy !== 'true', configContract);

				if (configContract.failureVisible) {
					addCheck('config-hard-error-contract', configContract.pageState === 'hard-error' &&
						configContract.failureRole === 'alert' && configContract.topSections.length === 1 &&
						configContract.nestedSections === 0 && configContract.retryButtons === 1,
						configContract);
					const hardErrorActionRoot = page.locator('.cbi-page-actions').first();
					const hardErrorActionContract = await hardErrorActionRoot.count()
						? await hardErrorActionRoot.evaluate(actions => {
							const buttons = Array.from(actions.querySelectorAll('.cbi-button,button'));
							return {
								state: actions.getAttribute('data-lanspeed-state') || '',
								hidden: actions.hidden || getComputedStyle(actions).display === 'none',
								ariaHidden: actions.getAttribute('aria-hidden'),
								buttons: buttons.map(button => ({
									disabled: button.disabled,
									ariaDisabled: button.getAttribute('aria-disabled')
								}))
							};
						}) : { state: '', hidden: false, ariaHidden: null, buttons: [] };
					evidence.observations.hardErrorNativeActions = hardErrorActionContract;
					addCheck('config-hard-error-native-actions',
						hardErrorActionContract.state === 'hard-error' &&
						hardErrorActionContract.hidden && hardErrorActionContract.ariaHidden === 'true' &&
						hardErrorActionContract.buttons.length >= 3 &&
						hardErrorActionContract.buttons.every(button =>
							button.disabled && button.ariaDisabled === 'true'), hardErrorActionContract);
					if (!config.allowBadState)
						addCheck('config-no-hard-failure', false, configContract);
				} else {
					const requiredSubsections = [ 'lanspeed-config-runtime-section', 'lanspeed-ifcfg' ];
					const uniqueFields = Array.from(new Set(configContract.fieldNames));
					const invalidGroups = configContract.groups.filter(group => {
						const modes = group.buttons.map(button => button.mode).sort().join(',');
						const selected = group.buttons.filter(button => button.checked === 'true' && button.active);
						return !group.name || group.buttons.length !== 3 || modes !== 'collect,observe,off' ||
							selected.length !== 1 || group.buttons.some(button =>
								(button.mode === 'off' || button.mode === 'observe') && button.disabled);
					});
					const invalidCheckboxes = configContract.checkboxes.filter(item =>
						!Number.isFinite(item.width) || !Number.isFinite(item.height) ||
						item.width < 10 || item.height < 10 || item.width > 24 || item.height > 24 ||
						Math.abs(item.width - item.height) > 4 ||
						(item.centerDelta !== null && Math.abs(item.centerDelta) > 2));
					addCheck('config-single-section-shell', configContract.topSections.length === 1 &&
						configContract.topSections[0].indexOf('lanspeed-config-page-section') !== -1 &&
						configContract.nestedSections === 0 && configContract.subsections.length === 2 &&
						requiredSubsections.every(className => configContract.subsections.some(section =>
							section.classes.indexOf(className) !== -1 && section.heading.trim())), configContract);
						addCheck('config-fields-contract', configContract.fieldNames.length === 13 &&
							uniqueFields.length === 13 && !configContract.compatibilityVisible &&
							configContract.compatibilityTerms === 0 && configContract.compatibilityValues === 0,
							configContract);
					addCheck('config-interface-mode-contract', configContract.groups.length ===
						configContract.interfaceRows && invalidGroups.length === 0 &&
						(configContract.groups.length > 0 || configContract.interfaceHint === 'empty' ||
							configContract.interfaceStatus === 'hard-error'), {
						groups: configContract.groups,
						invalidGroups: invalidGroups,
						interfaceStatus: configContract.interfaceStatus,
						interfaceHint: configContract.interfaceHint
					});
					addCheck('config-checkbox-native-size', configContract.checkboxes.length >= 5 &&
						invalidCheckboxes.length === 0, {
						checkboxes: configContract.checkboxes,
						invalid: invalidCheckboxes
					});
					const checkboxFocusTarget = root.locator(
						'.lanspeed-config-table input[type="checkbox"]:not(:disabled)').first();
					if (await checkboxFocusTarget.count()) {
						await page.keyboard.press('Tab');
						await checkboxFocusTarget.focus();
						await page.waitForTimeout(80);
						const checkboxFocus = await checkboxFocusTarget.evaluate(element => {
							const rect = element.getBoundingClientRect();
							const style = getComputedStyle(element);
							const marker = getComputedStyle(element, '::before');
							return {
								active: document.activeElement === element,
								focusVisible: element.matches(':focus-visible'),
								width: rect.width,
								height: rect.height,
								outlineStyle: style.outlineStyle,
								outlineWidth: style.outlineWidth,
								outlineColor: style.outlineColor,
								markerBoxShadow: marker.boxShadow
							};
						});
						evidence.interactions.checkboxFocus = checkboxFocus;
						addCheck('config-checkbox-keyboard-focus', checkboxFocus.active &&
							checkboxFocus.focusVisible && checkboxFocus.width >= 10 &&
							checkboxFocus.height >= 10 && checkboxFocus.width <= 24 &&
							checkboxFocus.height <= 24 &&
							(checkboxFocus.outlineStyle !== 'none' || checkboxFocus.markerBoxShadow !== 'none'),
							checkboxFocus);
					} else {
						addCheck('config-checkbox-keyboard-focus', false,
							'Enabled configuration checkbox missing');
					}
					if (!config.allowBadState)
						addCheck('config-no-hard-failure', configContract.pageState !== 'hard-error' &&
							configContract.interfaceStatus !== 'hard-error', configContract);

					const saveActions = page.locator(
						'.cbi-page-actions .cbi-button-save, .cbi-page-actions .cbi-button-apply');
					const resetActions = page.locator('.cbi-page-actions .cbi-button-reset');
					addCheck('config-native-actions', await saveActions.count() >= 2 &&
						await resetActions.count() >= 1, {
							saveApply: await saveActions.count(), reset: await resetActions.count()
						});
					const nativeActionTheme = await page.locator('.cbi-page-actions').first().evaluate(actions => {
						const save = actions.querySelector('.cbi-button-save');
						const reset = actions.querySelector('.cbi-button-reset');
						const root = document.querySelector('.lanspeed-config-root');
						const style = save && getComputedStyle(save);
						const resetStyle = reset && getComputedStyle(reset);
						const rootStyle = root && getComputedStyle(root);
						const resetBackgroundLayers = [];
						for (let node = reset; node; node = node.parentElement)
							resetBackgroundLayers.push(getComputedStyle(node).backgroundColor);
						return {
							theme: actions.getAttribute('data-lanspeed-theme') || '',
							mode: actions.getAttribute('data-lanspeed-color-mode') || '',
							background: style && style.backgroundColor || '',
							border: style && style.borderColor || '',
							resetColor: resetStyle && resetStyle.color || '',
							resetBackground: resetStyle && resetStyle.backgroundColor || '',
							resetBackgroundLayers: resetBackgroundLayers,
							resetBorder: resetStyle && resetStyle.borderColor || '',
							accent: rootStyle &&
								(rootStyle.getPropertyValue('--lanspeed-filled-action-safe').trim() ||
								 rootStyle.getPropertyValue('--lanspeed-accent-safe').trim()) || '',
							danger: rootStyle && rootStyle.getPropertyValue('--lanspeed-danger-safe').trim() || ''
						};
					});
					evidence.observations.nativeActionTheme = nativeActionTheme;
					addCheck('config-native-action-theme',
						nativeActionTheme.theme === config.expectedTheme &&
						nativeActionTheme.mode === config.expectedMode &&
						(config.expectedTheme !== 'argon' ||
							(colorChannelsNear(nativeActionTheme.background, nativeActionTheme.accent, 3) &&
								 colorChannelsNear(nativeActionTheme.border, nativeActionTheme.accent, 3))),
						nativeActionTheme);
					if (config.expectedTheme === 'argon') {
						const resetEffectiveBackground = effectiveBackgroundColor(
							nativeActionTheme.resetBackgroundLayers || []);
						const resetContrast = colorContrastRatio(nativeActionTheme.resetColor,
							resetEffectiveBackground);
						nativeActionTheme.resetEffectiveBackground = resetEffectiveBackground;
						nativeActionTheme.resetContrast = resetContrast;
						addCheck('config-native-reset-semantic',
							colorChannelsNear(nativeActionTheme.resetColor, nativeActionTheme.danger, 3) &&
							colorChannelsNear(nativeActionTheme.resetBorder, nativeActionTheme.danger, 3) &&
							!colorChannelsNear(nativeActionTheme.resetColor, nativeActionTheme.accent, 3) &&
							resetContrast !== null && resetContrast >= 4.5,
							nativeActionTheme);
					}

					const scan = root.locator('.lanspeed-ifcfg-actions button[aria-label="重新扫描网络接口"]:visible').first();
					if (await scan.count() && !(await scan.isDisabled())) {
						const scanMarker = '__lanspeedBrowserAuditScan';
						await page.evaluate(args => {
							const target = document.querySelector(args.selector);
							const state = { seenLoading: false, terminal: '', transitions: [] };
							function record() {
								const value = target && target.getAttribute('data-state') || '';
								state.transitions.push(value);
								if (value === 'loading') state.seenLoading = true;
								if (/^(ready|degraded|empty|hard-error)$/.test(value)) state.terminal = value;
							}
							state.observer = new MutationObserver(record);
							if (target) state.observer.observe(target, { attributes: true, attributeFilter: [ 'data-state' ] });
							window[args.marker] = state;
						}, { marker: scanMarker, selector: '.lanspeed-config-root .lanspeed-ifcfg' });
						await scan.click();
						await page.waitForFunction(marker => {
							const state = window[marker];
							return state && state.seenLoading && state.terminal;
						}, scanMarker, { timeout: config.timeoutMs });
						await page.waitForFunction(selector => {
							const button = document.querySelector(selector);
							return button && !button.disabled;
						}, '.lanspeed-config-root .lanspeed-ifcfg-actions button[aria-label="重新扫描网络接口"]',
						{ timeout: config.timeoutMs });
						evidence.interactions.scan = await page.evaluate(marker => {
							const state = window[marker] || { seenLoading: false, terminal: '', transitions: [] };
							if (state.observer) state.observer.disconnect();
							const result = { seenLoading: state.seenLoading, terminal: state.terminal,
								transitions: state.transitions };
							delete window[marker];
							return result;
						}, scanMarker);
						evidence.interactions.scan.disabledAfter = await scan.isDisabled();
						addCheck('config-interface-rescan', evidence.interactions.scan.seenLoading &&
							/^(ready|degraded|empty|hard-error)$/.test(evidence.interactions.scan.terminal) &&
							!evidence.interactions.scan.disabledAfter, evidence.interactions.scan);
					} else {
						addCheck('config-interface-rescan', false, 'Enabled interface rescan control missing');
					}

					const showIpv6 = root.locator('#lanspeed-config-show-ipv6').first();
					const hidePrivate = root.locator('#lanspeed-config-hide-private-ipv6').first();
					const rangeInput = root.locator('#lanspeed-config-hide-ipv6-ranges').first();
					const addRange = root.locator('button[aria-label="添加 IPv6 范围"]').first();
					if (await showIpv6.count() && await hidePrivate.count() &&
						await rangeInput.count() && await addRange.count()) {
						const originalShow = await showIpv6.isChecked();
						const originalPrivate = await hidePrivate.isChecked();
						const toggleByLabel = async (input, id, checked) => {
							if (await input.isChecked() === checked) return;
							const label = root.locator('label[for="' + id + '"]').first();
							await label.scrollIntoViewIfNeeded();
							await label.click();
							await page.waitForFunction(args => {
								const node = document.getElementById(args.id);
								return node && node.checked === args.checked;
							}, { id: id, checked: checked }, { timeout: config.timeoutMs });
						};
						await toggleByLabel(showIpv6, 'lanspeed-config-show-ipv6', false);
						const hiddenState = {
							hidePrivateDisabled: await hidePrivate.isDisabled(),
							rangeDisabled: await rangeInput.isDisabled(),
							addDisabled: await addRange.isDisabled()
						};
						await toggleByLabel(showIpv6, 'lanspeed-config-show-ipv6', true);
						await toggleByLabel(hidePrivate, 'lanspeed-config-hide-private-ipv6', false);
						const privateOffState = {
							hidePrivateDisabled: await hidePrivate.isDisabled(),
							rangeDisabled: await rangeInput.isDisabled(),
							addDisabled: await addRange.isDisabled()
						};
						await toggleByLabel(hidePrivate, 'lanspeed-config-hide-private-ipv6', true);
						const enabledState = {
							rangeDisabled: await rangeInput.isDisabled(),
							addDisabled: await addRange.isDisabled()
						};
						await toggleByLabel(hidePrivate, 'lanspeed-config-hide-private-ipv6', originalPrivate);
						await toggleByLabel(showIpv6, 'lanspeed-config-show-ipv6', originalShow);
						evidence.interactions.dependencies = {
							hiddenState: hiddenState, privateOffState: privateOffState,
							enabledState: enabledState, restored: {
								showIpv6: await showIpv6.isChecked(), hidePrivate: await hidePrivate.isChecked()
							}
						};
						addCheck('config-field-dependencies', hiddenState.hidePrivateDisabled &&
							hiddenState.rangeDisabled && hiddenState.addDisabled &&
							!privateOffState.hidePrivateDisabled && privateOffState.rangeDisabled &&
							privateOffState.addDisabled && !enabledState.rangeDisabled &&
							!enabledState.addDisabled &&
							evidence.interactions.dependencies.restored.showIpv6 === originalShow &&
							evidence.interactions.dependencies.restored.hidePrivate === originalPrivate,
							evidence.interactions.dependencies);
					} else {
						addCheck('config-field-dependencies', false, 'IPv6 dependency controls missing');
					}

					const interval = root.locator('#lanspeed-config-refresh-interval-ms').first();
					if (await interval.count()) {
						const original = await interval.inputValue();
						await interval.fill('500.5');
						await page.waitForFunction(selector => {
							const input = document.querySelector(selector);
							return input && input.getAttribute('aria-invalid') === 'true' &&
								input.closest('[data-field]').getAttribute('data-state') === 'invalid';
						}, '#lanspeed-config-refresh-interval-ms', { timeout: config.timeoutMs });
						const invalidState = {
							ariaInvalid: await interval.getAttribute('aria-invalid'),
							saveState: await root.locator('.lanspeed-config-save-state').getAttribute('data-state'),
							actions: await saveActions.evaluateAll(buttons => buttons.map(button => button.disabled))
						};
						await interval.fill(original);
						await page.waitForFunction(selector => {
							const input = document.querySelector(selector);
							return input && input.getAttribute('aria-invalid') !== 'true' &&
								input.closest('[data-field]').getAttribute('data-state') === 'valid';
						}, '#lanspeed-config-refresh-interval-ms', { timeout: config.timeoutMs });
						evidence.interactions.validation = {
							invalid: invalidState,
							restored: await interval.inputValue() === original,
							actionsAfterRestore: await saveActions.evaluateAll(buttons =>
								buttons.map(button => button.disabled))
						};
						addCheck('config-validation', invalidState.ariaInvalid === 'true' &&
							invalidState.saveState === 'invalid' && invalidState.actions.length >= 2 &&
							invalidState.actions.every(Boolean) && evidence.interactions.validation.restored &&
							(configContract.pageState === 'degraded' ||
								evidence.interactions.validation.actionsAfterRestore.every(disabled => !disabled)),
							evidence.interactions.validation);
					} else {
						addCheck('config-validation', false, 'Refresh interval control missing');
					}

					const modeGroups = root.locator('.lanspeed-ifcfg-seg');
					if (await modeGroups.count()) {
						let nonOff = root.locator('.lanspeed-ifcfg-seg button[aria-checked="true"]:not([data-mode="off"])');
						if (!(await nonOff.count())) {
							const firstObserve = root.locator('.lanspeed-ifcfg-seg button[data-mode="observe"]:not(:disabled)').first();
							if (await firstObserve.count()) await firstObserve.click();
						}
						for (let index = 0; index < await modeGroups.count(); index++) {
							nonOff = root.locator('.lanspeed-ifcfg-seg button[aria-checked="true"]:not([data-mode="off"])');
							if (!(await nonOff.count())) break;
							const group = nonOff.first().locator('xpath=..');
							await group.locator('button[data-mode="off"]').click();
						}
						const allOff = await modeGroups.evaluateAll(groups => groups.every(group => {
							const selected = group.querySelectorAll('button[aria-checked="true"]');
							return selected.length === 1 && selected[0].getAttribute('data-mode') === 'off';
						}));
						const scanDisabled = await scan.count() ? await scan.isDisabled() : false;
						evidence.interactions.interfaceModes = {
							groups: await modeGroups.count(), allOff: allOff, scanDisabled: scanDisabled
						};
						addCheck('config-all-off-mode', allOff && scanDisabled,
							evidence.interactions.interfaceModes);
					} else {
						evidence.interactions.interfaceModes = { skipped: true, reason: 'no interfaces' };
						addCheck('config-all-off-mode', configContract.interfaceHint === 'empty' ||
							configContract.interfaceStatus === 'hard-error', evidence.interactions.interfaceModes);
					}

					await page.reload({ waitUntil: 'domcontentloaded', timeout: config.timeoutMs });
					await root.waitFor({ state: 'visible', timeout: config.timeoutMs });
					await page.waitForFunction(selector => {
						const node = document.querySelector(selector);
						if (!node) return false;
						if (node.querySelector('.lanspeed-page-failure')) return true;
						const status = node.querySelector('.lanspeed-ifcfg .status');
						return status && /^(ready|degraded|empty|hard-error)$/.test(
							status.getAttribute('data-state') || '');
					}, config.rootSelector, { timeout: config.timeoutMs });
					await page.waitForTimeout(config.settleMs);
					evidence.interactions.restored = {
						pageState: await root.getAttribute('data-state'),
						busy: await root.getAttribute('aria-busy')
					};
					addCheck('config-interaction-reset', terminalConfigState.test(
						evidence.interactions.restored.pageState || '') &&
						evidence.interactions.restored.busy !== 'true', evidence.interactions.restored);
				}
			}

		await captureScreenshots();
	} catch (error) {
		addCheck('audit-execution', false, errorText(error));
		if (config && config.screenshotPath) {
			try {
				await captureScreenshots();
			} catch (screenshotError) {
				addCheck('screenshot', false, errorText(screenshotError));
			}
		}
		} finally {
			page.off('console', onConsole);
			page.off('pageerror', onPageError);
			page.off('response', onResponse);
			page.off('requestfailed', onRequestFailed);
			if (config && config.pageName === 'overview') {
				try {
					await page.evaluate(snapshot => {
						if (snapshot === null)
							window.localStorage.removeItem('luci-app-lanspeed.prefs.v4');
						else
							window.localStorage.setItem('luci-app-lanspeed.prefs.v4', snapshot);
					}, overviewPreferenceSnapshot);
				} catch (error) {}
			}
		try {
			await page.evaluate(key => window.localStorage.removeItem(key), configKey);
		} catch (error) {}
	}

	addCheck('page-errors', pageErrors.length === 0, pageErrors);
	addCheck('failed-responses', responseErrors.length === 0, responseErrors);
	addCheck('failed-requests', requestErrors.length === 0, requestErrors);
	const consoleErrors = consoleMessages.filter(message => message.type === 'error');
	addCheck('console-errors', consoleErrors.length === 0, consoleErrors);
	evidence.screenshot = config.screenshotPath || null;
	evidence.screenshotSegments = screenshotSegments;
	evidence.screenshotSaved = screenshotSaved;
	evidence.finishedAt = new Date().toISOString();
	evidence.ok = failures.length === 0;
	return evidence;
}
