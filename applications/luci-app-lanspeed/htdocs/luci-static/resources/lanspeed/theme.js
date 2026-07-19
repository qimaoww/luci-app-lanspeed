'use strict';
'require baseclass';

var AURORA_CLASS = 'lanspeed-theme-aurora';
var AURORA_META = 'LuCI Aurora';
var ARGON_CLASS = 'lanspeed-theme-argon';
var BOOTSTRAP_CLASS = 'lanspeed-theme-bootstrap';
var COLOR_MODE_CLEANUP = '__lanspeedColorModeCleanup';
var AURORA_CONTRAST_PROPERTIES = [
	'--lanspeed-accent-safe',
	'--lanspeed-action-text-safe',
	'--lanspeed-action-hover-text-safe',
	'--lanspeed-normal-text-safe',
	'--lanspeed-focus-color-safe',
	'--lanspeed-warning-safe',
	'--lanspeed-danger-safe',
	'--lanspeed-info-safe'
];
var ARGON_CONTRAST_PROPERTIES = [
	'--lanspeed-accent-safe',
	'--lanspeed-action-text-safe',
	'--lanspeed-link-safe',
	'--lanspeed-normal-text-safe',
	'--lanspeed-switch-accent-safe',
	'--lanspeed-filled-action-safe',
	'--lanspeed-filled-action-text-safe',
	'--lanspeed-focus-color-safe',
	'--lanspeed-warning-safe',
	'--lanspeed-danger-safe',
	'--lanspeed-info-safe'
];

function docOrGlobal(doc) {
	if (doc)
		return doc;
	if (typeof document !== 'undefined')
		return document;
	return null;
}

function colorLuminance(value) {
	var match = String(value || '').trim().match(
		/^rgba?\(\s*([\d.]+)(?:\s*,\s*|\s+)([\d.]+)(?:\s*,\s*|\s+)([\d.]+)(?:\s*(?:,|\/)\s*([\d.]+)(%)?)?\s*\)$/i
	);
	if (!match)
		return null;
	var red = Number(match[1]);
	var green = Number(match[2]);
	var blue = Number(match[3]);
	var alpha = match[4] === undefined ? 1 : Number(match[4]);
	if (match[5] === '%')
		alpha /= 100;
	if (![ red, green, blue, alpha ].every(function(channel) { return isFinite(channel); }) || alpha <= .01)
		return null;
	return (red * 299 + green * 587 + blue * 114) / 1000;
}

function clamp(value, minimum, maximum) {
	return Math.max(minimum, Math.min(maximum, value));
}

function parseCssColor(value) {
	var source = String(value || '').trim();
	var hex = source.match(/^#([\da-f]{3,8})$/i);
	if (hex) {
		var digits = hex[1];
		if (digits.length === 3 || digits.length === 4)
			digits = digits.split('').map(function(part) { return part + part; }).join('');
		if (digits.length === 6)
			digits += 'ff';
		if (digits.length === 8) {
			return {
				r: parseInt(digits.slice(0, 2), 16),
				g: parseInt(digits.slice(2, 4), 16),
				b: parseInt(digits.slice(4, 6), 16),
				a: parseInt(digits.slice(6, 8), 16) / 255
			};
		}
	}
	if (source.toLowerCase() === 'transparent')
		return { r: 0, g: 0, b: 0, a: 0 };
	var rgb = source.match(/^rgba?\(\s*(.*?)\s*\)$/i);
	var srgb = source.match(/^color\(\s*srgb\s+(.*?)\s*\)$/i);
	var parts;
	var scale;
	if (rgb) {
		parts = rgb[1].replace(/\//g, ' ').split(/[\s,]+/).filter(Boolean);
		scale = 255;
	} else if (srgb) {
		parts = srgb[1].replace(/\//g, ' ').split(/[\s,]+/).filter(Boolean);
		scale = 1;
	} else {
		return null;
	}
	if (parts.length < 3)
		return null;
	function channel(part, outputScale) {
		var percent = /%$/.test(part);
		var number = Number(String(part).replace(/%$/, ''));
		if (!isFinite(number))
			return null;
		return clamp((percent ? number / 100 : number / scale) * outputScale, 0, outputScale);
	}
	function alpha(part) {
		if (part === undefined)
			return 1;
		var percent = /%$/.test(part);
		var number = Number(String(part).replace(/%$/, ''));
		if (!isFinite(number))
			return null;
		return clamp(percent ? number / 100 : number, 0, 1);
	}
	var parsed = {
		r: channel(parts[0], 255),
		g: channel(parts[1], 255),
		b: channel(parts[2], 255),
		a: alpha(parts[3])
	};
	return [ parsed.r, parsed.g, parsed.b, parsed.a ].every(function(part) {
		return part !== null && isFinite(part);
	}) ? parsed : null;
}

/* CSSOM may preserve OKLCH/color-mix syntax; let the browser rasterize it. */
function rasterizeCssColor(doc, value) {
	try {
		var canvas = doc && doc.createElement && doc.createElement('canvas');
		var context = canvas && canvas.getContext && canvas.getContext('2d');
		if (!context)
			return null;
		canvas.width = 1;
		canvas.height = 1;
		context.clearRect(0, 0, 1, 1);
		context.fillStyle = value;
		context.fillRect(0, 0, 1, 1);
		var pixel = context.getImageData(0, 0, 1, 1).data;
		return { r: pixel[0], g: pixel[1], b: pixel[2], a: pixel[3] / 255 };
	} catch (e) {
		return null;
	}
}

function resolveAuroraToken(doc, name) {
	var view = doc && doc.defaultView;
	var html = doc && doc.documentElement;
	if (!view || !view.getComputedStyle || !html)
		return null;
	var style;
	try {
		style = view.getComputedStyle(html);
	} catch (e) {
		return null;
	}
	var raw = style && style.getPropertyValue && style.getPropertyValue(name);
	if (!raw)
		return null;
	return parseCssColor(raw) || rasterizeCssColor(doc, String(raw).trim());
}

function compositeColor(top, bottom) {
	var alpha = top.a + bottom.a * (1 - top.a);
	if (alpha <= 0)
		return { r: 255, g: 255, b: 255, a: 1 };
	return {
		r: (top.r * top.a + bottom.r * bottom.a * (1 - top.a)) / alpha,
		g: (top.g * top.a + bottom.g * bottom.a * (1 - top.a)) / alpha,
		b: (top.b * top.a + bottom.b * bottom.a * (1 - top.a)) / alpha,
		a: alpha
	};
}

function relativeLuminance(color) {
	function channel(value) {
		var normalized = value / 255;
		return normalized <= .03928 ? normalized / 12.92 : Math.pow((normalized + .055) / 1.055, 2.4);
	}
	return channel(color.r) * .2126 + channel(color.g) * .7152 + channel(color.b) * .0722;
}

function contrastRatio(foreground, background) {
	var renderedForeground = compositeColor(foreground, background);
	var renderedBackground = background.a < 1 ? compositeColor(background, {
		r: 255, g: 255, b: 255, a: 1
	}) : background;
	var foregroundLuminance = relativeLuminance(renderedForeground);
	var backgroundLuminance = relativeLuminance(renderedBackground);
	return (Math.max(foregroundLuminance, backgroundLuminance) + .05) /
		(Math.min(foregroundLuminance, backgroundLuminance) + .05);
}

function colorString(color) {
	var channels = Math.round(color.r) + ', ' + Math.round(color.g) + ', ' + Math.round(color.b);
	return color.a < 1
		? 'rgba(' + channels + ', ' + Math.round(color.a * 1000) / 1000 + ')'
		: 'rgb(' + channels + ')';
}

function chooseAuroraForeground(candidates, backgrounds, threshold) {
	var best = null;
	var bestRatio = -Infinity;
	for (var i = 0; i < candidates.length; i++) {
		var candidate = candidates[i];
		if (!candidate)
			continue;
		var minimum = Infinity;
		for (var j = 0; j < backgrounds.length; j++)
			minimum = Math.min(minimum, contrastRatio(candidate, backgrounds[j]));
		if (minimum > bestRatio) {
			best = candidate;
			bestRatio = minimum;
		}
		if (minimum >= threshold)
			return candidate;
	}
	return best;
}

function minimumContrast(color, backgrounds) {
	var minimum = Infinity;
	for (var i = 0; i < backgrounds.length; i++)
		minimum = Math.min(minimum, contrastRatio(color, backgrounds[i]));
	return minimum;
}

function mixColor(from, to, amount) {
	return {
		r: from.r + (to.r - from.r) * amount,
		g: from.g + (to.g - from.g) * amount,
		b: from.b + (to.b - from.b) * amount,
		a: 1
	};
}

function contrastAdjustedColor(color, backgrounds, threshold, targetThreshold) {
	if (!color || !backgrounds.length || minimumContrast(color, backgrounds) >= threshold)
		return color;
	targetThreshold = Math.max(threshold, targetThreshold || threshold);
	var black = { r: 0, g: 0, b: 0, a: 1 };
	var white = { r: 255, g: 255, b: 255, a: 1 };
	var target = minimumContrast(black, backgrounds) >= minimumContrast(white, backgrounds)
		? black : white;
	var low = 0;
	var high = 1;
	for (var i = 0; i < 16; i++) {
		var middle = (low + high) / 2;
		if (minimumContrast(mixColor(color, target, middle), backgrounds) >= targetThreshold)
			high = middle;
		else
			low = middle;
	}
	return mixColor(color, target, high);
}

function computedColor(doc, node, property) {
	var view = doc && doc.defaultView;
	if (!node || !view || !view.getComputedStyle)
		return null;
	try {
		var value = view.getComputedStyle(node)[property];
		return parseCssColor(value) || rasterizeCssColor(doc, value);
	} catch (e) {
		return null;
	}
}

function argonBackgrounds(doc) {
	var nodes = [
		doc && doc.querySelector && doc.querySelector('.main-right #maincontent'),
		doc && doc.querySelector && doc.querySelector('.main-right'),
		doc && doc.body,
		doc && doc.documentElement
	];
	var backgrounds = [];
	for (var i = 0; i < nodes.length; i++) {
		var background = computedColor(doc, nodes[i], 'backgroundColor');
		if (background && background.a > .01 && !backgrounds.some(function(existing) {
			return Math.abs(existing.r - background.r) < 1 &&
				Math.abs(existing.g - background.g) < 1 &&
				Math.abs(existing.b - background.b) < 1 &&
				Math.abs(existing.a - background.a) < .01;
		}))
			backgrounds.push(background);
	}
	if (!backgrounds.length)
		backgrounds.push({ r: 255, g: 255, b: 255, a: 1 });

	/* Argon uses faint currentColor layers over its page background. */
	var text = computedColor(doc, doc && doc.body, 'color');
	if (text) {
		var originals = backgrounds.slice();
		for (var j = 0; j < originals.length; j++) {
			backgrounds.push(compositeColor({ r: text.r, g: text.g, b: text.b, a: .02 }, originals[j]));
			backgrounds.push(compositeColor({ r: text.r, g: text.g, b: text.b, a: .05 }, originals[j]));
		}
	}
	return backgrounds;
}

function safeInteractiveColor(color, backgrounds) {
	return contrastAdjustedColor(color, backgrounds, 3, 3.25);
}

function safeTextColor(color, backgrounds) {
	return contrastAdjustedColor(color, backgrounds, 4.5, 4.75);
}

function semanticBackgrounds(color, backgrounds, alpha) {
	if (!color)
		return backgrounds;
	var tinted = {
		r: color.r,
		g: color.g,
		b: color.b,
		a: alpha
	};
	return backgrounds.concat(backgrounds.map(function(background) {
		return compositeColor(tinted, background);
	}));
}

function inlineStyleValue(root, name) {
	if (!root || !root.style)
		return '';
	return typeof root.style.getPropertyValue === 'function'
		? root.style.getPropertyValue(name)
		: root.styleValues && root.styleValues[name];
}

function setInlineStyle(root, name, value) {
	if (!root || !root.style || typeof root.style.setProperty !== 'function')
		return;
	if (String(inlineStyleValue(root, name) || '').trim() !== String(value || '').trim())
		root.style.setProperty(name, value);
}

function clearInlineStyle(root, name) {
	if (!root || !root.style || typeof root.style.removeProperty !== 'function')
		return;
	if (String(inlineStyleValue(root, name) || '').trim())
		root.style.removeProperty(name);
}

function setSafeColor(root, name, color) {
	if (color)
		setInlineStyle(root, name, colorString(color));
	else
		clearInlineStyle(root, name);
}

function safeActionText(color, backgrounds) {
	if (!color)
		return null;
	var black = { r: 0, g: 0, b: 0, a: 1 };
	var white = { r: 255, g: 255, b: 255, a: 1 };
	return chooseAuroraForeground([ black, white ], backgrounds.map(function(background) {
		return compositeColor(color, background);
	}), 4.5);
}

function updateArgonContrastTokens(root, doc, colorMode) {
	if (!root || !doc || !root.style || typeof root.style.setProperty !== 'function')
		return;
	var accent = resolveAuroraToken(doc, colorMode === 'dark' ? '--dark-primary' : '--primary') ||
		resolveAuroraToken(doc, '--primary') || resolveAuroraToken(doc, '--default');
	if (!accent) {
		ARGON_CONTRAST_PROPERTIES.forEach(function(name) { clearInlineStyle(root, name); });
		return;
	}
	var backgrounds = argonBackgrounds(doc);
	var safeAccent = safeInteractiveColor(accent, backgrounds);
	var accentSoftBackgrounds = semanticBackgrounds(accent, backgrounds, .12);
	var warning = resolveAuroraToken(doc, '--warning') || accent;
	var danger = resolveAuroraToken(doc, '--danger') || accent;
	var info = resolveAuroraToken(doc, '--info') || accent;

	setSafeColor(root, '--lanspeed-accent-safe', safeAccent);
	setSafeColor(root, '--lanspeed-link-safe', safeTextColor(accent, backgrounds));
	setSafeColor(root, '--lanspeed-normal-text-safe', safeTextColor(accent, accentSoftBackgrounds));
	setSafeColor(root, '--lanspeed-switch-accent-safe', safeAccent);
	setSafeColor(root, '--lanspeed-filled-action-safe', safeAccent);
	setSafeColor(root, '--lanspeed-focus-color-safe', safeAccent);
	setSafeColor(root, '--lanspeed-action-text-safe', safeActionText(safeAccent, accentSoftBackgrounds));
	setSafeColor(root, '--lanspeed-filled-action-text-safe', safeActionText(safeAccent, backgrounds));
	setSafeColor(root, '--lanspeed-warning-safe', safeTextColor(warning,
		semanticBackgrounds(warning, backgrounds, .1)));
	setSafeColor(root, '--lanspeed-danger-safe', safeTextColor(danger,
		semanticBackgrounds(danger, backgrounds, .1)));
	setSafeColor(root, '--lanspeed-info-safe', safeTextColor(info,
		semanticBackgrounds(info, backgrounds, .09)));
}

function clearAuroraContrastTokens(root) {
	if (!root || !root.style || typeof root.style.removeProperty !== 'function')
		return;
	AURORA_CONTRAST_PROPERTIES.forEach(function(name) {
		clearInlineStyle(root, name);
	});
	ARGON_CONTRAST_PROPERTIES.forEach(function(name) {
		clearInlineStyle(root, name);
	});
}

function updateAuroraContrastTokens(root, doc) {
	if (!root || !doc || !root.style || typeof root.style.setProperty !== 'function')
		return;
	var brand = resolveAuroraToken(doc, '--brand');
	if (!brand) {
		AURORA_CONTRAST_PROPERTIES.forEach(function(name) { clearInlineStyle(root, name); });
		return;
	}
	var brandHover = resolveAuroraToken(doc, '--brand-hover') || brand;
	var brandSubtle = resolveAuroraToken(doc, '--brand-subtle');
	var onBrand = resolveAuroraToken(doc, '--on-brand');
	var text = resolveAuroraToken(doc, '--text');
	var surface = resolveAuroraToken(doc, '--surface') || { r: 255, g: 255, b: 255, a: 1 };
	var surfaceOverlay = resolveAuroraToken(doc, '--surface-overlay') || surface;
	var backgrounds = [ surface, surfaceOverlay ];
	var black = { r: 0, g: 0, b: 0, a: 1 };
	var white = { r: 255, g: 255, b: 255, a: 1 };
	var actionBackground = backgrounds.map(function(background) {
		return compositeColor(brand, background);
	});
	var hoverBackground = backgrounds.map(function(background) {
		return compositeColor(brandHover, background);
	});
	var actionText = chooseAuroraForeground([ onBrand, text, surface, black, white ], actionBackground, 4.5);
	var actionHoverText = chooseAuroraForeground([ onBrand, text, surface, black, white ], hoverBackground, 4.5);
	setSafeColor(root, '--lanspeed-action-text-safe', actionText);
	setSafeColor(root, '--lanspeed-action-hover-text-safe', actionHoverText);
	setSafeColor(root, '--lanspeed-accent-safe', safeInteractiveColor(brand, backgrounds));
	var normalText = null;
	if (brandSubtle) {
		var subtleBackground = backgrounds.map(function(background) {
			return compositeColor(brandSubtle, background);
		});
		normalText = chooseAuroraForeground([ brand, text, surface, black, white ], subtleBackground, 4.5);
	}
	setSafeColor(root, '--lanspeed-normal-text-safe', normalText);
	var focusText = chooseAuroraForeground([ brand, text, onBrand, black, white ], backgrounds, 3);
	setSafeColor(root, '--lanspeed-focus-color-safe', focusText);
	setSafeColor(root, '--lanspeed-warning-safe', safeTextColor(
		resolveAuroraToken(doc, '--warning') || brand, backgrounds));
	setSafeColor(root, '--lanspeed-danger-safe', safeTextColor(
		resolveAuroraToken(doc, '--danger') || brand, backgrounds));
	setSafeColor(root, '--lanspeed-info-safe', safeTextColor(
		resolveAuroraToken(doc, '--info') || brand, backgrounds));
}

function detectDarkSurface(doc) {
	var view = doc && doc.defaultView;
	if (!view || !view.getComputedStyle)
		return null;

	var candidates = [
		doc.querySelector && doc.querySelector('.main-right #maincontent'),
		doc.querySelector && doc.querySelector('.main-right'),
		doc.body,
		doc.documentElement
	];
	var luminances = [];
	for (var i = 0; i < candidates.length; i++) {
		var background = computedColor(doc, candidates[i], 'backgroundColor');
		if (background && background.a > .01)
			luminances.push(relativeLuminance(background));
	}
	if (!luminances.length)
		return null;
	/* Shells can layer a transparent body over a real main surface. Use the
	 * darkest opaque candidate, while ignoring tiny translucent text layers. */
	return Math.min.apply(null, luminances) < .35;
}

function explicitColorMode(doc, theme) {
	var html = doc && doc.documentElement;
	var body = doc && doc.body;
	var attributes = [ 'data-color-mode', 'data-theme', 'data-mode', 'data-darkmode' ];
	var nodes = [ html, body ];
	for (var i = 0; i < nodes.length; i++) {
		var node = nodes[i];
		if (!node || !node.getAttribute)
			continue;
		for (var j = 0; j < attributes.length; j++) {
			var value = String(node.getAttribute(attributes[j]) || '').toLowerCase();
			if (value === 'dark' || value === 'true')
				return 'dark';
			if (value === 'light' || value === 'false')
				return 'light';
		}
		var className = String(node.className || '').toLowerCase();
		if (/(^|\s)(dark|dark-mode|theme-dark)(\s|$)/.test(className))
			return 'dark';
		if (/(^|\s)(light|light-mode|theme-light)(\s|$)/.test(className))
			return 'light';
	}
	if (theme === 'aurora' && html) {
		var darkmode = html.getAttribute('data-darkmode');
		if (darkmode === 'true')
			return 'dark';
		if (darkmode === 'false')
			return 'light';
	}
	return '';
}

function detectColorMode(doc, theme) {
	var explicit = explicitColorMode(doc, theme);
	if (explicit)
		return explicit;
	var dark = detectDarkSurface(doc);
	if (dark !== null)
		return dark ? 'dark' : 'light';
	var view = doc && doc.defaultView;
	try {
		if (view && view.matchMedia && view.matchMedia('(prefers-color-scheme: dark)').matches)
			return 'dark';
	} catch (e) {}
	return '';
}

function updateColorMode(root, doc, theme) {
	var colorMode = detectColorMode(doc, theme);
	if (!root)
		return colorMode;
	var currentMode = root.getAttribute
		? root.getAttribute('data-lanspeed-color-mode')
		: root.attrs && root.attrs['data-lanspeed-color-mode'];
	if (colorMode) {
		if (currentMode !== colorMode)
			root.setAttribute('data-lanspeed-color-mode', colorMode);
	} else if (currentMode && root.removeAttribute) {
		root.removeAttribute('data-lanspeed-color-mode');
	}
	if (theme === 'aurora')
		updateAuroraContrastTokens(root, doc);
	else if (theme === 'argon')
		updateArgonContrastTokens(root, doc, colorMode);
	else
		clearAuroraContrastTokens(root);
	if (root && typeof root.dispatchEvent === 'function') {
		var view = doc && doc.defaultView;
		var event = null;
		try {
			if (view && typeof view.CustomEvent === 'function') {
				event = new view.CustomEvent('lanspeed-theme-update', {
					detail: { theme: theme, colorMode: colorMode }
				});
			} else if (doc && typeof doc.createEvent === 'function') {
				event = doc.createEvent('CustomEvent');
				event.initCustomEvent('lanspeed-theme-update', false, false, {
					theme: theme, colorMode: colorMode
				});
			}
		} catch (e) {
			event = null;
		}
		if (event)
			root.dispatchEvent(event);
	}
	return colorMode;
}

function releaseColorMode(root) {
	var cleanup = root && root[COLOR_MODE_CLEANUP];
	if (typeof cleanup === 'function')
		cleanup();
}

function watchColorMode(root, doc, theme) {
	updateColorMode(root, doc, theme);

	var view = doc && doc.defaultView;
	if (!root || !view)
		return;

	var media = null;
	var useEventTarget = false;
	try {
		media = view.matchMedia && view.matchMedia('(prefers-color-scheme: dark)');
	} catch (e) {
		media = null;
	}

	var active = true;
	var observer = null;
	var pollTimer = null;
	var updateTimer = null;
	var scheduleUpdate = function() {
		if (!active || updateTimer !== null)
			return;
		if (typeof view.setTimeout !== 'function') {
			updateColorMode(root, doc, theme);
			return;
		}
		updateTimer = view.setTimeout(function() {
			updateTimer = null;
			if (active)
				updateColorMode(root, doc, theme);
		}, 0);
	};
	var mediaListener = function() {
		if (active)
			scheduleUpdate();
	};
	var mediaBound = false;
	if (media && typeof media.addEventListener === 'function') {
		media.addEventListener('change', mediaListener);
		useEventTarget = true;
		mediaBound = true;
	} else if (media && typeof media.addListener === 'function') {
		media.addListener(mediaListener);
		mediaBound = true;
	}

	var cleanup = function() {
		if (!active)
			return;
		active = false;
		if (mediaBound && useEventTarget && typeof media.removeEventListener === 'function')
			media.removeEventListener('change', mediaListener);
		else if (mediaBound && typeof media.removeListener === 'function')
			media.removeListener(mediaListener);
		if (observer)
			observer.disconnect();
		if (pollTimer !== null && typeof view.clearInterval === 'function')
			view.clearInterval(pollTimer);
		if (updateTimer !== null && typeof view.clearTimeout === 'function')
			view.clearTimeout(updateTimer);
		updateTimer = null;
		if (root[COLOR_MODE_CLEANUP] === cleanup)
			root[COLOR_MODE_CLEANUP] = null;
	};

	if (typeof view.MutationObserver === 'function' && doc.documentElement) {
		observer = new view.MutationObserver(function(records) {
			for (var i = 0; i < records.length; i++) {
				var record = records[i];
				for (var j = 0; j < (record.removedNodes || []).length; j++) {
					var removed = record.removedNodes[j];
					if (removed === root || (removed.contains && removed.contains(root))) {
						cleanup();
						return;
					}
				}
			}
			scheduleUpdate();
		});
		var options = {
			attributes: true,
			attributeFilter: [
				'class', 'style', 'data-darkmode', 'data-theme', 'data-mode', 'data-color-mode'
			],
			childList: true,
			subtree: true
		};
		try {
			observer.observe(doc.documentElement, options);
		} catch (e) {
			observer = null;
		}
	}

	/* Some themes replace a stylesheet or a CSS variable without mutating an
	 * observed node. A low-frequency poll keeps contrast-safe tokens current
	 * without making the page continuously recalculate layout. */
	if (typeof view.setInterval === 'function')
		pollTimer = view.setInterval(scheduleUpdate, 1000);

	if (mediaBound || observer || pollTimer !== null)
		root[COLOR_MODE_CLEANUP] = cleanup;
}

function hasSelector(doc, selector) {
	try {
		return !!(doc && doc.querySelector && doc.querySelector(selector));
	} catch (e) {
		return false;
	}
}

function hasAuroraAsset(doc) {
	return hasSelector(doc, 'link[href*="/luci-static/aurora/"]');
}

function hasArgonAsset(doc) {
	return hasSelector(doc, 'link[href*="/luci-static/argon/"]') ||
		hasSelector(doc, 'script[src*="menu-argon.js"]');
}

function hasBootstrapAsset(doc) {
	return hasSelector(doc, 'link[href*="/luci-static/bootstrap/"]') ||
		hasSelector(doc, 'link[href*="/luci-static/bootstrap-dark/"]') ||
		hasSelector(doc, 'link[href*="/luci-static/bootstrap-light/"]');
}

function hasAuroraMeta(doc) {
	var meta = doc && doc.querySelector &&
		doc.querySelector('meta[name="application-name"]');
	var content = (meta && meta.getAttribute('content')) || '';
	return content === AURORA_META || /LuCI\s+Aurora/i.test(content);
}

function hasAuroraShell(doc) {
	var html = doc && doc.documentElement;
	var body = doc && doc.body;

	return !!(
		html && html.hasAttribute('data-darkmode') &&
		body && body.hasAttribute('data-nav-type') &&
		(hasSelector(doc, '.theme-switcher') ||
		 hasSelector(doc, '.sidebar-panel') ||
		 hasSelector(doc, '.desktop-menu-container') ||
		 hasSelector(doc, '#floating-toolbar'))
	);
}

function isAurora(doc) {
	doc = docOrGlobal(doc);
	return !!(doc && (hasAuroraAsset(doc) || hasAuroraMeta(doc) || hasAuroraShell(doc)));
}

function hasArgonShell(doc) {
	return !!(
		hasSelector(doc, '.main') &&
		hasSelector(doc, '.main-left#mainmenu') &&
		hasSelector(doc, '.main-right') &&
		hasSelector(doc, '.darkMask') &&
		hasSelector(doc, '#tabmenu')
	);
}

function isArgon(doc) {
	doc = docOrGlobal(doc);
	return !!(doc && (hasArgonAsset(doc) || hasArgonShell(doc)));
}

function isBootstrap(doc) {
	doc = docOrGlobal(doc);
	return !!(doc && hasBootstrapAsset(doc));
}

return baseclass.extend({
	detect: function(doc) {
		if (isAurora(doc))
			return 'aurora';
		if (isArgon(doc))
			return 'argon';
		if (isBootstrap(doc))
			return 'bootstrap';
		return '';
	},

	className: function(doc) {
		var theme = this.detect(doc);
		if (theme === 'aurora')
			return AURORA_CLASS;
		if (theme === 'argon')
			return ARGON_CLASS;
		if (theme === 'bootstrap')
			return BOOTSTRAP_CLASS;
		return '';
	},

	applyRoot: function(root, doc) {
		doc = docOrGlobal(doc);
		if (root) {
			releaseColorMode(root);
			clearAuroraContrastTokens(root);
		}
		var theme = this.detect(doc);

		if (!root)
			return theme;

		if (root.classList && typeof root.classList.remove === 'function') {
			root.classList.remove(AURORA_CLASS);
			root.classList.remove(ARGON_CLASS);
			root.classList.remove(BOOTSTRAP_CLASS);
		}
		if (root.removeAttribute)
			root.removeAttribute('data-lanspeed-theme');
		if (!theme)
			return theme;

		root.classList.add(this.className(doc));
		root.setAttribute('data-lanspeed-theme', theme);
		watchColorMode(root, doc, theme);
		return theme;
	},

	releaseRoot: function(root) {
		releaseColorMode(root);
		clearAuroraContrastTokens(root);
	}
});
