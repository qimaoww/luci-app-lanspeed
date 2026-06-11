'use strict';
'require baseclass';

var AURORA_CLASS = 'lanspeed-theme-aurora';
var AURORA_META = 'LuCI Aurora';

function docOrGlobal(doc) {
	if (doc)
		return doc;
	if (typeof document !== 'undefined')
		return document;
	return null;
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

return baseclass.extend({
	detect: function(doc) {
		return isAurora(doc) ? 'aurora' : '';
	},

	className: function(doc) {
		var theme = this.detect(doc);
		return theme === 'aurora' ? AURORA_CLASS : '';
	},

	applyRoot: function(root, doc) {
		var theme = this.detect(doc);

		if (!root || !theme)
			return theme;

		root.classList.add(this.className(doc));
		root.setAttribute('data-lanspeed-theme', theme);
		return theme;
	}
});
