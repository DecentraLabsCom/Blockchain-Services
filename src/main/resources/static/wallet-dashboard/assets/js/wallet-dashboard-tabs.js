document.addEventListener('DOMContentLoaded', () => {
    const DEFAULT_TAB = 'overview';
    const main = document.querySelector('.dashboard-main');
    const tabList = document.querySelector('[role="tablist"]');
    const status = document.querySelector('#walletTabStatus');
    const tabs = Array.from(document.querySelectorAll('[data-wallet-tab]'));
    const sections = Array.from(document.querySelectorAll('[data-wallet-tab-section]'));
    const panels = new Map();
    const initializedTabs = new Set();
    let activeTab = null;

    if (!main || !tabList || tabs.length === 0) return;

    function getTab(name) {
        return tabs.find(tab => tab.dataset.walletTab === name) || null;
    }

    function visibleTabs() {
        return tabs.filter(tab => !tab.hidden && !tab.disabled);
    }

    function fallbackTab() {
        return visibleTabs().find(tab => tab.dataset.walletTab === DEFAULT_TAB) || visibleTabs()[0] || null;
    }

    tabs.forEach(tab => {
        const tabName = tab.dataset.walletTab;
        const panelId = `wallet-panel-${tabName}`;
        const panel = document.getElementById(panelId) || document.createElement('div');
        panel.id = panelId;
        panel.classList.add('wallet-tab-panel');
        panel.setAttribute('role', 'tabpanel');
        panel.setAttribute('aria-labelledby', tab.id);
        panel.hidden = true;

        sections
            .filter(section => section.dataset.walletTabSection === tabName)
            .sort((left, right) => Number(left.dataset.walletOrder || 0) - Number(right.dataset.walletOrder || 0))
            .forEach(section => panel.appendChild(section));

        panels.set(tabName, panel);
        main.appendChild(panel);
    });
    document.body.classList.add('wallet-tabs-ready');

    function tabFromHash() {
        const candidate = window.location.hash.replace(/^#/, '').trim();
        const candidateTab = getTab(candidate);
        if (candidateTab && !candidateTab.hidden && !candidateTab.disabled) return candidate;
        return fallbackTab()?.dataset.walletTab || DEFAULT_TAB;
    }

    function setHash(tabName, replace) {
        const nextHash = `#${tabName}`;
        if (window.location.hash === nextHash) return;
        if (replace) {
            window.history.replaceState(null, '', nextHash);
        } else {
            window.history.pushState(null, '', nextHash);
        }
    }

    function activateTab(tabName, options = {}) {
        const requestedTab = getTab(tabName);
        const tab = requestedTab && !requestedTab.hidden && !requestedTab.disabled
            ? requestedTab
            : fallbackTab();
        if (!tab) return;

        const selectedName = tab.dataset.walletTab;
        const isFirstActivation = !initializedTabs.has(selectedName);
        activeTab = selectedName;
        initializedTabs.add(selectedName);

        tabs.forEach(candidate => {
            const selected = candidate === tab;
            candidate.setAttribute('aria-selected', selected ? 'true' : 'false');
            candidate.tabIndex = selected ? 0 : -1;
        });
        panels.forEach((panel, name) => {
            panel.hidden = name !== selectedName;
        });

        if (options.updateHash !== false) {
            setHash(selectedName, options.replaceHash === true);
        }
        if (options.focus === true) tab.focus();
        if (status) status.textContent = '';

        document.dispatchEvent(new CustomEvent('wallet-dashboard:tab-activated', {
            detail: { tab: selectedName, firstActivation: isFirstActivation }
        }));
    }

    function setRoleVisibility({ isInstitution = false, isProvider = false, isOperator = false } = {}) {
        const availableRoles = new Set();
        if (isInstitution) availableRoles.add('institution');
        if (isProvider) availableRoles.add('provider');
        if (isOperator) availableRoles.add('operator');

        tabs.forEach(tab => {
            const requiredRoles = (tab.dataset.walletTabRoles || '')
                .split(',')
                .map(role => role.trim())
                .filter(Boolean);
            const visible = requiredRoles.length === 0
                || requiredRoles.some(role => availableRoles.has(role));
            tab.hidden = !visible;
            tab.setAttribute('aria-hidden', visible ? 'false' : 'true');
        });

        const active = getTab(activeTab);
        if (!active || active.hidden || active.disabled) {
            activateTab(fallbackTab()?.dataset.walletTab || DEFAULT_TAB, { replaceHash: true });
        }
    }

    tabs.forEach(tab => {
        tab.addEventListener('click', () => activateTab(tab.dataset.walletTab));
        tab.addEventListener('keydown', event => {
            const availableTabs = visibleTabs();
            const currentIndex = availableTabs.indexOf(tab);
            let nextIndex = null;
            if (event.key === 'ArrowRight') nextIndex = (currentIndex + 1) % availableTabs.length;
            if (event.key === 'ArrowLeft') nextIndex = (currentIndex - 1 + availableTabs.length) % availableTabs.length;
            if (event.key === 'Home') nextIndex = 0;
            if (event.key === 'End') nextIndex = availableTabs.length - 1;
            if (nextIndex === null || availableTabs.length === 0) return;
            event.preventDefault();
            activateTab(availableTabs[nextIndex].dataset.walletTab, { focus: true });
        });
    });

    window.addEventListener('hashchange', () => activateTab(tabFromHash(), { updateHash: false }));
    window.addEventListener('popstate', () => activateTab(tabFromHash(), { updateHash: false }));

    window.WalletDashboardTabs = Object.freeze({
        get activeTab() {
            return activeTab;
        },
        activateTab,
        setRoleVisibility
    });

    activateTab(tabFromHash(), { replaceHash: true });
});
