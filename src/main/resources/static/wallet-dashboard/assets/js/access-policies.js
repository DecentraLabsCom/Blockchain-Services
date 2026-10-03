(function () {
    'use strict';

    const categories = [
        'Mathematics', 'Statistics & Probability', 'Computer Science', 'Artificial Intelligence & Machine Learning',
        'Data Science', 'Cybersecurity', 'Software Engineering', 'Physics', 'Chemistry', 'Biochemistry', 'Biology',
        'Molecular Biology', 'Genetics', 'Microbiology', 'Biotechnology', 'Engineering & Technology', 'Civil Engineering', 'Mechanical Engineering',
        'Electrical Engineering', 'Chemical Engineering', 'Materials Engineering', 'Robotics', 'Nanotechnology',
        'Biomedical Engineering', 'Medicine', 'Clinical Medicine', 'Pharmacology', 'Immunology', 'Public Health',
        'Medical Imaging', 'Laboratory Medicine', 'Agriculture', 'Veterinary Medicine', 'Environmental Sciences',
        'Climate Science', 'Psychology', 'Cognitive Science', 'Economics', 'Sociology', 'Political Science', 'Linguistics',
        'Digital Humanities', 'Archaeology', 'Energy Engineering', 'Renewable Energy', 'Food Science & Technology',
        'Quality Control', 'Metrology', 'Other'
    ];

    const state = { policy: null, audit: [], groups: [] };
    const $ = (id) => document.getElementById(id);
    const toast = (message, type) => {
        if (typeof window.showToast === 'function') window.showToast(message, type || 'info');
        else console[type === 'error' ? 'error' : 'log'](message);
    };

    function normalizePolicy(payload) {
        const policy = payload?.policy || payload || {};
        return {
            institutionId: policy.institutionId || payload?.institutionId || '',
            name: policy.name || 'Institutional access policy',
            version: Number(policy.version || 0),
            enabled: Boolean(policy.enabled),
            defaultDecision: policy.defaultDecision === 'ALLOW' ? 'ALLOW' : 'DENY',
            groups: Array.isArray(policy.groups) ? policy.groups : [],
            overrides: Array.isArray(policy.overrides) ? policy.overrides : [],
        };
    }

    function escapeHtml(value) {
        return String(value ?? '').replace(/[&<>'"]/g, character => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[character]));
    }

    function multiSelectOptionMarkup(category, selected) {
        const isSelected = selected.includes(category);
        return `<button type="button" class="policy-multi-select-option" role="option" aria-selected="${isSelected}" data-multiselect-option data-value="${escapeHtml(category)}">
            <span class="policy-multi-select-check" aria-hidden="true"><i class="fas fa-check"></i></span>
            <span>${escapeHtml(category)}</span>
        </button>`;
    }

    function multiSelectContents(id, selected, label) {
        const safeId = escapeHtml(id);
        const safeLabel = escapeHtml(label || $(id)?.dataset.multiselectLabel || 'Categories');
        return `<button id="${safeId}-trigger" type="button" class="policy-multi-select-trigger" data-multiselect-trigger aria-haspopup="listbox" aria-expanded="false" aria-controls="${safeId}-menu" aria-label="Choose ${safeLabel.toLowerCase()}">
                <span class="policy-multi-select-summary" data-multiselect-summary><span class="policy-multi-select-placeholder">Choose categories</span></span>
                <i class="fas fa-chevron-down policy-multi-select-chevron" aria-hidden="true"></i>
            </button>
                <div id="${safeId}-menu" class="policy-multi-select-menu hidden" data-multiselect-menu>
                <div class="policy-multi-select-search">
                    <input type="search" data-multiselect-search placeholder="Search categories" aria-label="Search ${safeLabel.toLowerCase()}" autocomplete="off">
                </div>
                <div class="policy-multi-select-options" data-multiselect-options role="listbox" aria-label="${safeLabel}" aria-multiselectable="true">
                    ${categories.map(category => multiSelectOptionMarkup(category, selected)).join('')}
                </div>
                <div class="policy-multi-select-empty hidden" data-multiselect-empty>No categories found</div>
                <div class="policy-multi-select-footer">
                    <span data-multiselect-count>No categories selected</span>
                    <button type="button" class="policy-multi-select-clear" data-multiselect-clear>Clear</button>
                </div>
            </div>`;
    }

    function multiSelectMarkup(id, selected, attribute, label) {
        const dataAttribute = attribute ? ` ${attribute}` : '';
        return `<div id="${escapeHtml(id)}" class="policy-multi-select" data-policy-multiselect data-multiselect-label="${escapeHtml(label || 'Categories')}"${dataAttribute}>${multiSelectContents(id, selected, label)}</div>`;
    }

    function renderTestCategories() {
        const container = $('accessPolicyTestCategories');
        if (container) {
            container.innerHTML = multiSelectContents(container.id, []);
            updateMultiSelectSummary(container);
        }
    }

    function updateMultiSelectSummary(container) {
        const selected = selectedValues(container);
        const summary = container.querySelector('[data-multiselect-summary]');
        const count = container.querySelector('[data-multiselect-count]');
        const trigger = container.querySelector('[data-multiselect-trigger]');
        if (!summary || !trigger) return;
        if (!selected.length) {
            summary.innerHTML = '<span class="policy-multi-select-placeholder">Choose categories</span>';
            trigger.setAttribute('aria-label', 'Choose categories');
        } else {
            const visible = selected.slice(0, 2).map(value => `<span class="policy-multi-select-chip">${escapeHtml(value)}</span>`).join('');
            const remainder = selected.length > 2 ? `<span class="policy-multi-select-more">+${selected.length - 2} more</span>` : '';
            summary.innerHTML = visible + remainder;
            trigger.setAttribute('aria-label', `${selected.length} categories selected`);
        }
        if (count) count.textContent = selected.length ? `${selected.length} selected` : 'No categories selected';
    }

    function matcherChips(matchers) {
        return Object.entries(matchers || {}).flatMap(([key, values]) => (Array.isArray(values) ? values : [values])
            .map(value => `<span class="policy-chip">${escapeHtml(key)}: ${escapeHtml(value)}</span>`)).join('');
    }

    function renderGroups() {
        const host = $('accessPolicyGroups');
        if (!state.groups.length) {
            host.innerHTML = '<div class="policy-empty">No groups yet. Add one to define access.</div>';
            return;
        }
        host.innerHTML = state.groups.map((group, index) => {
            const matchers = group.matchers || {};
            const allowed = Array.isArray(group.allowedCategories) ? group.allowedCategories : [];
            const denied = Array.isArray(group.deniedCategories) ? group.deniedCategories : [];
            return `<article class="policy-group" data-policy-group="${index}">
                <div class="policy-group-heading"><input data-group-label value="${escapeHtml(group.label || group.id || `Group ${index + 1}`)}" placeholder="Group name"><button type="button" class="btn btn-danger btn-small" data-remove-group>Remove</button></div>
                <div class="policy-chips">${matcherChips(matchers) || '<span class="status-text">No matchers</span>'}</div>
                <div class="policy-matcher-row"><input data-matcher-input placeholder="attribute=value"><button type="button" class="btn btn-secondary btn-small" data-add-matcher>Add matcher</button></div>
                <div class="policy-category-grid">
                    <div class="policy-category-field"><span class="policy-field-label">Allow categories</span>${multiSelectMarkup(`group-${index}-allow`, allowed, 'data-group-allow', 'Allowed categories')}</div>
                    <div class="policy-category-field"><span class="policy-field-label">Deny categories</span>${multiSelectMarkup(`group-${index}-deny`, denied, 'data-group-deny', 'Denied categories')}</div>
                </div>
            </article>`;
        }).join('');
    }

    function selectedValues(container) {
        if (!container) return [];
        return Array.from(container.querySelectorAll('[data-multiselect-option][aria-selected="true"]'))
            .map(option => option.dataset.value || '');
    }

    function closeMultiSelects(except) {
        document.querySelectorAll('[data-policy-multiselect]').forEach(container => {
            if (container === except) return;
            const menu = container.querySelector('[data-multiselect-menu]');
            const trigger = container.querySelector('[data-multiselect-trigger]');
            menu?.classList.add('hidden');
            trigger?.setAttribute('aria-expanded', 'false');
        });
    }

    function setMultiSelectOpen(container, open) {
        const menu = container.querySelector('[data-multiselect-menu]');
        const trigger = container.querySelector('[data-multiselect-trigger]');
        if (!menu || !trigger) return;
        if (open) {
            closeMultiSelects(container);
            menu.classList.remove('hidden');
            trigger.setAttribute('aria-expanded', 'true');
            menu.querySelector('[data-multiselect-search]')?.focus();
        } else {
            menu.classList.add('hidden');
            trigger.setAttribute('aria-expanded', 'false');
        }
    }

    function filterMultiSelect(container, query) {
        const normalizedQuery = query.trim().toLowerCase();
        let visibleOptions = 0;
        container.querySelectorAll('[data-multiselect-option]').forEach(option => {
            const visible = !normalizedQuery || option.textContent.trim().toLowerCase().includes(normalizedQuery);
            option.hidden = !visible;
            if (visible) visibleOptions += 1;
        });
        const empty = container.querySelector('[data-multiselect-empty]');
        if (empty) empty.classList.toggle('hidden', visibleOptions > 0);
    }

    function bindMultiSelectEvents() {
        document.addEventListener('click', event => {
            const trigger = event.target.closest('[data-multiselect-trigger]');
            if (trigger) {
                const container = trigger.closest('[data-policy-multiselect]');
                const isOpen = trigger.getAttribute('aria-expanded') === 'true';
                event.preventDefault();
                setMultiSelectOpen(container, !isOpen);
                return;
            }

            const option = event.target.closest('[data-multiselect-option]');
            if (option) {
                const container = option.closest('[data-policy-multiselect]');
                event.preventDefault();
                option.setAttribute('aria-selected', option.getAttribute('aria-selected') !== 'true' ? 'true' : 'false');
                updateMultiSelectSummary(container);
                return;
            }

            const clear = event.target.closest('[data-multiselect-clear]');
            if (clear) {
                const container = clear.closest('[data-policy-multiselect]');
                event.preventDefault();
                container.querySelectorAll('[data-multiselect-option]').forEach(option => option.setAttribute('aria-selected', 'false'));
                updateMultiSelectSummary(container);
                container.querySelector('[data-multiselect-search]').value = '';
                filterMultiSelect(container, '');
                return;
            }

            if (!event.target.closest('[data-policy-multiselect]')) closeMultiSelects();
        });

        document.addEventListener('input', event => {
            if (!event.target.matches('[data-multiselect-search]')) return;
            filterMultiSelect(event.target.closest('[data-policy-multiselect]'), event.target.value);
        });

        document.addEventListener('keydown', event => {
            if (event.key === 'Escape') {
                const container = event.target.closest('[data-policy-multiselect]');
                if (container) setMultiSelectOpen(container, false);
            }
        });
    }

    function readGroups() {
        state.groups = Array.from(document.querySelectorAll('[data-policy-group]')).map((element, index) => {
            const original = state.groups[index] || {};
            return {
                id: original.id || `group-${index + 1}`,
                label: element.querySelector('[data-group-label]')?.value.trim() || `Group ${index + 1}`,
                matchers: original.matchers || {},
                allowedCategories: selectedValues(element.querySelector('[data-group-allow]')),
                deniedCategories: selectedValues(element.querySelector('[data-group-deny]')),
            };
        });
    }

    function render() {
        $('accessPolicyName').value = state.policy.name;
        $('accessPolicyDefaultDecision').value = state.policy.defaultDecision;
        $('accessPolicyVersion').textContent = state.policy.version ? `Version ${state.policy.version}` : 'Not saved';
        const status = $('accessPolicyStatus');
        status.textContent = state.policy.enabled ? 'Active' : (state.policy.version ? 'Disabled' : 'Not configured');
        status.className = `policy-status ${state.policy.enabled ? 'policy-status-active' : 'policy-status-disabled'}`;
        $('accessPolicyActivateBtn').disabled = state.policy.enabled;
        $('accessPolicyDeactivateBtn').disabled = !state.policy.enabled;
        state.groups = state.policy.groups.slice();
        renderGroups();
        $('accessPolicyAudit').innerHTML = state.audit.length
            ? state.audit.map(event => `<div class="policy-audit-row"><span>${escapeHtml(event.event_type || event.eventType || 'Updated')}</span><small>${escapeHtml(event.created_at || '')}</small></div>`).join('')
            : '<div class="policy-empty">No changes yet.</div>';
    }

    async function load() {
        try {
            const response = await API.getAccessPolicy();
            state.policy = normalizePolicy(response);
            state.audit = response.audit || [];
            render();
        } catch (error) {
            toast(`Access policy unavailable: ${error.message}`, 'error');
        }
    }

    async function save() {
        readGroups();
        const payload = {
            name: $('accessPolicyName').value.trim(),
            defaultDecision: $('accessPolicyDefaultDecision').value,
            enabled: state.policy.enabled,
            groups: state.groups,
            overrides: state.policy.overrides || [],
        };
        const response = await API.saveAccessPolicy(payload);
        state.policy = normalizePolicy(response);
        state.audit = response.audit || state.audit;
        render();
        toast('Policy saved', 'success');
    }

    async function setEnabled(enabled) {
        const response = enabled ? await API.activateAccessPolicy() : await API.deactivateAccessPolicy();
        state.policy = normalizePolicy(response);
        state.audit = response.audit || state.audit;
        render();
        toast(enabled ? 'Policy activated' : 'Policy disabled', 'success');
    }

    async function testPolicy(event) {
        event.preventDefault();
        let attributes;
        try { attributes = JSON.parse($('accessPolicyTestAttributes').value || '{}'); } catch (error) { toast('Attributes must be valid JSON', 'error'); return; }
        const response = await API.testAccessPolicy({
            attributes,
            categories: selectedValues($('accessPolicyTestCategories')),
            price: '1',
        });
        const result = $('accessPolicyTestResult');
        result.classList.remove('hidden');
        result.className = `policy-test-result ${response.allowed ? 'policy-result-allow' : 'policy-result-deny'}`;
        result.textContent = response.allowed ? `Allowed · ${response.reasonCode}` : `Denied · ${response.reasonCode}`;
    }

    function bind() {
        bindMultiSelectEvents();
        renderTestCategories();
        $('accessPolicyForm').addEventListener('submit', event => { event.preventDefault(); save().catch(error => toast(error.message, 'error')); });
        $('accessPolicyActivateBtn').addEventListener('click', () => setEnabled(true).catch(error => toast(error.message, 'error')));
        $('accessPolicyDeactivateBtn').addEventListener('click', () => setEnabled(false).catch(error => toast(error.message, 'error')));
        $('accessPolicyTestForm').addEventListener('submit', event => testPolicy(event).catch(error => toast(error.message, 'error')));
        $('addAccessPolicyGroupBtn').addEventListener('click', () => { readGroups(); state.groups.push({ id: `group-${Date.now()}`, label: '', matchers: {}, allowedCategories: [], deniedCategories: [] }); renderGroups(); });
        $('accessPolicyGroups').addEventListener('click', event => {
            const group = event.target.closest('[data-policy-group]');
            if (!group) return;
            const index = Number(group.dataset.policyGroup);
            if (event.target.matches('[data-remove-group]')) { readGroups(); state.groups.splice(index, 1); renderGroups(); return; }
            if (event.target.matches('[data-add-matcher]')) {
                const input = group.querySelector('[data-matcher-input]');
                const [key, ...parts] = input.value.split('=');
                if (!key || !parts.length) return;
                readGroups();
                state.groups[index].matchers = state.groups[index].matchers || {};
                state.groups[index].matchers[key.trim()] = [...(state.groups[index].matchers[key.trim()] || []), parts.join('=').trim()];
                input.value = '';
                renderGroups();
            }
        });
        $('accessPolicyExportBtn').addEventListener('click', () => { $('accessPolicyTransfer').classList.remove('hidden'); $('accessPolicyTransfer').value = JSON.stringify(state.policy, null, 2); });
        $('accessPolicyImportBtn').addEventListener('click', async () => {
            const transfer = $('accessPolicyTransfer');
            transfer.classList.remove('hidden');
            if (!transfer.value.trim()) return;
            try { const response = await API.importAccessPolicy(JSON.parse(transfer.value)); state.policy = normalizePolicy(response); state.audit = response.audit || state.audit; render(); toast('Policy imported', 'success'); }
            catch (error) { toast(`Import failed: ${error.message}`, 'error'); }
        });
    }

    document.addEventListener('DOMContentLoaded', () => { bind(); load(); });
}());
