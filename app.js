// DKIM Inspector: lookups go to dns.google (DNS over HTTPS) from the browser, nothing else is contacted.
  (function() {
    // DOM elements
    const domainInput = document.getElementById('domainInput');
    const selectorInput = document.getElementById('selectorInput');
    const checkBtn = document.getElementById('checkBtn');
    const btnText = document.getElementById('btnText');
    const btnLoader = document.getElementById('btnLoader');
    const resultContainer = document.getElementById('resultContainer');
    const placeholderState = document.getElementById('placeholderState');
    const recordsContainer = document.getElementById('recordsContainer');
    const errorContainer = document.getElementById('errorContainer');

    // Tab elements
    const tabGenerate = document.getElementById('tabGenerate');
    const tabRecommend = document.getElementById('tabRecommend');
    const tabTools = document.getElementById('tabTools');
    const generateTab = document.getElementById('generateTab');
    const recommendTab = document.getElementById('recommendTab');
    const toolsTab = document.getElementById('toolsTab');

    // Tab switching
    function switchTab(activeTab, activeContent) {
      // Remove active class from all tabs
      [tabGenerate, tabRecommend, tabTools].forEach(t => t.classList.remove('active'));
      [generateTab, recommendTab, toolsTab].forEach(t => t.classList.remove('active'));
      
      // Add active class to selected tab and content
      activeTab.classList.add('active');
      [tabGenerate, tabRecommend, tabTools].forEach(t => t.setAttribute('aria-pressed', String(t === activeTab)));
      activeContent.classList.add('active');
    }

    tabGenerate.addEventListener('click', () => switchTab(tabGenerate, generateTab));
    tabRecommend.addEventListener('click', () => switchTab(tabRecommend, recommendTab));
    tabTools.addEventListener('click', () => switchTab(tabTools, toolsTab));

    // Helper to show/hide containers
    function setActiveView(view) {
      placeholderState.classList.toggle('hidden', view !== 'placeholder');
      recordsContainer.classList.toggle('hidden', view !== 'records');
      errorContainer.classList.toggle('hidden', view !== 'error');
    }

    [tabGenerate, tabRecommend, tabTools].forEach(t => t.setAttribute('aria-pressed', String(t === tabGenerate)));

    // Initial state
    setActiveView('placeholder');

    // Parse DKIM record and extract tags
    function parseDKIMRecord(record) {
      const tags = [];
      // Remove quotes and split by semicolons
      let cleanRecord = record.replace(/^"|"$/g, '').replace(/\\"/g, '"');
      
      // Split by semicolons
      const parts = cleanRecord.split(';');
      
      for (let part of parts) {
        part = part.trim();
        if (!part) continue;
        
        const match = part.match(/^([a-zA-Z0-9]+)=(.+)$/);
        if (match) {
          tags.push({
            key: match[1],
            value: match[2].replace(/^"|"$/g, '') // Remove surrounding quotes
          });
        }
      }
      return tags;
    }

    // Validate DKIM record
    function validateDKIM(tags) {
      const validation = {
        valid: true,
        messages: [],
        warnings: []
      };

      const tagMap = {};
      tags.forEach(t => tagMap[t.key] = t.value);

      // Check required v= tag
      if (!tagMap.v) {
        validation.valid = false;
        validation.messages.push('Missing required "v=DKIM1" tag');
      } else if (tagMap.v !== 'DKIM1') {
        validation.valid = false;
        validation.messages.push('Version must be "DKIM1"');
      }

      // Check for public key
      if (!tagMap.p) {
        validation.valid = false;
        validation.messages.push('Missing public key (p= tag)');
      } else if (tagMap.p === '') {
        validation.warnings.push('Public key is empty (revoked)');
      }

      // Check key type
      if (tagMap.k && tagMap.k !== 'rsa') {
        validation.warnings.push(`Uncommon key type: ${tagMap.k}`);
      }

      // Check hash algorithms
      if (tagMap.h) {
        const hashes = tagMap.h.split(':');
        if (hashes.includes('sha1')) {
          validation.warnings.push('SHA-1 is deprecated for DKIM');
        }
      }

      // Check service types
      if (tagMap.s && tagMap.s !== '*') {
        const services = tagMap.s.split(':');
        if (!services.includes('email')) {
          validation.warnings.push('Service type may not include email');
        }
      }

      return validation;
    }

    // Render DKIM record with validation
    function renderDKIMResult(domain, selector, record) {
      const tags = parseDKIMRecord(record);
      const validation = validateDKIM(tags);

      let tagsHtml = '';
      tags.forEach(tag => {
        // For a long public key, show a truncated version with a show/hide control
        if (tag.key === 'p' && tag.value.length > 100) {
          const truncatedKey = tag.value.substring(0, 100) + '...';
          tagsHtml += `
            <li class="tag">
              <span class="tag-key">${escapeHtml(tag.key)}</span>=<span class="tag-value" data-short>${escapeHtml(truncatedKey)}</span><span class="tag-value hidden" data-full>${escapeHtml(tag.value)}</span>
              <button type="button" class="expand-key-btn" aria-expanded="false">Show full key</button>
            </li>
          `;
        } else {
          tagsHtml += `
            <li class="tag">
              <span class="tag-key">${escapeHtml(tag.key)}</span>=<span class="tag-value">${escapeHtml(tag.value)}</span>
            </li>
          `;
        }
      });

      const verdictClass = validation.valid ? (validation.warnings.length ? 'warn' : 'good') : 'bad';
      const verdictTitle = validation.valid ? 'Valid DKIM record' : 'Invalid DKIM record';

      let issuesHtml = '';
      validation.messages.forEach(msg => {
        issuesHtml += `<li class="issue bad"><span class="issue-word">Fail</span> ${escapeHtml(msg)}</li>`;
      });
      validation.warnings.forEach(warning => {
        issuesHtml += `<li class="issue warn"><span class="issue-word">Warning</span> ${escapeHtml(warning)}</li>`;
      });

      const dkimDomain = `${selector}._domainkey.${domain}`;

      // Format the full record with line breaks for better readability
      const formattedRecord = record.replace(/;/g, ';\n');

      recordsContainer.innerHTML = `
        <div class="verdict ${verdictClass}">
          <p class="title">${verdictTitle}</p>
          <p class="detail">DKIM record for <code>${escapeHtml(dkimDomain)}</code></p>
          ${issuesHtml ? `<ul class="issues">${issuesHtml}</ul>` : ''}
        </div>

        <dl class="record-meta">
          <div><dt>Selector</dt><dd>${escapeHtml(selector)}</dd></div>
          <div><dt>Domain</dt><dd>${escapeHtml(domain)}</dd></div>
        </dl>

        <h3 class="section-title">Tags</h3>
        <ul class="tag-list">
          ${tagsHtml}
        </ul>

        <h3 class="section-title">Full record</h3>
        <pre class="record-card">${escapeHtml(formattedRecord)}</pre>

        <p class="dns-lookup"><strong>DNS lookup:</strong> <code>${escapeHtml(dkimDomain)}</code> IN TXT</p>
      `;
    }

    // Escape HTML
    function escapeHtml(unsafe) {
      if (!unsafe) return '';
      return String(unsafe).replace(/[&<>"']/g, function(m) {
        if (m === '&') return '&amp;';
        if (m === '<') return '&lt;';
        if (m === '>') return '&gt;';
        if (m === '"') return '&quot;';
        return '&#39;';
      });
    }

    // Loading state
    function setLoading(isLoading) {
      checkBtn.disabled = isLoading;
      btnText.textContent = isLoading ? 'Checking' : 'Check DKIM';
      btnLoader.className = isLoading ? 'loader' : 'hidden';
    }

    // DKIM lookup function
    async function queryDKIM(domain, selector) {
      let cleanDomain = domain.trim().replace(/\.+$/, '');
      let cleanSelector = selector.trim().replace(/\.+$/, '');
      
      if (!cleanDomain) throw new Error('Please enter a domain');
      if (!cleanSelector) throw new Error('Please enter a selector');
      
      // Construct DKIM domain: selector._domainkey.domain.com
      const dkimDomain = `${cleanSelector}._domainkey.${cleanDomain}`;
      
      const url = `https://dns.google/resolve?name=${encodeURIComponent(dkimDomain)}&type=TXT`;
      
      const response = await fetch(url);
      if (!response.ok) throw new Error(`DNS query failed (HTTP ${response.status})`);
      
      const data = await response.json();
      
      if (data.Status === 3) {
        throw new Error(`No DKIM record found for "${dkimDomain}"`);
      } else if (data.Status !== 0) {
        const reason = data.Comment || `DNS error code ${data.Status}`;
        throw new Error(`DNS lookup error: ${reason}`);
      }
      
      const answers = data.Answer || [];
      // Find TXT records (type 16)
      const txtRecords = answers.filter(r => r.type === 16);
      
      if (txtRecords.length === 0) {
        throw new Error(`No TXT records found for "${dkimDomain}"`);
      }
      
      // Combine multiple strings if needed (DKIM records can be split)
      let fullRecord = '';
      txtRecords.forEach(r => {
        if (r.data) {
          // TXT data might be quoted, remove outer quotes
          let txt = r.data.replace(/^"|"$/g, '');
          fullRecord += txt;
        }
      });
      
      return {
        domain: cleanDomain,
        selector: cleanSelector,
        dkimDomain: dkimDomain,
        record: fullRecord,
        raw: txtRecords
      };
    }

    // Main lookup function
    async function performLookup() {
      const domain = domainInput.value.trim();
      const selector = selectorInput.value.trim();
      
      if (!domain || !selector) {
        setActiveView('error');
        errorContainer.innerHTML = `
          <div class="verdict bad error-message">
            <p class="title">Missing information</p>
            <p class="detail">Please enter both domain and selector</p>
          </div>
        `;
        return;
      }
      
      setLoading(true);
      try {
        const result = await queryDKIM(domain, selector);
        renderDKIMResult(result.domain, result.selector, result.record);
        setActiveView('records');
      } catch (err) {
        errorContainer.innerHTML = `
          <div class="verdict bad error-message">
            <p class="title">Error checking DKIM</p>
            <p class="detail">${escapeHtml(err.message)}</p>
          </div>
        `;
        setActiveView('error');
      } finally {
        setLoading(false);
      }
    }

    // Event listeners
    recordsContainer.addEventListener('click', (e) => {
      const btn = e.target.closest('.expand-key-btn');
      if (!btn) return;
      const tag = btn.closest('.tag');
      const open = btn.getAttribute('aria-expanded') !== 'true';
      tag.querySelector('[data-short]').classList.toggle('hidden', open);
      tag.querySelector('[data-full]').classList.toggle('hidden', !open);
      btn.setAttribute('aria-expanded', String(open));
      btn.textContent = open ? 'Hide full key' : 'Show full key';
    });

    checkBtn.addEventListener('click', performLookup);
    
    domainInput.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') performLookup();
    });
    
    selectorInput.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') performLookup();
    });

    // Handle URL parameters
    function handleUrlParameter() {
      const urlParams = new URLSearchParams(window.location.search);
      const domainParam = urlParams.get('domain');
      const selectorParam = urlParams.get('selector');
      
      if (domainParam) domainInput.value = domainParam;
      if (selectorParam) selectorInput.value = selectorParam;
      
      if (domainParam && selectorParam) {
        performLookup();
      }
    }

    window.addEventListener('load', handleUrlParameter);
  })();
