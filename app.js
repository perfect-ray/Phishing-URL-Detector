(function () {
  const form = document.getElementById('scan-form');
  const input = document.getElementById('url-input');
  const btn = document.getElementById('scan-btn');
  const btnLabel = btn.querySelector('.btn-label');

  const resultZone = document.getElementById('result-zone');
  const radarPanel = document.getElementById('radar-panel');
  const verdictPanel = document.getElementById('verdict-panel');
  const signalsPanel = document.getElementById('signals-panel');
  const errorPanel = document.getElementById('error-panel');
  const errorText = document.getElementById('error-text');

  const verdictLabel = document.getElementById('verdict-label');
  const verdictConfidence = document.getElementById('verdict-confidence');
  const gaugeNeedle = document.getElementById('gauge-needle');
  const metaUrl = document.getElementById('meta-url');
  const metaDomain = document.getElementById('meta-domain');
  const metaTld = document.getElementById('meta-tld');
  const signalLog = document.getElementById('signal-log');

  const historySection = document.getElementById('history-section');
  const historyLog = document.getElementById('history-log');

  const enrichLoadingPanel = document.getElementById('enrich-loading-panel');
  const enrichLoadingText = document.getElementById('enrich-loading-text');
  const holisticPanel = document.getElementById('holistic-panel');
  const holisticLabel = document.getElementById('holistic-label');
  const holisticScore = document.getElementById('holistic-score');
  const holisticOverride = document.getElementById('holistic-override');
  const holisticBars = document.getElementById('holistic-bars');
  const vtPanel = document.getElementById('vt-panel');
  const vtBody = document.getElementById('vt-body');
  const whoisPanel = document.getElementById('whois-panel');
  const whoisBody = document.getElementById('whois-body');
  const dnsPanel = document.getElementById('dns-panel');
  const dnsBody = document.getElementById('dns-body');

  const MIN_SCAN_MS = 900;

  function resetPanels() {
    resultZone.hidden = false;
    radarPanel.hidden = false;
    verdictPanel.hidden = true;
    signalsPanel.hidden = true;
    errorPanel.hidden = true;
    enrichLoadingPanel.hidden = true;
    holisticPanel.hidden = true;
    vtPanel.hidden = true;
    whoisPanel.hidden = true;
    dnsPanel.hidden = true;
  }

  function showError(message) {
    radarPanel.hidden = true;
    verdictPanel.hidden = true;
    signalsPanel.hidden = true;
    errorPanel.hidden = false;
    errorText.textContent = message;
  }

  function setNeedle(riskPct) {
    // riskPct 0..100 maps to -85deg (safe/left) .. 85deg (danger/right)
    const angle = -85 + (riskPct / 100) * 170;
    gaugeNeedle.style.transform = `rotate(${angle}deg)`;
  }

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function renderVerdict(data) {
    const isLegit = data.label === 'legitimate';
    verdictLabel.textContent = isLegit ? 'LEGITIMATE' : 'PHISHING DETECTED';
    verdictLabel.className = 'verdict-label ' + (isLegit ? 'legit' : 'phish');

    const confidencePct = isLegit ? data.probability_legitimate : data.probability_phishing;
    verdictConfidence.textContent = `${confidencePct}% confidence`;

    setNeedle(data.probability_phishing);

    metaUrl.textContent = data.url;
    metaDomain.textContent = data.domain || '—';
    metaTld.textContent = data.tld ? '.' + data.tld : '—';

    signalLog.innerHTML = '';
    data.signals.forEach((sig) => {
      const li = document.createElement('li');
      const flag = document.createElement('span');
      flag.className = 'signal-flag ' + (sig.risky ? 'risk' : 'ok');
      flag.textContent = sig.risky ? '!' : '✓';
      const label = document.createElement('span');
      label.className = 'signal-label';
      label.textContent = sig.label;
      const value = document.createElement('span');
      value.className = 'signal-value';
      value.textContent = sig.value;
      li.appendChild(flag);
      li.appendChild(label);
      li.appendChild(value);
      signalLog.appendChild(li);
    });

    radarPanel.hidden = true;
    verdictPanel.hidden = false;
    signalsPanel.hidden = false;

    addHistoryEntry(data);
  }

  function addHistoryEntry(data) {
    historySection.hidden = false;
    const li = document.createElement('li');
    const isLegit = data.label === 'legitimate';

    const dot = document.createElement('span');
    dot.className = 'history-dot ' + (isLegit ? 'legit' : 'phish');

    const url = document.createElement('span');
    url.className = 'history-url';
    url.textContent = data.url;

    const pct = document.createElement('span');
    pct.className = 'history-pct';
    pct.textContent = isLegit
      ? `${data.probability_legitimate}% legit`
      : `${data.probability_phishing}% phishing`;

    li.appendChild(dot);
    li.appendChild(url);
    li.appendChild(pct);
    historyLog.prepend(li);

    while (historyLog.children.length > 6) {
      historyLog.removeChild(historyLog.lastChild);
    }
  }

  // ------------------------------------------------------------ VirusTotal

  function renderVT(vt) {
    vtBody.innerHTML = '';
    vtPanel.hidden = false;

    if (!vt || !vt.available) {
      const reason = (vt && vt.reason) || 'unavailable';
      const messages = {
        no_api_key: "No VirusTotal API key configured. Add VIRUSTOTAL_API_KEY to your .env file to enable this.",
        invalid_api_key: "The configured VirusTotal API key was rejected.",
        rate_limited: "VirusTotal rate limit hit — try again in a minute.",
        network_error: "Couldn't reach VirusTotal from this server.",
      };
      const p = el('p', 'enrich-muted', messages[reason] || `VirusTotal check unavailable (${reason}).`);
      vtBody.appendChild(p);
      return;
    }

    if (vt.status === 'pending') {
      const p = el('p', 'enrich-muted', vt.message || 'Still analyzing this URL.');
      vtBody.appendChild(p);
      if (vt.permalink) {
        const a = el('a', 'enrich-link', 'Check progress on VirusTotal ↗');
        a.href = vt.permalink;
        a.target = '_blank';
        a.rel = 'noopener noreferrer';
        vtBody.appendChild(a);
      }
      return;
    }

    const flagged = vt.flagged || 0;
    const total = vt.total_engines || 0;
    const tone = flagged === 0 ? 'ok' : flagged <= 2 ? 'warn' : 'risk';

    const row = el('div', 'vt-summary');
    const ratio = el('div', `vt-ratio ${tone}`, `${flagged} / ${total}`);
    const label = el('div', 'vt-ratio-label', 'security vendors flagged this URL');
    row.appendChild(ratio);
    row.appendChild(label);
    vtBody.appendChild(row);

    const bar = el('div', 'vt-bar');
    const segments = [
      ['malicious', vt.malicious, 'var(--accent-red)'],
      ['suspicious', vt.suspicious, 'var(--accent-amber)'],
      ['harmless', vt.harmless, 'var(--accent-green)'],
      ['undetected', vt.undetected, 'var(--line)'],
    ];
    segments.forEach(([name, count, color]) => {
      if (!count) return;
      const seg = el('span', 'vt-bar-seg');
      seg.style.width = `${(count / Math.max(total, 1)) * 100}%`;
      seg.style.background = color;
      seg.title = `${name}: ${count}`;
      bar.appendChild(seg);
    });
    vtBody.appendChild(bar);

    const stats = el('div', 'vt-stats');
    stats.appendChild(el('span', null, `malicious: ${vt.malicious}`));
    stats.appendChild(el('span', null, `suspicious: ${vt.suspicious}`));
    stats.appendChild(el('span', null, `harmless: ${vt.harmless}`));
    stats.appendChild(el('span', null, `undetected: ${vt.undetected}`));
    vtBody.appendChild(stats);

    if (vt.permalink) {
      const a = el('a', 'enrich-link', 'View full report on VirusTotal ↗');
      a.href = vt.permalink;
      a.target = '_blank';
      a.rel = 'noopener noreferrer';
      vtBody.appendChild(a);
    }
  }

  // ----------------------------------------------------------------- WHOIS

  function formatDate(iso) {
    if (!iso) return '—';
    try {
      return new Date(iso).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
    } catch (e) {
      return iso;
    }
  }

  function formatAge(days) {
    if (days === null || days === undefined) return null;
    if (days < 0) return null;
    if (days < 30) return `${days} day${days === 1 ? '' : 's'} old`;
    if (days < 365) {
      const months = Math.floor(days / 30);
      return `~${months} month${months === 1 ? '' : 's'} old`;
    }
    const years = Math.floor(days / 365);
    return `~${years} year${years === 1 ? '' : 's'} old`;
  }

  function renderWhois(whois) {
    whoisBody.innerHTML = '';
    whoisPanel.hidden = false;

    if (!whois || !whois.available) {
      const reason = (whois && whois.reason) || 'unavailable';
      const messages = {
        lookup_failed: "WHOIS lookup failed or timed out for this domain.",
        no_data: "No WHOIS record found for this domain.",
      };
      whoisBody.appendChild(el('p', 'enrich-muted', messages[reason] || `WHOIS unavailable (${reason}).`));
      return;
    }

    const age = formatAge(whois.domain_age_days);
    if (age) {
      const isYoung = whois.domain_age_days < 30;
      const badge = el('div', 'age-badge ' + (isYoung ? 'risk' : 'ok'), `Registered ${age}`);
      whoisBody.appendChild(badge);
    }

    const rows = [
      ['registrar', whois.registrar],
      ['created', formatDate(whois.creation_date)],
      ['expires', formatDate(whois.expiration_date)],
      ['updated', formatDate(whois.updated_date)],
      ['org', whois.org],
      ['country', whois.country],
    ];
    rows.forEach(([key, val]) => {
      if (!val) return;
      const row = el('div', 'meta-row');
      row.appendChild(el('span', 'meta-key', key));
      row.appendChild(el('span', 'meta-val', String(val)));
      whoisBody.appendChild(row);
    });

    if (whois.name_servers && whois.name_servers.length) {
      const nsRow = el('div', 'chip-row');
      whois.name_servers.forEach((ns) => nsRow.appendChild(el('span', 'chip', ns)));
      whoisBody.appendChild(el('p', 'enrich-subhead', 'name servers'));
      whoisBody.appendChild(nsRow);
    }
  }

  // ------------------------------------------------------------------- DNS

  function renderDns(dns) {
    dnsBody.innerHTML = '';
    dnsPanel.hidden = false;

    if (!dns || !dns.available) {
      dnsBody.appendChild(el('p', 'enrich-muted', 'DNS lookup unavailable.'));
      return;
    }

    if (!dns.resolves) {
      dnsBody.appendChild(el('p', 'enrich-muted risk-text', "This domain doesn't resolve to anything right now."));
      return;
    }

    const order = ['A', 'AAAA', 'MX', 'NS', 'TXT'];
    order.forEach((rtype) => {
      const values = (dns.records && dns.records[rtype]) || [];
      if (!values.length) return;
      dnsBody.appendChild(el('p', 'enrich-subhead', rtype));
      const row = el('div', 'chip-row');
      values.slice(0, 6).forEach((v) => row.appendChild(el('span', 'chip mono', v)));
      dnsBody.appendChild(row);
    });
  }

  // ------------------------------------------------------------ holistic

  const SOURCE_LABELS = {
    ml: 'ML model',
    virustotal: 'VirusTotal',
    whois: 'WHOIS (domain age)',
    dns: 'DNS',
  };

  function renderHolistic(holistic) {
    if (!holistic) return;
    holisticPanel.hidden = false;

    const isLegit = holistic.label === 'legitimate';
    holisticLabel.textContent = isLegit ? 'LEGITIMATE' : 'PHISHING';
    holisticLabel.className = 'holistic-label ' + (isLegit ? 'legit' : 'phish');
    holisticScore.textContent = `${holistic.confidence}% confidence`;

    if (holistic.overrides && holistic.overrides.length) {
      holisticOverride.hidden = false;
      holisticOverride.textContent = '⚠ ' + holistic.overrides.join(' · ');
    } else {
      holisticOverride.hidden = true;
    }

    holisticBars.innerHTML = '';
    (holistic.breakdown || []).forEach((b) => {
      const row = el('div', 'holistic-bar-row');
      const label = el('span', 'holistic-bar-label', SOURCE_LABELS[b.source] || b.source);
      row.appendChild(label);

      const track = el('div', 'holistic-bar-track');
      if (b.available) {
        const fill = el('div', 'holistic-bar-fill');
        const pct = Math.round(b.risk * 100);
        fill.style.width = `${pct}%`;
        fill.classList.add(pct >= 50 ? 'risk' : 'ok');
        track.appendChild(fill);
      } else {
        track.classList.add('unavailable');
      }
      row.appendChild(track);

      const weight = el(
        'span',
        'holistic-bar-weight',
        b.available ? `${Math.round(b.weight * 100)}% weight` : 'n/a'
      );
      row.appendChild(weight);

      holisticBars.appendChild(row);
    });
  }

  // -------------------------------------------------------------- enrich

  async function enrichUrl(url) {
    enrichLoadingPanel.hidden = false;
    enrichLoadingText.textContent = 'Checking VirusTotal, WHOIS & DNS…';

    try {
      const res = await fetch('/api/enrich', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url }),
      });
      const data = await res.json();
      enrichLoadingPanel.hidden = true;

      if (!res.ok) {
        return;
      }
      renderHolistic(data.holistic);
      renderVT(data.virustotal);
      renderWhois(data.whois);
      renderDns(data.dns);
    } catch (err) {
      enrichLoadingPanel.hidden = true;
    }
  }

  // ---------------------------------------------------------------- scan

  async function scan(url) {
    resetPanels();
    btn.disabled = true;
    btnLabel.textContent = 'Scanning…';

    const started = Date.now();

    try {
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url }),
      });
      const data = await res.json();

      const elapsed = Date.now() - started;
      const wait = Math.max(0, MIN_SCAN_MS - elapsed);
      await new Promise((r) => setTimeout(r, wait));

      if (!res.ok) {
        showError(data.error || 'Could not analyze that URL.');
        return;
      }
      renderVerdict(data);
      enrichUrl(url); // fire and forget -- doesn't block the button/UI below
    } catch (err) {
      showError('Network error — is the PhishGuard server running?');
    } finally {
      btn.disabled = false;
      btnLabel.textContent = 'Scan';
    }
  }

  form.addEventListener('submit', (e) => {
    e.preventDefault();
    const url = input.value.trim();
    if (!url) return;
    scan(url);
  });
})();
