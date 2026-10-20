/\*\*  
 \* DMARCForensics Pro \- Web Application Orchestrator  
 \*/

(function () {  
  'use strict';

  // Embedded XML Presets for 100% Offline / Client-Side Execution  
  const PRESETS \= {  
    bank: \`\<?xml version="1.0" encoding="UTF-8" ?\>  
\<feedback xmlns="urn:ietf:params:xml:ns:dmarc-2.0"\>  
  \<report\_metadata\>  
    \<org\_name\>google.com\</org\_name\>  
    \<email\>noreply-dmarc-support@google.com\</email\>  
    \<extra\_contact\_info\>https\://support.google.com/a/answer/2466580\</extra\_contact\_info\>  
    \<report\_id\>apexfinbank\_google\_20260930\_001\</report\_id\>  
    \<date\_range\>  
      \<begin\>1790726400\</begin\>  
      \<end\>1790812800\</end\>  
    \</date\_range\>  
  \</report\_metadata\>  
  \<policy\_published\>  
    \<domain\>apexfinbank.com\</domain\>  
    \<adkim\>r\</adkim\>  
    \<aspf\>r\</aspf\>  
    \<p\>reject\</p\>  
    \<sp\>reject\</sp\>  
    \<pct\>100\</pct\>  
    \<fo\>1\</fo\>  
  \</policy\_published\>  
  \<record\>  
    \<row\>  
      \<source\_ip\>209.85.220.41\</source\_ip\>  
      \<count\>15400\</count\>  
      \<policy\_evaluated\>  
        \<disposition\>none\</disposition\>  
        \<dkim\>pass\</dkim\>  
        \<spf\>pass\</spf\>  
      \</policy\_evaluated\>  
    \</row\>  
    \<identifiers\>  
      \<header\_from\>apexfinbank.com\</header\_from\>  
    \</identifiers\>  
    \<auth\_results\>  
      \<dkim\>  
        \<domain\>apexfinbank.com\</domain\>  
        \<result\>pass\</result\>  
        \<selector\>google\</selector\>  
      \</dkim\>  
      \<spf\>  
        \<domain\>apexfinbank.com\</domain\>  
        \<result\>pass\</result\>  
        \<scope\>mfrom\</scope\>  
      \</spf\>  
    \</auth\_results\>  
  \</record\>  
  \<record\>  
    \<row\>  
      \<source\_ip\>167.89.10.22\</source\_ip\>  
      \<count\>4200\</count\>  
      \<policy\_evaluated\>  
        \<disposition\>none\</disposition\>  
        \<dkim\>pass\</dkim\>  
        \<spf\>pass\</spf\>  
      \</policy\_evaluated\>  
    \</row\>  
    \<identifiers\>  
      \<header\_from\>apexfinbank.com\</header\_from\>  
    \</identifiers\>  
    \<auth\_results\>  
      \<dkim\>  
        \<domain\>apexfinbank.com\</domain\>  
        \<result\>pass\</result\>  
        \<selector\>s1\</selector\>  
      \</dkim\>  
      \<spf\>  
        \<domain\>em.apexfinbank.com\</domain\>  
        \<result\>pass\</result\>  
        \<scope\>mfrom\</scope\>  
      \</spf\>  
    \</auth\_results\>  
  \</record\>  
  \<record\>  
    \<row\>  
      \<source\_ip\>185.220.101.5\</source\_ip\>  
      \<count\>180\</count\>  
      \<policy\_evaluated\>  
        \<disposition\>reject\</disposition\>  
        \<dkim\>fail\</dkim\>  
        \<spf\>fail\</spf\>  
      \</policy\_evaluated\>  
    \</row\>  
    \<identifiers\>  
      \<header\_from\>apexfinbank.com\</header\_from\>  
    \</identifiers\>  
    \<auth\_results\>  
      \<spf\>  
        \<domain\>malicious-botnet.ru\</domain\>  
        \<result\>fail\</result\>  
        \<scope\>mfrom\</scope\>  
      \</spf\>  
    \</auth\_results\>  
  \</record\>  
\</feedback\>\`,  
    saas: \`\<?xml version="1.0" encoding="UTF-8" ?\>  
\<feedback xmlns="urn:ietf:params:xml:ns:dmarc-2.0"\>  
  \<report\_metadata\>  
    \<org\_name\>Microsoft 365 Enterprise Protection\</org\_name\>  
    \<email\>dmarcreporting@microsoft.com\</email\>  
    \<report\_id\>cloudpulse\_m365\_20260930\_092\</report\_id\>  
    \<date\_range\>  
      \<begin\>1790726400\</begin\>  
      \<end\>1790812800\</end\>  
    \</date\_range\>  
  \</report\_metadata\>  
  \<policy\_published\>  
    \<domain\>cloudpulse.io\</domain\>  
    \<adkim\>r\</adkim\>  
    \<aspf\>r\</aspf\>  
    \<p\>quarantine\</p\>  
    \<sp\>quarantine\</sp\>  
    \<pct\>100\</pct\>  
  \</policy\_published\>  
  \<record\>  
    \<row\>  
      \<source\_ip\>40.107.94.101\</source\_ip\>  
      \<count\>8500\</count\>  
      \<policy\_evaluated\>  
        \<disposition\>none\</disposition\>  
        \<dkim\>pass\</dkim\>  
        \<spf\>pass\</spf\>  
      \</policy\_evaluated\>  
    \</row\>  
    \<identifiers\>  
      \<header\_from\>cloudpulse.io\</header\_from\>  
    \</identifiers\>  
    \<auth\_results\>  
      \<dkim\>  
        \<domain\>cloudpulse.io\</domain\>  
        \<result\>pass\</result\>  
        \<selector\>selector1\</selector\>  
      \</dkim\>  
      \<spf\>  
        \<domain\>cloudpulse.io\</domain\>  
        \<result\>pass\</result\>  
      \</spf\>  
    \</auth\_results\>  
  \</record\>  
  \<record\>  
    \<row\>  
      \<source\_ip\>54.240.27.18\</source\_ip\>  
      \<count\>1200\</count\>  
      \<policy\_evaluated\>  
        \<disposition\>quarantine\</disposition\>  
        \<dkim\>fail\</dkim\>  
        \<spf\>pass\</spf\>  
      \</policy\_evaluated\>  
    \</row\>  
    \<identifiers\>  
      \<header\_from\>cloudpulse.io\</header\_from\>  
    \</identifiers\>  
    \<auth\_results\>  
      \<spf\>  
        \<domain\>amazonses.com\</domain\>  
        \<result\>pass\</result\>  
      \</spf\>  
    \</auth\_results\>  
  \</record\>  
\</feedback\>\`,  
    legacy: \`\<?xml version="1.0" encoding="UTF-8" ?\>  
\<feedback xmlns="urn:ietf:params:xml:ns:dmarc-2.0"\>  
  \<report\_metadata\>  
    \<org\_name\>Yahoo\! Postmaster\</org\_name\>  
    \<email\>postmaster@yahoo.com\</email\>  
    \<report\_id\>legacycorp\_yahoo\_20260930\_664\</report\_id\>  
    \<date\_range\>  
      \<begin\>1790726400\</begin\>  
      \<end\>1790812800\</end\>  
    \</date\_range\>  
  \</report\_metadata\>  
  \<policy\_published\>  
    \<domain\>legacycorp.com\</domain\>  
    \<adkim\>r\</adkim\>  
    \<aspf\>r\</aspf\>  
    \<p\>none\</p\>  
    \<sp\>none\</sp\>  
    \<pct\>100\</pct\>  
  \</policy\_published\>  
  \<record\>  
    \<row\>  
      \<source\_ip\>198.51.100.44\</source\_ip\>  
      \<count\>2500\</count\>  
      \<policy\_evaluated\>  
        \<disposition\>none\</disposition\>  
        \<dkim\>pass\</dkim\>  
        \<spf\>pass\</spf\>  
      \</policy\_evaluated\>  
    \</row\>  
    \<identifiers\>  
      \<header\_from\>legacycorp.com\</header\_from\>  
    \</identifiers\>  
    \<auth\_results\>  
      \<spf\>  
        \<domain\>legacycorp.com\</domain\>  
        \<result\>pass\</result\>  
      \</spf\>  
    \</auth\_results\>  
  \</record\>  
  \<record\>  
    \<row\>  
      \<source\_ip\>194.26.29.112\</source\_ip\>  
      \<count\>3800\</count\>  
      \<policy\_evaluated\>  
        \<disposition\>none\</disposition\>  
        \<dkim\>fail\</dkim\>  
        \<spf\>fail\</spf\>  
      \</policy\_evaluated\>  
    \</row\>  
    \<identifiers\>  
      \<header\_from\>legacycorp.com\</header\_from\>  
    \</identifiers\>  
    \<auth\_results\>  
      \<spf\>  
        \<domain\>bulletproof-spoofer.cc\</domain\>  
        \<result\>fail\</result\>  
      \</spf\>  
    \</auth\_results\>  
  \</record\>  
\</feedback\>\`  
  };

  let currentParsedReport \= null;  
  let activeSynthTarget \= 'cloudflare';  
  let activeSimScenario \= 'phishing';

  // DOM Elements  
  const presetSelector \= document.getElementById('presetSelector');  
  const configInput \= document.getElementById('configInput');  
  const btnAudit \= document.getElementById('btnAudit');  
  const btnReset \= document.getElementById('btnReset');  
  const inspDomain \= document.getElementById('inspDomain');  
  const inspVolume \= document.getElementById('inspVolume');  
  const inspBlocked \= document.getElementById('inspBlocked');  
  const inspReporter \= document.getElementById('inspReporter');  
  const gradeBadge \= document.getElementById('gradeBadge');  
  const scoreText \= document.getElementById('scoreText');  
  const gradeSummary \= document.getElementById('gradeSummary');  
  const scoreSummaryTag \= document.getElementById('scoreSummaryTag');  
  const checksContainer \= document.getElementById('checksContainer');  
  const btnSimPhishing \= document.getElementById('btnSimPhishing');  
  const btnSimDeliverability \= document.getElementById('btnSimDeliverability');  
  const simUnhardenedSummary \= document.getElementById('simUnhardenedSummary');  
  const simHardenedSummary \= document.getElementById('simHardenedSummary');  
  const simUnhardenedTimeline \= document.getElementById('simUnhardenedTimeline');  
  const simHardenedTimeline \= document.getElementById('simHardenedTimeline');  
  const codeOutput \= document.getElementById('codeOutput');  
  const btnCopyCode \= document.getElementById('btnCopyCode');

  function loadPreset(key) {  
    const xml \= PRESETS\[key\] || PRESETS.bank;  
    configInput.value \= xml.trim();  
    runAnalysis();  
  }

  function runAnalysis() {  
    let parsed;  
    try {  
      parsed \= window.DMARCEngine.parseDmarcXml(configInput.value);  
      currentParsedReport \= parsed;  
    } catch (e) {  
      alert('DMARC XML Parsing Error: ' \+ e.message);  
      return;  
    }

    const result \= window.DMARCAuditor.auditDmarcReport(parsed);

    // Update Inspector Pills  
    inspDomain.textContent \= \`\${parsed.policy.domain} (p=\${parsed.policy.policy})\`;  
    inspVolume.textContent \= \`\${parsed.metrics.totalVolume.toLocaleString()} msgs (\${parsed.metrics.passPercentage}% Pass)\`;  
    inspVolume.style.color \= parsed.metrics.passPercentage \>= 90 ? 'var(--accent-emerald)' : 'var(--accent-amber)';

    const blockedTotal \= parsed.metrics.rejectVolume \+ parsed.metrics.quarantineVolume;  
    inspBlocked.textContent \= \`\${blockedTotal.toLocaleString()} Blocked (\${parsed.metrics.rejectVolume} Rejected)\`;  
    inspBlocked.style.color \= blockedTotal \> 0 || parsed.metrics.failVolume \=== 0 ? 'var(--accent-emerald)' : 'var(--accent-rose)';

    inspReporter.textContent \= parsed.metadata.orgName;

    // Update Scorecard  
    scoreText.textContent \= \`\${result.overallScore} / 100 Points\`;  
    gradeBadge.textContent \= result.grade;  
    gradeBadge.className \= 'grade-circle';  
    if (result.grade \=== 'F' || result.grade \=== 'D') {  
      gradeBadge.classList.add('grade-f');  
    } else if (result.grade \=== 'B' || result.grade \=== 'C') {  
      gradeBadge.classList.add('grade-b');  
    } else if (result.grade \=== 'A+' || result.grade \=== 'A') {  
      gradeBadge.classList.add('grade-a');  
    }

    scoreSummaryTag.textContent \= \`\${result.summary.passed} Passed • \${result.summary.warnings} Warnings • \${result.summary.failures} Failures\`;  
    gradeSummary.textContent \= \`\${result.grade \=== 'A+' ? 'Zero-Trust Enforced' : 'Analysis Complete'} • \${result.summary.failures} Spoofing Vulnerabilities\`;

    // Render Checks  
    checksContainer.innerHTML \= '';  
    result.checks.forEach(function (c) {  
      const item \= document.createElement('div');  
      item.className \= 'check-item';

      const badgeClass \=  
        c.status \=== 'PASS'  
          ? 'badge-pass'  
          : c.status \=== 'WARN'  
          ? 'badge-warn'  
          : c.status \=== 'FAIL'  
          ? 'badge-fail'  
          : 'badge-info';

      item.innerHTML \= \`  
        \<div class="check-header"\>  
          \<span class="check-name"\>\${c.title}\</span\>  
          \<span class="badge \${badgeClass}"\>\${c.status} (\${c.score}/\${c.weight})\</span\>  
        \</div\>  
        \<div class="check-desc"\>\${c.details}\</div\>  
        \${c.remediation ? \`\<div class="check-remediation"\>Remediation: \${c.remediation}\</div\>\` : ''}  
      \`;  
      checksContainer.appendChild(item);  
    });

    renderSimulation();  
    renderSynthesizer();  
  }

  function renderSimulation() {  
    if (activeSimScenario \=== 'phishing') {  
      const unhardened \= window.DMARCSimulator.simulatePhishingAttack({ policy: 'none' });  
      const hardened \= window.DMARCSimulator.simulatePhishingAttack({ policy: 'reject' });

      simUnhardenedSummary.textContent \= unhardened.verdict;  
      simHardenedSummary.textContent \= hardened.verdict;

      simUnhardenedTimeline.innerHTML \= unhardened.steps.map(s \=\> \`  
        \<div class="timeline-step \${s.isBreach ? 'step-outage' : ''}"\>  
          \<strong\>\${s.phase}\</strong\>: \${s.description}  
          \<div style="font-size: 11px; margin-top: 2px; color: \${s.isBreach ? 'var(--accent-rose)' : 'var(--accent-emerald)'};"\>  
            \${s.trafficRoute}  
          \</div\>  
        \</div\>  
      \`).join('');

      simHardenedTimeline.innerHTML \= hardened.steps.map(s \=\> \`  
        \<div class="timeline-step"\>  
          \<strong\>\${s.phase}\</strong\>: \${s.description}  
          \<div style="font-size: 11px; margin-top: 2px; color: var(--accent-emerald);"\>  
            \${s.trafficRoute}  
          \</div\>  
        \</div\>  
      \`).join('');  
    } else {  
      const unhardened \= window.DMARCSimulator.simulateSaaSDeliverability({ isAligned: false });  
      const hardened \= window.DMARCSimulator.simulateSaaSDeliverability({ isAligned: true });

      simUnhardenedSummary.textContent \= unhardened.verdict;  
      simHardenedSummary.textContent \= hardened.verdict;

      simUnhardenedTimeline.innerHTML \= unhardened.steps.map(s \=\> \`  
        \<div class="timeline-step \${s.isOutage ? 'step-outage' : ''}"\>  
          \<strong\>\${s.phase}\</strong\>: \${s.description}  
          \<div style="font-size: 11px; margin-top: 2px; color: \${s.isOutage ? 'var(--accent-rose)' : 'var(--accent-emerald)'};"\>  
            \${s.routeDetails}  
          \</div\>  
        \</div\>  
      \`).join('');

      simHardenedTimeline.innerHTML \= hardened.steps.map(s \=\> \`  
        \<div class="timeline-step"\>  
          \<strong\>\${s.phase}\</strong\>: \${s.description}  
          \<div style="font-size: 11px; margin-top: 2px; color: var(--accent-emerald);"\>  
            \${s.routeDetails}  
          \</div\>  
        \</div\>  
      \`).join('');  
    }  
  }

  function renderSynthesizer() {  
    if (\!currentParsedReport) return;  
    const synth \= window.DNSSynthesizer;  
    const domain \= currentParsedReport.policy.domain || 'yourcompany.com';  
    let code \= '';  
    if (activeSynthTarget \=== 'cloudflare') {  
      code \= synth.generateCloudflareRecords(domain, 'reject');  
    } else if (activeSynthTarget \=== 'route53') {  
      code \= synth.generateRoute53Json(domain, 'reject');  
    } else if (activeSynthTarget \=== 'bind') {  
      code \= synth.generateBindZonefile(domain, 'reject');  
    } else if (activeSynthTarget \=== 'terraform') {  
      code \= synth.generateTerraformHcl(domain, 'reject');  
    }  
    codeOutput.textContent \= code;  
  }

  // Event Listeners  
  presetSelector.addEventListener('change', function () {  
    loadPreset(this.value);  
  });

  btnAudit.addEventListener('click', runAnalysis);

  btnReset.addEventListener('click', function () {  
    loadPreset(presetSelector.value);  
  });

  btnSimPhishing.addEventListener('click', function () {  
    activeSimScenario \= 'phishing';  
    btnSimPhishing.classList.add('active');  
    btnSimDeliverability.classList.remove('active');  
    renderSimulation();  
  });

  btnSimDeliverability.addEventListener('click', function () {  
    activeSimScenario \= 'deliverability';  
    btnSimDeliverability.classList.add('active');  
    btnSimPhishing.classList.remove('active');  
    renderSimulation();  
  });

  document.querySelectorAll('.synth-tabs button').forEach(function (btn) {  
    btn.addEventListener('click', function () {  
      document.querySelectorAll('.synth-tabs button').forEach(b \=\> b.classList.remove('active'));  
      btn.classList.add('active');  
      activeSynthTarget \= btn.getAttribute('data-target');  
      renderSynthesizer();  
    });  
  });

  btnCopyCode.addEventListener('click', function () {  
    navigator.clipboard.writeText(codeOutput.textContent).then(function () {  
      const originalText \= btnCopyCode.textContent;  
      btnCopyCode.textContent \= 'Copied\!';  
      setTimeout(function () {  
        btnCopyCode.textContent \= originalText;  
      }, 1800);  
    });  
  });

  // Initial Load  
  loadPreset('bank');  
})();  
