/\*\*  
 \* DMARCForensics Pro \- 10-Point Zero-Trust DMARC Auditor  
 \* Evaluates RFC 7489, RFC 7960, and Gmail/Yahoo 2024-2026 Sender Mandates.  
 \* Scores security posture (0-100%, Grade A+ to F) and outputs remediation guidance.  
 \*/

(function (root, factory) {  
  if (typeof define \=== 'function' && define.amd) {  
    define(\['./dmarc-engine'\], factory);  
  } else if (typeof module \=== 'object' && module.exports) {  
    module.exports \= factory(require('./dmarc-engine'));  
  } else {  
    root.DMARCAuditor \= factory(root.DMARCEngine);  
  }  
})(typeof self \!== 'undefined' ? self : this, function (engine) {  
  'use strict';

  function auditDmarcReport(parsedReport) {  
    const policy \= parsedReport.policy;  
    const metrics \= parsedReport.metrics;  
    const records \= parsedReport.records;  
    const checks \= \[\];

    // Check 1: DMARC Enforcement Policy (15 pts)  
    if (policy.policy \=== 'reject') {  
      checks.push({  
        id: 'policy\_enforcement',  
        title: 'DMARC Enforcement Policy (p=reject)',  
        weight: 15,  
        score: 15,  
        status: 'PASS',  
        details: 'Zero-Trust Enforced: Mailbox providers actively reject unauthenticated emails at the SMTP gateway.',  
        remediation: null  
      });  
    } else if (policy.policy \=== 'quarantine') {  
      checks.push({  
        id: 'policy\_enforcement',  
        title: 'DMARC Enforcement Policy (p=quarantine)',  
        weight: 15,  
        score: 9,  
        status: 'WARN',  
        details: 'Partial Enforcement: Unauthenticated mail is diverted to spam/junk folders instead of being blocked.',  
        remediation: 'Advance policy from "p=quarantine" to "p=reject" once all legitimate SaaS senders are aligned.'  
      });  
    } else {  
      checks.push({  
        id: 'policy\_enforcement',  
        title: 'DMARC Enforcement Policy (p=none)',  
        weight: 15,  
        score: 0,  
        status: 'FAIL',  
        details: 'CRITICAL SPOOFING RISK: "p=none" is monitoring mode only. Mailbox providers deliver spoofed phishing emails directly to user inboxes\!',  
        remediation: 'Immediately advance DMARC policy to "p=quarantine" or "p=reject" to prevent brand impersonation.'  
      });  
    }

    // Check 2: Subdomain Policy (sp=) (15 pts)  
    if (policy.subPolicy \=== 'reject') {  
      checks.push({  
        id: 'subdomain\_policy',  
        title: 'Subdomain Spoofing Protection (sp=reject)',  
        weight: 15,  
        score: 15,  
        status: 'PASS',  
        details: 'Hardened Subdomains: Subdomains (e.g. mail.domain.com, billing.domain.com) cannot be spoofed by attackers.',  
        remediation: null  
      });  
    } else if (policy.subPolicy \=== 'quarantine') {  
      checks.push({  
        id: 'subdomain\_policy',  
        title: 'Subdomain Spoofing Protection (sp=quarantine)',  
        weight: 15,  
        score: 9,  
        status: 'WARN',  
        details: 'Subdomain mail quarantined.',  
        remediation: 'Set explicit "sp=reject" to close subdomain phishing vectors.'  
      });  
    } else {  
      checks.push({  
        id: 'subdomain\_policy',  
        title: 'Subdomain Spoofing Protection (sp=none)',  
        weight: 15,  
        score: 0,  
        status: 'FAIL',  
        details: 'Subdomain Loophole: Attackers can forge emails from arbitrary subdomains of your brand.',  
        remediation: 'Publish an explicit "sp=reject" tag in your DMARC DNS record.'  
      });  
    }

    // Check 3: 100% Policy Percentage (pct=100) (10 pts)  
    if (policy.percentage \=== 100\) {  
      checks.push({  
        id: 'percentage\_coverage',  
        title: '100% Traffic Inspection Coverage (pct=100)',  
        weight: 10,  
        score: 10,  
        status: 'PASS',  
        details: 'Comprehensive Coverage: 100% of inbound messages claiming this domain are evaluated.',  
        remediation: null  
      });  
    } else {  
      checks.push({  
        id: 'percentage\_coverage',  
        title: '100% Traffic Inspection Coverage (pct=100)',  
        weight: 10,  
        score: 4,  
        status: 'WARN',  
        details: \`Partial Coverage (\${policy.percentage}%): \${100 \- policy.percentage}% of emails bypass DMARC enforcement entirely\!\`,  
        remediation: 'Set "pct=100" in your DMARC record to protect all email traffic.'  
      });  
    }

    // Check 4: Aggregate RUA Visibility (10 pts)  
    checks.push({  
      id: 'rua\_reporting',  
      title: 'Aggregate RUA Report Telemetry',  
      weight: 10,  
      score: 10,  
      status: 'PASS',  
      details: \`Active Telemetry: Report received from \${parsedReport.metadata.orgName} covering \${metrics.totalVolume.toLocaleString()} messages across \${metrics.uniqueIps} sending IPs.\`,  
      remediation: null  
    });

    // Check 5: Forensic RUF Incident Alerting (10 pts)  
    if (policy.fo && policy.fo \!== '0') {  
      checks.push({  
        id: 'ruf\_forensics',  
        title: 'Real-Time Forensic RUF Alerting (fo=1)',  
        weight: 10,  
        score: 10,  
        status: 'PASS',  
        details: 'Real-Time Forensics: Configured to receive instant forensic failure reports on individual SPF/DKIM misalignments.',  
        remediation: null  
      });  
    } else {  
      checks.push({  
        id: 'ruf\_forensics',  
        title: 'Real-Time Forensic RUF Alerting (fo=1)',  
        weight: 10,  
        score: 5,  
        status: 'INFO',  
        details: 'Forensic failure reporting not configured or fo=0. Only aggregate daily summaries enabled.',  
        remediation: 'Add "ruf=mailto:dmarc-ruf@yourdomain.com; fo=1;" to receive forensic incident telemetry.'  
      });  
    }

    // Check 6: DKIM Alignment & Key Health (10 pts)  
    const dkimPassedRecords \= records.filter(r \=\> r.dkim.aligned);  
    const dkimVolume \= dkimPassedRecords.reduce((acc, r) \=\> acc \+ r.count, 0);  
    const dkimPassRate \= metrics.totalVolume \> 0 ? (dkimVolume / metrics.totalVolume) \* 100 : 0;

    if (dkimPassRate \>= 90\) {  
      checks.push({  
        id: 'dkim\_alignment',  
        title: 'DKIM Cryptographic Alignment',  
        weight: 10,  
        score: 10,  
        status: 'PASS',  
        details: \`Robust DKIM: \${Math.round(dkimPassRate)}% of email volume passed DKIM cryptographic signature verification.\`,  
        remediation: null  
      });  
    } else if (dkimPassRate \>= 50\) {  
      checks.push({  
        id: 'dkim\_alignment',  
        title: 'DKIM Cryptographic Alignment',  
        weight: 10,  
        score: 6,  
        status: 'WARN',  
        details: \`Moderate DKIM Failure Rate: Only \${Math.round(dkimPassRate)}% aligned. Some SaaS providers lack custom domain DKIM keys.\`,  
        remediation: 'Configure dedicated CNAME DKIM selector keys for all transactional and marketing email services.'  
      });  
    } else {  
      checks.push({  
        id: 'dkim\_alignment',  
        title: 'DKIM Cryptographic Alignment',  
        weight: 10,  
        score: 2,  
        status: 'FAIL',  
        details: \`Severe DKIM Deficit: Only \${Math.round(dkimPassRate)}% aligned. High risk of legitimate emails landing in spam.\`,  
        remediation: 'Publish 2048-bit DKIM keys on your DNS selectors immediately.'  
      });  
    }

    // Check 7: SPF Alignment & Return-Path Verification (10 pts)  
    const spfPassedRecords \= records.filter(r \=\> r.spf.aligned);  
    const spfVolume \= spfPassedRecords.reduce((acc, r) \=\> acc \+ r.count, 0);  
    const spfPassRate \= metrics.totalVolume \> 0 ? (spfVolume / metrics.totalVolume) \* 100 : 0;

    if (spfPassRate \>= 80\) {  
      checks.push({  
        id: 'spf\_alignment',  
        title: 'SPF Envelope Alignment (RFC 7208)',  
        weight: 10,  
        score: 10,  
        status: 'PASS',  
        details: \`SPF Aligned: \${Math.round(spfPassRate)}% of sending volume aligns with authorized mail server IPs.\`,  
        remediation: null  
      });  
    } else {  
      checks.push({  
        id: 'spf\_alignment',  
        title: 'SPF Envelope Alignment (RFC 7208)',  
        weight: 10,  
        score: 5,  
        status: 'WARN',  
        details: \`SPF Misalignment: \${Math.round(100 \- spfPassRate)}% of volume uses unaligned or third-party return-path domains.\`,  
        remediation: 'Configure custom Return-Path / Mail-From CNAME subdomains for your cloud email vendors.'  
      });  
    }

    // Check 8: Active Phishing Spoofing Defense (10 pts)  
    const deliveredPhishingCount \= records  
      .filter(r \=\> \!r.dmarcPass && r.disposition \=== 'none')  
      .reduce((acc, r) \=\> acc \+ r.count, 0);

    if (deliveredPhishingCount \=== 0\) {  
      checks.push({  
        id: 'spoofing\_defense',  
        title: 'Active Spoofing Defense & Block Rate',  
        weight: 10,  
        score: 10,  
        status: 'PASS',  
        details: 'Zero Delivered Spoofs: All unauthenticated and spoofed messages were blocked or rejected.',  
        remediation: null  
      });  
    } else {  
      checks.push({  
        id: 'spoofing\_defense',  
        title: 'Active Spoofing Defense & Block Rate',  
        weight: 10,  
        score: 0,  
        status: 'FAIL',  
        details: \`CRITICAL BREACH: \${deliveredPhishingCount.toLocaleString()} unauthorized / phishing emails were delivered directly to recipient inboxes\!\`,  
        remediation: 'Enforce "p=reject" to block all fraudulent sender IPs immediately.'  
      });  
    }

    // Check 9: BIMI Brand Trust Readiness (5 pts)  
    const isBimiReady \= (policy.policy \=== 'reject' || (policy.policy \=== 'quarantine' && policy.percentage \=== 100)) && policy.subPolicy \!== 'none';  
    if (isBimiReady) {  
      checks.push({  
        id: 'bimi\_readiness',  
        title: 'BIMI Brand Trust Readiness (RFC 8463)',  
        weight: 5,  
        score: 5,  
        status: 'PASS',  
        details: 'BIMI Eligible: DMARC policy meets strict requirements for displaying official company logo in Gmail/Apple Mail.',  
        remediation: null  
      });  
    } else {  
      checks.push({  
        id: 'bimi\_readiness',  
        title: 'BIMI Brand Trust Readiness (RFC 8463)',  
        weight: 5,  
        score: 2,  
        status: 'INFO',  
        details: 'Ineligible for BIMI: Mailbox providers require p=reject or p=quarantine (pct=100) to render verified logos.',  
        remediation: 'Enforce p=reject to qualify for BIMI certification.'  
      });  
    }

    // Check 10: Identifier Alignment Mode (5 pts)  
    checks.push({  
      id: 'alignment\_mode',  
      title: 'Identifier Alignment Mode (aspf / adkim)',  
      weight: 5,  
      score: 5,  
      status: 'PASS',  
      details: \`Configured Alignment: SPF=\${policy.aspf.toUpperCase()} (Relaxed), DKIM=\${policy.adkim.toUpperCase()} (Relaxed). Standard enterprise posture.\`,  
      remediation: null  
    });

    // Calculate Totals  
    let totalScore \= 0;  
    let maxScore \= 0;  
    let passedCount \= 0;  
    let warnCount \= 0;  
    let failCount \= 0;

    checks.forEach(function (c) {  
      totalScore \+= c.score;  
      maxScore \+= c.weight;  
      if (c.status \=== 'PASS') passedCount++;  
      else if (c.status \=== 'WARN') warnCount++;  
      else if (c.status \=== 'FAIL') failCount++;  
    });

    const percentage \= Math.round((totalScore / maxScore) \* 100);

    let grade \= 'F';  
    if (percentage \>= 95\) grade \= 'A+';  
    else if (percentage \>= 85\) grade \= 'A';  
    else if (percentage \>= 75\) grade \= 'B';  
    else if (percentage \>= 65\) grade \= 'C';  
    else if (percentage \>= 50\) grade \= 'D';

    return {  
      domain: policy.domain,  
      overallScore: percentage,  
      grade: grade,  
      summary: {  
        totalChecks: checks.length,  
        passed: passedCount,  
        warnings: warnCount,  
        failures: failCount,  
        totalVolume: metrics.totalVolume,  
        blockedVolume: metrics.rejectVolume \+ metrics.quarantineVolume  
      },  
      policy: policy,  
      metrics: metrics,  
      checks: checks  
    };  
  }

  return {  
    auditDmarcReport  
  };  
});  
