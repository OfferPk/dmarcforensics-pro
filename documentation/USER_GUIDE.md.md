\# DMARCForensics Pro: User Guide & NetDevOps / AppSec Integration

\#\# Overview  
DMARCForensics Pro operates both as a 100% client-side web application and as a standalone Python CLI tool to parse DMARC aggregate XML reports, audit email domain security against a 10-point Zero-Trust scorecard, simulate phishing attacks, and synthesize production DNS records.

\---

\#\# 1\. Web Studio Quickstart  
1\. Open \`source-code/index.html\` in any modern web browser.  
2\. Select an XML report preset:  
   \- \*\*Apex FinBank\*\*: Fully hardened \`p=reject\` with Google/SendGrid alignment (Grade A+).  
   \- \*\*CloudPulse SaaS\*\*: Microsoft 365 \`p=quarantine\` with unaligned SES traffic (Grade B).  
   \- \*\*Legacy Corp\*\*: Permissive \`p=none\` actively exploited by spoofed botnets (Grade F).  
3\. Click \*\*Analyze Report\*\* to evaluate the 10-point scorecard.  
4\. Review the \*\*Interactive Simulator\*\* to compare \`p=reject\` gateway dropping against \`p=none\` phishing delivery.  
5\. Select a DNS provider (\*\*Cloudflare\*\*, \*\*AWS Route 53\*\*, \*\*BIND Zonefile\*\*, or \*\*Terraform HCL\*\*) and click \*\*Copy DNS Records\*\*.

\---

\#\# 2\. Standalone Python CLI Tool

Requires Python 3.8+ with zero external package dependencies.

\#\#\# Command Reference

\`\`\`bash  
\# Audit a DMARC aggregate XML report  
python3 build/dmarc-forensics-cli.py audit \-p presets/enterprise-bank-hardened-reject-rua.xml

\# Audit with strict CI/CD gating (exits 1 on failures or score \< 90\)  
python3 build/dmarc-forensics-cli.py audit \-p presets/enterprise-bank-hardened-reject-rua.xml \--strict

\# Inspect parsed report metrics as JSON  
python3 build/dmarc-forensics-cli.py inspect \-p presets/enterprise-bank-hardened-reject-rua.xml  
\`\`\`

\---

\#\# 3\. NetDevOps / AppSec CI/CD Pipeline Integration

Integrate DMARCForensics Pro into your domain management workflows to prevent publishing weak DMARC policies:

\`\`\`yaml  
\# .github/workflows/dmarc-audit.yml  
name: DMARC & Email Security Verification  
on: \[push, pull\_request\]

jobs:  
  dmarc-verify:  
    runs-on: ubuntu-latest  
    steps:  
      \- uses: actions/checkout@v4  
      \- name: Set up Python  
        uses: actions/setup-python@v5  
        with:  
          python-version: '3.11'  
      \- name: Run DMARCForensics Strict Audit  
        run: |  
          python3 build/dmarc-forensics-cli.py audit \\  
            \-p presets/enterprise-bank-hardened-reject-rua.xml \\  
            \--strict  
\`\`\`  
