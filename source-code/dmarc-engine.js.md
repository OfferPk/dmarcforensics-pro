/\*\*  
 \* DMARCForensics Pro \- Core DMARC & XML Forensics Engine  
 \* RFC 7489 (DMARC), RFC 7960, RFC 7208 (SPF), and RFC 6376 (DKIM) Analyzer  
 \*/

(function (root, factory) {  
  if (typeof define \=== 'function' && define.amd) {  
    define(\[\], factory);  
  } else if (typeof module \=== 'object' && module.exports) {  
    module.exports \= factory();  
  } else {  
    root.DMARCEngine \= factory();  
  }  
})(typeof self \!== 'undefined' ? self : this, function () {  
  'use strict';

  /\*\*  
   \* Universal XML Tag Content Extractor (Regex-based, 0-dependency)  
   \*/  
  function getTagValue(xmlText, tagName, defaultValue) {  
    if (\!xmlText) return defaultValue || '';  
    const regex \= new RegExp('\<' \+ tagName \+ '\[^\>\]\*\>(\[\\\\s\\\\S\]\*?)\<\\\\/' \+ tagName \+ '\>', 'i');  
    const match \= xmlText.match(regex);  
    return match ? match\[1\].trim() : (defaultValue || '');  
  }

  /\*\*  
   \* Parse RFC 7489 DMARC Aggregate (RUA) XML Report  
   \*/  
  function parseDmarcXml(xmlString) {  
    if (\!xmlString || typeof xmlString \!== 'string') {  
      throw new Error('Invalid XML input');  
    }

    // 1\. Metadata  
    const metadataBlock \= getTagValue(xmlString, 'report\_metadata');  
    const orgName \= getTagValue(metadataBlock, 'org\_name', 'Unknown Mailbox Provider');  
    const email \= getTagValue(metadataBlock, 'email', '');  
    const reportId \= getTagValue(metadataBlock, 'report\_id', 'UNKNOWN-ID');  
    const dateRangeBlock \= getTagValue(metadataBlock, 'date\_range');  
    const beginTime \= parseInt(getTagValue(dateRangeBlock, 'begin', '0'), 10);  
    const endTime \= parseInt(getTagValue(dateRangeBlock, 'end', '0'), 10);

    // 2\. Published Policy  
    const policyBlock \= getTagValue(xmlString, 'policy\_published');  
    const domain \= getTagValue(policyBlock, 'domain', 'example.com');  
    const policy \= getTagValue(policyBlock, 'p', 'none').toLowerCase();  
    const subPolicy \= getTagValue(policyBlock, 'sp', policy).toLowerCase();  
    const pct \= parseInt(getTagValue(policyBlock, 'pct', '100'), 10);  
    const aspf \= getTagValue(policyBlock, 'aspf', 'r').toLowerCase();  
    const adkim \= getTagValue(policyBlock, 'adkim', 'r').toLowerCase();  
    const fo \= getTagValue(policyBlock, 'fo', '0');

    // 3\. Records Extraction  
    const records \= \[\];  
    const recordRegex \= /\<record\>(\[\\s\\S\]\*?)\<\\/record\>/gi;  
    let match;

    let totalVolume \= 0;  
    let passVolume \= 0;  
    let failVolume \= 0;  
    let rejectVolume \= 0;  
    let quarantineVolume \= 0;

    while ((match \= recordRegex.exec(xmlString)) \!== null) {  
      const recXml \= match\[1\];

      // Row block  
      const rowBlock \= getTagValue(recXml, 'row');  
      const sourceIp \= getTagValue(rowBlock, 'source\_ip', '0.0.0.0');  
      const count \= parseInt(getTagValue(rowBlock, 'count', '1'), 10);

      const policyEvalBlock \= getTagValue(rowBlock, 'policy\_evaluated');  
      const disposition \= getTagValue(policyEvalBlock, 'disposition', 'none').toLowerCase();  
      const dkimEval \= getTagValue(policyEvalBlock, 'dkim', 'fail').toLowerCase();  
      const spfEval \= getTagValue(policyEvalBlock, 'spf', 'fail').toLowerCase();

      // Identifiers  
      const idBlock \= getTagValue(recXml, 'identifiers');  
      const headerFrom \= getTagValue(idBlock, 'header\_from', domain);

      // Auth Results  
      const authBlock \= getTagValue(recXml, 'auth\_results');  
      const dkimBlock \= getTagValue(authBlock, 'dkim');  
      const dkimDomain \= getTagValue(dkimBlock, 'domain', '');  
      const dkimResult \= getTagValue(dkimBlock, 'result', 'none').toLowerCase();  
      const dkimSelector \= getTagValue(dkimBlock, 'selector', '');

      const spfBlock \= getTagValue(authBlock, 'spf');  
      const spfDomain \= getTagValue(spfBlock, 'domain', '');  
      const spfResult \= getTagValue(spfBlock, 'result', 'none').toLowerCase();

      // DMARC Alignment Check  
      // DMARC passes if either SPF or DKIM is aligned and passes  
      const isSpfAligned \= (spfResult \=== 'pass') && (  
        aspf \=== 's' ? (spfDomain.toLowerCase() \=== headerFrom.toLowerCase()) : (headerFrom.toLowerCase().endsWith(spfDomain.toLowerCase()) || spfDomain.toLowerCase().endsWith(headerFrom.toLowerCase()))  
      );

      const isDkimAligned \= (dkimResult \=== 'pass') && (  
        adkim \=== 's' ? (dkimDomain.toLowerCase() \=== headerFrom.toLowerCase()) : (headerFrom.toLowerCase().endsWith(dkimDomain.toLowerCase()) || dkimDomain.toLowerCase().endsWith(headerFrom.toLowerCase()))  
      );

      const dmarcPass \= isSpfAligned || isDkimAligned;

      totalVolume \+= count;  
      if (dmarcPass) {  
        passVolume \+= count;  
      } else {  
        failVolume \+= count;  
        if (disposition \=== 'reject') rejectVolume \+= count;  
        else if (disposition \=== 'quarantine') quarantineVolume \+= count;  
      }

      records.push({  
        sourceIp: sourceIp,  
        count: count,  
        headerFrom: headerFrom,  
        disposition: disposition,  
        dmarcPass: dmarcPass,  
        spf: {  
          domain: spfDomain,  
          result: spfResult,  
          aligned: isSpfAligned  
        },  
        dkim: {  
          domain: dkimDomain,  
          selector: dkimSelector,  
          result: dkimResult,  
          aligned: isDkimAligned  
        }  
      });  
    }

    return {  
      metadata: {  
        orgName: orgName,  
        email: email,  
        reportId: reportId,  
        beginTime: beginTime,  
        endTime: endTime  
      },  
      policy: {  
        domain: domain,  
        policy: policy,  
        subPolicy: subPolicy,  
        percentage: pct,  
        aspf: aspf,  
        adkim: adkim,  
        fo: fo  
      },  
      metrics: {  
        totalVolume: totalVolume,  
        passVolume: passVolume,  
        failVolume: failVolume,  
        rejectVolume: rejectVolume,  
        quarantineVolume: quarantineVolume,  
        passPercentage: totalVolume \> 0 ? Math.round((passVolume / totalVolume) \* 100\) : 0,  
        uniqueIps: new Set(records.map(r \=\> r.sourceIp)).size  
      },  
      records: records  
    };  
  }

  /\*\*  
   \* Synthesize DMARC DNS Record  
   \*/  
  function generateDmarcRecord(params) {  
    const policy \= params.policy || 'reject';  
    const subPolicy \= params.subPolicy || policy;  
    const pct \= params.percentage \!== undefined ? params.percentage : 100;  
    const rua \= params.rua || 'mailto:dmarc-rua@yourdomain.com';  
    const ruf \= params.ruf || 'mailto:dmarc-ruf@yourdomain.com';  
    const aspf \= params.aspf || 'r';  
    const adkim \= params.adkim || 'r';

    return \`v=DMARC1; p=\${policy}; sp=\${subPolicy}; pct=\${pct}; rua=\${rua}; ruf=\${ruf}; fo=1; aspf=\${aspf}; adkim=\${adkim};\`;  
  }

  return {  
    getTagValue,  
    parseDmarcXml,  
    generateDmarcRecord  
  };  
});  
