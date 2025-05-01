const fs = require('fs');
const axios = require('axios');
const path = require('path');
require('dotenv').config();
const { execSync } = require('child_process');
const { spawnSync } = require('child_process');
const { GoogleGenAI } = require("@google/genai");

async function analyzeContract(filePath) {
  try {
    const contractCode = fs.readFileSync(filePath, 'utf-8');
    

    const grokFindings = await analyzeWithGemini(contractCode); // analyze original code with LLM
    const slitherFindings = runSlither(filePath); // analyze file with slither

    const scoreData = calculateScore(grokFindings, slitherFindings);
    generateReport(grokFindings, slitherFindings, scoreData);


  } catch (error) {
    console.error('Error analyzing contract:', error);
  }
}

async function analyzeWithGemini(code) {
  const prompt = `
    Analyze the following Solidity contract for vulnerabilities that could lead to loss of principal (e.g., stolen funds, frozen assets, unauthorized transfers). Focus on:

    - Arithmetic Safety: Use of SafeMath or Solidity ^0.8.0’s overflow checks to prevent balance manipulation.
    - Reentrancy Protection: Use of ReentrancyGuard or equivalent to prevent recursive call exploits.
    - Access Control: Secure use of Ownable, AccessControl, or similar to prevent unauthorized actions.
    - Audited Libraries: Use of trusted libraries (e.g., OpenZeppelin ERC20/ERC721) to minimize bugs.
    - Safe External Calls: Minimized and secure calls to prevent reentrancy or delegatecall exploits.
    - ERC20/ERC721 Compliance: Correct token standard implementation for safe transfers.
    - Event Logging: Proper events for transfers and approvals to ensure auditability.
    - Solidity Version Safety: Use of a recent, secure version (e.g., ^0.8.0) to avoid compiler bugs.

    For each issue, return a JSON object with the following exact field names:
    - "Issue title": A short, one-line summary of the issue (e.g., "Missing Reentrancy Protection")
    - "Issue description": A detailed explanation of the vulnerability
    - "Severity": "Critical", "Moderate", or "Minor"
    - "Recommendation": Actionable advice to fix the issue
    - "Risk": Must be "principal_loss"

    Return a clean JSON array with only these fields for each issue.

    Contract code:
    ${code}
  `;

  try {
    const response = await axios.post(
      'https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=' + process.env.GEMINI_API_KEY,
      {
        contents: [{ parts: [{ text: prompt }] }]
      },
      {
        headers: { 'Content-Type': 'application/json' }
      }
    );

    const rawText = response.data.candidates?.[0]?.content?.parts?.[0]?.text || '';
  
    const cleanText = rawText.replace(/```(?:json)?\s*([\s\S]*?)\s*```/, '$1').trim();
    // console.log(cleanText);
    let findings = [];
    try {
      findings = JSON.parse(cleanText);
    } catch (parseError) {
      console.error('Failed to parse Gemini JSON:', parseError);
      console.error('Raw Gemini response:', rawText);
      return [];
    }

    return findings
    .filter(f => (f.risk || f["Risk"]) === 'principal_loss')
    .map(f => {

  
      return {
        issue: f["Issue title"] || 'MISSING ISSUE DESCRIPTION',
        severity: f.severity || f["Severity"] || 'Unknown',
        recommendation: f.recommendation || f["Recommendation"] || '',
        risk: f.risk || f["Risk"] || 'principal_loss'
      };
    });
  

  } catch (error) {
    console.error('Gemini Axios API call error:', error);
    return [];
  }
}


function runSlither(filePath) {
  const outputFile = path.join(__dirname, 'slither_output.json');
  const targetFileName = path.basename(filePath);

  // Run slither . --json slither_output.json
  const result = spawnSync('slither', ['.', '--json', outputFile], {
    encoding: 'utf-8'
  });

  // console.log(result);

  if (result.error) {
    console.error('❌ Slither failed to run:', result.error.message);
    return [];
  }

  if (result.status !== 0) {
    console.warn('⚠️ Slither returned non-zero exit code. Might be warnings.');
  }

  if (!fs.existsSync(outputFile)) {
    console.error('❌ Slither output JSON file not found.');
    return [];
  }

  let parsed;
  try {
    parsed = JSON.parse(fs.readFileSync(outputFile, 'utf-8'));
  } catch (err) {
    console.error('❌ Failed to parse Slither output JSON:', err.message);
    return [];
  }

  const detectors = parsed.results?.detectors || [];
  
  // Filter findings based on criteria
  const filteredFindings = detectors
  .flatMap(d => {
    return d.elements
      ?.filter(el =>
        (
          el.source_mapping?.filename_relative?.endsWith(targetFileName) &&
          !el.source_mapping?.is_dependency
        ) &&
        (
          d.impact === 'High' ||
          d.impact === 'Informational'
        ) &&
        ['reentrancy', 'access-control', 'arithmetic', 'unchecked-transfer', 'solc-version'].includes(d.check)
      )

      .map(() => ({
        issue: d.description,
        severity: 'Critical',
        recommendation: `Mitigate ${d.check} vulnerability (see Slither documentation).`,
        risk: 'principal_loss'
      })) || [];
  });

  return filteredFindings;
}


function calculateScore(grokFindings, slitherFindings) {
  const allFindings = [...grokFindings, ...slitherFindings];
  const uniqueIssues = [];
  const seenIssues = new Set();

  // Remove empty findings
  for (const finding of uniqueIssues) {
    if (!finding || !finding.issue) continue;
  }

   // Deduplicate findings (e.g., reentrancy flagged by both Grok and Slither)
  for (const finding of allFindings) {
    const issueKey = finding.issue.toLowerCase().replace(/\s+/g, '');
    if (!seenIssues.has(issueKey)) {
      seenIssues.add(issueKey);
      uniqueIssues.push(finding);
    }
  }

  

  let score = 10;
  const deductions = [];
  
  // Deduct points based on severity
  for (const finding of uniqueIssues) {
    let deduction = 0;
    switch (finding.severity.toLowerCase()) {
      case 'critical':
        deduction = 3;
        break;
      case 'moderate':
        deduction = 1;
        break;
      case 'minor':
        deduction = 0.5;
        break;
    }
    score -= deduction;
    deductions.push({ issue: finding.issue, severity: finding.severity, deduction });
  }

  score = Math.max(0, Math.round(score * 10) / 10); // Round to 1 decimal, ensure >= 0
  return { score, deductions };
}

// Generate a report based on findings and score
function generateReport(grokFindings, slitherFindings, scoreData) {
  console.log('=== Principal Protection Report ===');
  console.log(`Security Score: ${scoreData.score}/10`);
  console.log('Risks to Loss of Principal:');

  console.log('\nGrok Findings:');
  if (grokFindings.length === 0) {
    console.log('No critical vulnerabilities detected that risk loss of principal.');
  } else {    
      grokFindings.forEach(finding => {
        console.log(`\n- Issue: ${finding.issue} (${finding.severity})`);
        console.log(`  Recommendation: ${finding.recommendation}`);
      });
    }

  console.log('\nSlither Findings:');
  if (slitherFindings.length === 0) {
    console.log('No critical vulnerabilities detected that risk loss of principal.');
  } else {
      slitherFindings.forEach(finding => {
        console.log(`- Issue: ${finding.issue} (${finding.severity})`);
        console.log(`  Recommendation: ${finding.recommendation}`);
      });
    }

    console.log('\nScore Deductions:');
    scoreData.deductions.forEach(d => {
      console.log(`- ${d.issue} (${d.severity}): -${d.deduction} points`);
    });


  // Save the report to a JSON file
  const report = {
    score: scoreData.score,
    grokFindings,
    slitherFindings,
    deductions: scoreData.deductions
  };
  fs.writeFileSync('principal_protection_report.json', JSON.stringify(report, null, 2));
}

if (process.argv.length < 3) {
  console.log('Usage: node index.js <path-to-solidity-file>');
  process.exit(1);
}

analyzeContract(process.argv[2]);