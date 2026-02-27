/**
 * CodeShield Detection Engine
 * Main orchestrator for secret detection pipeline
 */

import { scanWithRegex } from './scanner.js';
import { scanWithEntropy } from './entropy.js';

/**
 * Removes duplicate detections from the results
 * @param {Array} detections - Array of detection objects
 * @returns {Array} Deduplicated array of detections
 */
function removeDuplicates(detections) {
  if (!Array.isArray(detections)) {
    return [];
  }

  const seen = new Set();
  const unique = [];
  
  for (const detection of detections) {
    // Create a unique key based on type, value, and index
    const key = `${detection.type}-${detection.index}-${detection.value}`;
    
    if (!seen.has(key)) {
      seen.add(key);
      unique.push(detection);
    }
  }
  
  return unique;
}

/**
 * Sorts detections by their index position in the text
 * @param {Array} detections - Array of detection objects
 * @returns {Array} Sorted array of detections
 */
function sortByIndex(detections) {
  if (!Array.isArray(detections)) {
    return [];
  }

  return detections.sort((a, b) => a.index - b.index);
}

/**
 * Merges results from regex and entropy scans
 * @param {Array} regexResults - Results from regex scanning
 * @param {Array} entropyResults - Results from entropy scanning
 * @returns {Array} Merged and deduplicated results
 */
function mergeResults(regexResults, entropyResults) {
  const allResults = [
    ...(Array.isArray(regexResults) ? regexResults : []),
    ...(Array.isArray(entropyResults) ? entropyResults : [])
  ];
  
  // Remove duplicates and sort
  const deduplicated = removeDuplicates(allResults);
  return sortByIndex(deduplicated);
}

/**
 * Validates input parameter
 * @param {any} rawCode - Input to validate
 * @returns {boolean} True if input is valid string
 */
function isValidInput(rawCode) {
  return typeof rawCode === 'string' && rawCode.length > 0;
}

/**
 * Main processing function for the CodeShield detection engine
 * @param {string} rawCode - The code/text to process
 * @returns {Object} Detection results with metadata
 */
export function processCode(rawCode) {
  // Handle invalid input
  if (!isValidInput(rawCode)) {
    return {
      secretsFound: [],
      redactedCode: '',
      mapping: {},
      metadata: {
        totalLength: 0,
        processingTime: 0,
        scanCount: 0
      }
    };
  }

  const startTime = performance.now();
  
  try {
    // Run regex scan for known secrets
    const regexResults = scanWithRegex(rawCode);
    
    // Run entropy scan for unknown secrets
    const entropyResults = scanWithEntropy(rawCode);
    
    // Merge results and remove duplicates
    const mergedResults = mergeResults(regexResults, entropyResults);
    
    const endTime = performance.now();
    const processingTime = endTime - startTime;
    
    // Return results structure (redaction will be implemented later)
    return {
      secretsFound: mergedResults,
      redactedCode: rawCode, // Will be implemented in redaction module
      mapping: {}, // Will be implemented in redaction module
      metadata: {
        totalLength: rawCode.length,
        processingTime: Math.round(processingTime * 100) / 100, // Round to 2 decimal places
        scanCount: mergedResults.length,
        regexMatches: regexResults.length,
        entropyMatches: entropyResults.length
      }
    };
    
  } catch (error) {
    // Handle any unexpected errors gracefully
    console.error('CodeShield processing error:', error);
    
    return {
      secretsFound: [],
      redactedCode: rawCode,
      mapping: {},
      metadata: {
        totalLength: rawCode.length,
        processingTime: 0,
        scanCount: 0,
        error: error.message
      }
    };
  }
}

/**
 * Quick scan function that returns only the secrets found
 * @param {string} rawCode - The code/text to scan
 * @returns {Array} Array of detected secrets
 */
export function quickScan(rawCode) {
  const result = processCode(rawCode);
  return result.secretsFound;
}

/**
 * Gets statistics about the detection process
 * @param {string} rawCode - The code/text to analyze
 * @returns {Object} Statistics about the code and potential secrets
 */
export function getCodeStats(rawCode) {
  if (!isValidInput(rawCode)) {
    return {
      lineCount: 0,
      characterCount: 0,
      wordCount: 0,
      estimatedRisk: 'none'
    };
  }

  const lines = rawCode.split('\n');
  const words = rawCode.split(/\s+/).filter(word => word.length > 0);
  
  // Quick scan for risk assessment
  const secrets = quickScan(rawCode);
  let risk = 'none';
  
  if (secrets.length > 0) {
    const highRiskTypes = ['AWS_ACCESS_KEY', 'AWS_SECRET_KEY', 'OPENAI_API_KEY', 'PRIVATE_KEY'];
    const hasHighRisk = secrets.some(secret => highRiskTypes.includes(secret.type));
    risk = hasHighRisk ? 'high' : (secrets.length > 3 ? 'medium' : 'low');
  }
  
  return {
    lineCount: lines.length,
    characterCount: rawCode.length,
    wordCount: words.length,
    estimatedRisk: risk,
    secretCount: secrets.length
  };
}
