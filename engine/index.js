/**
 * CodeShield Detection Engine
 * Main orchestrator for secret detection pipeline
 */

import { scanWithRegex } from './scanner.js';
import { scanWithEntropy } from './entropy.js';
// CHANGE 1: Import your redaction logic
import { redactCode } from './redactor.js'; 

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
  
  const deduplicated = removeDuplicates(allResults);
  return sortByIndex(deduplicated);
}

/**
 * Validates input parameter
 */
function isValidInput(rawCode) {
  return typeof rawCode === 'string' && rawCode.length > 0;
}

/**
 * Main processing function for the CodeShield detection engine
 */
export function processCode(rawCode) {
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
    const regexResults = scanWithRegex(rawCode);
    const entropyResults = scanWithEntropy(rawCode);
    const mergedResults = mergeResults(regexResults, entropyResults);
    
    // CHANGE 2: Execute your redaction engine using the merged results
    const { redactedCode, mapping } = redactCode(rawCode, mergedResults);
    
    const endTime = performance.now();
    const processingTime = endTime - startTime;
    
    // CHANGE 3: Return the actual redacted code and mapping instead of placeholders
    return {
      secretsFound: mergedResults,
      redactedCode: redactedCode, 
      mapping: mapping,           
      metadata: {
        totalLength: rawCode.length,
        processingTime: Math.round(processingTime * 100) / 100,
        scanCount: mergedResults.length,
        regexMatches: regexResults.length,
        entropyMatches: entropyResults.length
      }
    };
    
  } catch (error) {
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

// ... rest of the file (quickScan and getCodeStats) remains unchanged ...