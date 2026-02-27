// ======================================
// Sample Backend Service (Test File)
// Used to test CodeShield detection engine
// ======================================

// import axios from "axios";  // Commented out for testing

const PORT = 3000;

// OpenAI API Key (secret that should be detected)
const OPENAI_API_KEY = "sk-abc1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";

// Database configuration
const DB_CONFIG = {
  host: "localhost",
  user: "admin",
  password: "myDatabasePassword123"
};

// Example function calling an API
async function generateResponse(prompt) {
  try {
    const response = await axios.post(
      "https://api.openai.com/v1/chat/completions",
      {
        model: "gpt-4",
        messages: [{ role: "user", content: prompt }]
      },
      {
        headers: {
          Authorization: `Bearer ${OPENAI_API_KEY}`,
          "Content-Type": "application/json"
        }
      }
    );

    return response.data;
  } catch (error) {
    console.error("Error calling AI service:", error.message);
  }
}

// Start server
function startServer() {
  console.log(`Server running on port ${PORT}`);
}

startServer();

// ======================================
// CODESHIELD TESTING CODE
// ======================================

import { processCode, quickScan, getCodeStats } from './engine/index.js';

// Read the current file content
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const fileContent = readFileSync(__filename, 'utf8');

console.log('🔍 Testing Your Updated File\n');

// Process the file
const result = processCode(fileContent);
const stats = getCodeStats(fileContent);

console.log('📊 File Statistics:');
console.log(`   Lines: ${stats.lineCount}`);
console.log(`   Characters: ${stats.characterCount}`);
console.log(`   Risk Level: ${stats.estimatedRisk}\n`);

if (result.secretsFound.length === 0) {
  console.log('✅ No secrets detected in your code!');
} else {
  console.log(`🚨 Found ${result.secretsFound.length} potential secrets:\n`);
  
  result.secretsFound.forEach((secret, index) => {
    console.log(`${index + 1}. ${secret.type}`);
    console.log(`   Position: ${secret.index}`);
    console.log(`   Value: ${secret.value.substring(0, 60)}${secret.value.length > 60 ? '...' : ''}`);
    console.log();
  });
}

console.log(`⏱️  Processing Time: ${result.metadata.processingTime}ms`);