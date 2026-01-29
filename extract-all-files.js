/**
 * Script to extract text from all files for AI search
 * Run this once to enable content-based search for existing files
 * 
 * Usage: node extract-all-files.js
 */

const axios = require('axios');
const readline = require('readline');

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

const API_URL = 'http://localhost:5001/api';

async function extractAllFiles() {
  try {
    // Get token from user
    rl.question('Enter your JWT token (from browser localStorage or login): ', async (token) => {
      if (!token) {
        console.log('No token provided. Exiting.');
        rl.close();
        return;
      }

      try {
        console.log('\n🔄 Extracting text from all files...');
        console.log('This may take a few minutes depending on the number of files...\n');

        const response = await axios.post(
          `${API_URL}/search/extract-all`,
          {},
          {
            headers: {
              'Authorization': `Bearer ${token}`,
              'Content-Type': 'application/json'
            }
          }
        );

        console.log('✅ Extraction completed!');
        console.log(`   - Extracted: ${response.data.extracted} files`);
        console.log(`   - Skipped: ${response.data.skipped} files`);
        console.log(`   - Errors: ${response.data.errors} files`);
        console.log(`   - Total: ${response.data.total} files\n`);
        console.log('🎉 You can now search by content! Try searching for "homework" or "exam"\n');

      } catch (error) {
        console.error('❌ Error:', error.response?.data?.message || error.message);
      }

      rl.close();
    });
  } catch (error) {
    console.error('Error:', error.message);
    rl.close();
  }
}

console.log('📄 File Text Extraction Script');
console.log('==============================\n');
console.log('This will extract text from all your PDFs and documents');
console.log('so you can search by content, not just filenames.\n');
console.log('To get your token:');
console.log('1. Open your browser');
console.log('2. Press F12 (Developer Tools)');
console.log('3. Go to Console tab');
console.log('4. Type: localStorage.getItem("token")');
console.log('5. Copy the token\n');

extractAllFiles();










