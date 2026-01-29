// Copy and paste this into your browser console (F12)

// Step 1: Extract text from all files
fetch('http://localhost:5001/api/search/extract-all', {
  method: 'POST',
  headers: {
    'Authorization': 'Bearer ' + localStorage.getItem('token'),
    'Content-Type': 'application/json'
  }
})
.then(r => r.json())
.then(data => {
  console.log('✅ Extraction started!');
  console.log('📊 Results:', data);
  console.log('\n⏳ This may take 1-2 minutes...');
  console.log('📄 Extracted:', data.extracted, 'files');
  console.log('⏭️ Skipped:', data.skipped, 'files');
  console.log('❌ Errors:', data.errors, 'files');
  
  // Wait a bit, then check status
  setTimeout(() => {
    console.log('\n🔍 Checking extraction status...');
    fetch('http://localhost:5001/api/debug/extraction-status', {
      headers: {
        'Authorization': 'Bearer ' + localStorage.getItem('token')
      }
    })
    .then(r => r.json())
    .then(status => {
      console.log('📈 Status:', status.filesWithContent, '/', status.totalFiles, 'files have content');
      console.log('✅ Ready to search! Try searching for "homework" or "resume"');
    });
  }, 3000);
})
.catch(err => {
  console.error('❌ Error:', err);
  console.log('Make sure you are logged in and the server is running!');
});










