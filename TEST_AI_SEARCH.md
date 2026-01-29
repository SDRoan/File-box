# 🔍 Test & Fix AI Search

## Step 1: Check Extraction Status

Open your browser console (F12) and run:

```javascript
fetch('http://localhost:5001/api/debug/extraction-status', {
  headers: {
    'Authorization': 'Bearer ' + localStorage.getItem('token')
  }
}).then(r => r.json()).then(console.log)
```

This will show you which files have been extracted.

## Step 2: Extract All Files

If files aren't extracted, run this in browser console:

```javascript
fetch('http://localhost:5001/api/search/extract-all', {
  method: 'POST',
  headers: {
    'Authorization': 'Bearer ' + localStorage.getItem('token'),
    'Content-Type': 'application/json'
  }
}).then(r => r.json()).then(console.log)
```

Wait for it to complete (may take 1-2 minutes).

## Step 3: Test Search

After extraction, try searching for:
- "homework" 
- "resume"
- "exam"
- Any content from your PDFs

## Step 4: Check Server Logs

Look at your server terminal. You should see:
- `[AI Search] Query: "homework"...`
- `[AI Search] Results: X semantic, Y content-keyword...`
- `[AI Search] Files with content extracted: X/Y`

## Common Issues:

1. **No extraction happened**: Run Step 2
2. **Hugging Face failing**: Check server logs for errors
3. **Search returns nothing**: Make sure text was actually extracted (Step 1)










