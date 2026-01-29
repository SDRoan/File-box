# Configuration Guide

All configuration values are now externalized and can be set via environment variables. No hardcoded values remain in the codebase.

## Environment Variables

Create a `.env` file in the `server/` directory with the following variables:

### Server Configuration
```bash
PORT=5001                          # Server port (default: 5001)
CLIENT_URL=http://localhost:3000   # Frontend URL for CORS
```

### Database Configuration
```bash
MONGODB_URI=mongodb://localhost:27017/dropbox-clone
```

### JWT Configuration
```bash
JWT_SECRET=your-secret-key-change-in-production  # Change in production!
JWT_EXPIRES_IN=7d                                 # Token expiration (default: 7d)
```

### Storage Configuration
```bash
DEFAULT_STORAGE_LIMIT_BYTES=10737418240    # Default user storage limit (10GB)
MAX_FILE_SIZE_BYTES=107374182400           # Max file upload size (100GB)
```

### AI Search Configuration (FREE Options Available!)

**Option 1: Hugging Face (FREE - Recommended)**
```bash
# No API key needed for free tier! Works out of the box.
# Optional: Get free API key from https://huggingface.co/settings/tokens for higher limits
HUGGINGFACE_API_KEY=                          # Optional - free tier works without it
HUGGINGFACE_EMBEDDING_MODEL=sentence-transformers/all-MiniLM-L6-v2
USE_HUGGINGFACE_FREE=true                     # Use free inference (default)
```

**Option 2: OpenAI (Paid - Optional)**
```bash
OPENAI_API_KEY=                              # Your OpenAI API key (optional - paid)
OPENAI_EMBEDDING_MODEL=text-embedding-ada-002 # Embedding model to use
```

**Note:** The app uses Hugging Face (FREE) by default. No API keys needed!

### AI Search Configuration
```bash
AI_MAX_TEXT_LENGTH=8000              # Max text length for embeddings
AI_MIN_SIMILARITY_THRESHOLD=0.1      # Minimum similarity score (0-1)
AI_MAX_SEARCH_RESULTS=20             # Max results returned
AI_FOLDER_SEARCH_LIMIT=10            # Max folders in search results
AI_FILENAME_SEARCH_LIMIT=5           # Max filename matches
AI_SIMPLE_EMBEDDING_MAX_WORDS=100    # Max words for fallback embedding
```

### Search Scoring Weights
```bash
SCORE_EXACT_FILENAME_MATCH=10        # Score for exact filename match
SCORE_PARTIAL_FILENAME_MATCH=5      # Score for partial filename match
SCORE_CONTENT_MATCH=0.5             # Score multiplier for content matches
```

### OCR Configuration
```bash
OCR_LANGUAGE=eng                    # Tesseract OCR language code
```

### MIME Type Configuration
```bash
# Supported MIME types for text extraction (comma-separated)
# Leave empty to use defaults: pdf,word,document,text,json,xml,javascript,css,html,image/*
SUPPORTED_MIME_TYPES=

# Allowed MIME types for upload (comma-separated)
# Leave empty/null to allow all types
ALLOWED_MIME_TYPES=
```

### AI Summarization Configuration (FREE!)
```bash
# Enable/disable summarization (default: enabled)
AI_SUMMARIZATION_ENABLED=true

# Hugging Face summarization model (free)
AI_SUMMARIZATION_MODEL=facebook/bart-large-cnn

# Max input length in tokens (default: 1024)
AI_SUMMARIZATION_MAX_INPUT_LENGTH=1024

# Max summary length in tokens (default: 150)
AI_SUMMARIZATION_MAX_LENGTH=150

# Min summary length in tokens (default: 30)
AI_SUMMARIZATION_MIN_LENGTH=30

# Auto-generate summaries on file upload (default: false)
AI_AUTO_SUMMARIZE=false

# Use free Hugging Face inference (default: true)
USE_HUGGINGFACE_FREE=true
```

**Note:** Summarization uses Hugging Face's free inference API. No API key needed!

## Configuration Files

All configuration is centralized in:
- `server/config/appConfig.js` - Application configuration
- `server/config/aiConfig.js` - AI search configuration

These files read from environment variables and provide defaults if not set.

## Frontend Configuration

The frontend uses React environment variables. Create a `.env` file in the `client/` directory:

```bash
REACT_APP_API_URL=http://localhost:5001/api
```

## Production Deployment

**IMPORTANT**: For production, ensure you:
1. Set a strong `JWT_SECRET`
2. Set `CLIENT_URL` to your production frontend URL
3. Set `MONGODB_URI` to your production database
4. Set `OPENAI_API_KEY` if using AI search features
5. Review and adjust all limits and thresholds as needed

