# OpenRouter API Setup

## Getting Your OpenRouter API Key

1. Go to https://openrouter.ai/
2. Sign up or log in
3. Navigate to your API Keys section
4. Create a new API key
5. Copy the API key

## Setting Up the Environment Variable

### Option 1: Create a `.env` file in the `server` directory (Recommended)

1. Copy the example file:
   ```bash
   cd server
   cp .env.example .env
   ```

2. Edit `server/.env` and add your OpenRouter API key:

```
OPENROUTER_API_KEY=your_api_key_here
APP_URL=http://localhost:3000
```

**Note:** The `.env` file is already configured to load automatically via `dotenv` in `server/index.js`.

### Option 2: Set environment variable directly

**macOS/Linux:**
```bash
export OPENROUTER_API_KEY=your_api_key_here
export APP_URL=http://localhost:3000
```

**Windows:**
```cmd
set OPENROUTER_API_KEY=your_api_key_here
set APP_URL=http://localhost:3000
```

### Option 3: Add to your server startup script

If you're using `nodemon` or similar, you can add it to your `package.json`:

```json
{
  "scripts": {
    "dev": "OPENROUTER_API_KEY=your_key_here nodemon index.js"
  }
}
```

## Testing

After setting up the API key, restart your server and try asking the AI Assistant:

- "How do I share a file?"
- "What are Collections?"
- "How do I organize my files?"
- "What is the Social Feed feature?"

The AI should now provide intelligent, contextual responses instead of hardcoded answers.

## Model Used

Currently using `openai/gpt-4o-mini` for cost-effectiveness. You can change this in `server/routes/aiAssistant.js` by modifying the `model` parameter.

Available models on OpenRouter:
- `openai/gpt-4o-mini` (recommended - fast and cheap)
- `openai/gpt-4o` (more capable, more expensive)
- `anthropic/claude-3-haiku` (alternative)
- `google/gemini-pro` (alternative)

## Cost Considerations

OpenRouter charges per token usage. GPT-4o-mini is very affordable (~$0.15 per 1M input tokens, $0.60 per 1M output tokens).

Monitor your usage at: https://openrouter.ai/activity

