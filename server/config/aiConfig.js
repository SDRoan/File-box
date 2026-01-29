require('dotenv').config();

module.exports = {
  // OpenAI Configuration (Optional - paid)
  openai: {
    apiKey: process.env.OPENAI_API_KEY || '',
    embeddingModel: process.env.OPENAI_EMBEDDING_MODEL || 'text-embedding-ada-002',
  },

  // Hugging Face Configuration (Free tier available)
  huggingface: {
    apiKey: process.env.HUGGINGFACE_API_KEY || '',
    embeddingModel: process.env.HUGGINGFACE_EMBEDDING_MODEL || 'sentence-transformers/all-MiniLM-L6-v2',
    useFreeInference: process.env.USE_HUGGINGFACE_FREE === 'true' || !process.env.HUGGINGFACE_API_KEY,
  },

  // Text Extraction Configuration
  extraction: {
    maxTextLength: parseInt(process.env.AI_MAX_TEXT_LENGTH) || 8000,
    ocrLanguage: process.env.OCR_LANGUAGE || 'eng',
    supportedMimeTypes: process.env.SUPPORTED_MIME_TYPES 
      ? process.env.SUPPORTED_MIME_TYPES.split(',')
      : [
          'application/pdf',
          'application/msword',
          'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
          'text/plain',
          'text/html',
          'text/css',
          'text/javascript',
          'application/json',
          'application/xml',
          'image/jpeg',
          'image/png',
          'image/gif',
          'image/bmp',
          'image/tiff'
        ]
  },

  // Search Configuration
  search: {
    minSimilarityThreshold: parseFloat(process.env.AI_MIN_SIMILARITY_THRESHOLD) || 0.1,
    maxResults: parseInt(process.env.AI_MAX_SEARCH_RESULTS) || 20,
    folderSearchLimit: parseInt(process.env.AI_FOLDER_SEARCH_LIMIT) || 10,
    filenameSearchLimit: parseInt(process.env.AI_FILENAME_SEARCH_LIMIT) || 5,
    simpleEmbeddingMaxWords: parseInt(process.env.AI_SIMPLE_EMBEDDING_MAX_WORDS) || 100,
  },

  // Keyword Search Scoring Weights
  scoring: {
    exactFilenameMatch: parseInt(process.env.SCORE_EXACT_FILENAME_MATCH) || 10,
    partialFilenameMatch: parseInt(process.env.SCORE_PARTIAL_FILENAME_MATCH) || 5,
    contentMatch: parseFloat(process.env.SCORE_CONTENT_MATCH) || 0.5,
  },

  // Summarization Configuration
  summarization: {
    enabled: process.env.AI_SUMMARIZATION_ENABLED !== 'false', // Default: enabled
    model: process.env.AI_SUMMARIZATION_MODEL || 'facebook/bart-large-cnn', // Hugging Face model
    maxInputLength: parseInt(process.env.AI_SUMMARIZATION_MAX_INPUT_LENGTH) || 1024, // Max tokens for input
    maxSummaryLength: parseInt(process.env.AI_SUMMARIZATION_MAX_LENGTH) || 150, // Max tokens for summary
    minLength: parseInt(process.env.AI_SUMMARIZATION_MIN_LENGTH) || 30, // Min tokens for summary
    useFreeInference: process.env.USE_HUGGINGFACE_FREE === 'true' || !process.env.HUGGINGFACE_API_KEY,
    autoSummarize: process.env.AI_AUTO_SUMMARIZE === 'true', // Auto-generate summaries on upload
  },

  // Smart Organization Configuration
  smartOrganization: {
    enabled: process.env.AI_SMART_ORG_ENABLED !== 'false', // Default: enabled
    model: process.env.AI_SMART_ORG_MODEL || 'mistralai/Mistral-7B-Instruct-v0.2', // Hugging Face model
    useFreeInference: process.env.USE_HUGGINGFACE_FREE === 'true' || !process.env.HUGGINGFACE_API_KEY,
  },

  // Learning Resource Generation Configuration (AI-Generated, Updates Every 24 Hours)
  learningResources: {
    enabled: process.env.AI_LEARNING_RESOURCES_ENABLED !== 'false', // Default: enabled
    count: parseInt(process.env.AI_LEARNING_RESOURCES_COUNT) || 7, // Number of resources to generate
    updateInterval: process.env.AI_LEARNING_RESOURCES_INTERVAL || '0 0 * * *', // Cron schedule: every 24 hours at midnight
    openRouterModel: process.env.AI_LEARNING_RESOURCES_MODEL || 'google/gemini-flash-1.5-8b:free',
    huggingFaceModel: process.env.AI_LEARNING_RESOURCES_HF_MODEL || 'gpt2',
    // Topics pool - randomly selected each generation for variety
    topics: process.env.AI_LEARNING_RESOURCES_TOPICS 
      ? process.env.AI_LEARNING_RESOURCES_TOPICS.split(',').map(t => t.trim())
      : [
          'File Organization Strategies',
          'Advanced Search Techniques',
          'Collaborative Workflows',
          'Data Security Essentials',
          'Automation Features',
          'Mobile App Usage',
          'Integration Setup',
          'Backup and Recovery',
          'Performance Optimization',
          'Customization Options',
          'Team Management',
          'Version Control',
          'Access Control',
          'API Integration',
          'Troubleshooting Common Issues',
          'Smart Folder Organization',
          'File Sharing Best Practices',
          'Team Collaboration Tools',
          'Security Settings Configuration',
          'Advanced Search Features'
        ],
    categories: process.env.AI_LEARNING_RESOURCES_CATEGORIES
      ? process.env.AI_LEARNING_RESOURCES_CATEGORIES.split(',').map(c => c.trim())
      : ['getting-started', 'file-management', 'sharing', 'collaboration', 'security', 'advanced', 'api'],
    types: process.env.AI_LEARNING_RESOURCES_TYPES
      ? process.env.AI_LEARNING_RESOURCES_TYPES.split(',').map(t => t.trim())
      : ['tutorial', 'guide', 'article', 'faq'],
    difficulties: process.env.AI_LEARNING_RESOURCES_DIFFICULTIES
      ? process.env.AI_LEARNING_RESOURCES_DIFFICULTIES.split(',').map(d => d.trim())
      : ['beginner', 'intermediate', 'advanced'],
    minDuration: parseInt(process.env.AI_LEARNING_RESOURCES_MIN_DURATION) || 5,
    maxDuration: parseInt(process.env.AI_LEARNING_RESOURCES_MAX_DURATION) || 30,
    // AI generation settings
    minContentLength: parseInt(process.env.AI_LEARNING_RESOURCES_MIN_CONTENT_LENGTH) || 1000, // Minimum characters for AI content
    maxRetries: parseInt(process.env.AI_LEARNING_RESOURCES_MAX_RETRIES) || 3, // Max retry attempts for AI generation
  }
};

