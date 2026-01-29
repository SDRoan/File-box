const OpenAI = require('openai');
const { HfInference } = require('@huggingface/inference');
const config = require('../config/aiConfig');

// Initialize OpenAI (optional - paid)
const openai = config.openai.apiKey ? new OpenAI({
  apiKey: config.openai.apiKey
}) : null;

// Initialize Hugging Face (free tier)
const hf = config.huggingface.apiKey 
  ? new HfInference(config.huggingface.apiKey)
  : new HfInference(); // Works without API key for free inference

class AISearch {
  /**
   * Generate embedding for text using free services (Hugging Face) or paid (OpenAI)
   */
  async generateEmbedding(text) {
    if (!text || text.trim().length === 0) {
      return [];
    }

    // Limit text length to avoid token limits
    const maxLength = config.extraction.maxTextLength;
    const truncatedText = text.length > maxLength ? text.substring(0, maxLength) : text;

    try {
      // Priority 1: Try Hugging Face (FREE)
      if (config.huggingface.useFreeInference || config.huggingface.apiKey) {
        try {
          const response = await hf.featureExtraction({
            model: config.huggingface.embeddingModel,
            inputs: truncatedText,
          });
          
          // Hugging Face returns array or nested array
          let embedding = response;
          if (Array.isArray(response) && response.length > 0 && Array.isArray(response[0])) {
            // If nested array, take first element
            embedding = response[0];
          }
          
          // Ensure it's a proper array
          if (Array.isArray(embedding) && embedding.length > 0) {
            return embedding;
          }
        } catch (hfError) {
          console.log('Hugging Face embedding failed, trying fallback:', hfError.message);
          // Continue to next option
        }
      }

      // Priority 2: Try OpenAI (if API key provided - paid)
      if (openai && config.openai.apiKey) {
        try {
          const response = await openai.embeddings.create({
            model: config.openai.embeddingModel,
            input: truncatedText
          });
          return response.data[0].embedding;
        } catch (openaiError) {
          console.log('OpenAI embedding failed, using fallback:', openaiError.message);
        }
      }

      // Priority 3: Fallback to simple keyword-based search (FREE)
      return this.simpleEmbedding(truncatedText);
    } catch (error) {
      console.error('Error generating embedding:', error);
      // Fallback to simple embedding
      return this.simpleEmbedding(truncatedText);
    }
  }

  /**
   * Simple keyword-based embedding fallback
   */
  simpleEmbedding(text) {
    // Simple TF-IDF like vector (for demonstration)
    const words = text.toLowerCase().split(/\s+/);
    const wordFreq = {};
    words.forEach(word => {
      wordFreq[word] = (wordFreq[word] || 0) + 1;
    });
    // Return a simple hash-based vector
    return Object.keys(wordFreq).slice(0, config.search.simpleEmbeddingMaxWords).map(word => wordFreq[word] / words.length);
  }

  /**
   * Calculate cosine similarity between two vectors
   */
  cosineSimilarity(vecA, vecB) {
    if (vecA.length === 0 || vecB.length === 0) return 0;
    
    let dotProduct = 0;
    let normA = 0;
    let normB = 0;

    const minLength = Math.min(vecA.length, vecB.length);
    for (let i = 0; i < minLength; i++) {
      dotProduct += vecA[i] * vecB[i];
      normA += vecA[i] * vecA[i];
      normB += vecB[i] * vecB[i];
    }

    if (normA === 0 || normB === 0) return 0;
    return dotProduct / (Math.sqrt(normA) * Math.sqrt(normB));
  }

  /**
   * Semantic search: find files similar to query
   */
  async semanticSearch(query, fileContents) {
    try {
      // Generate embedding for query
      const queryEmbedding = await this.generateEmbedding(query);

      if (queryEmbedding.length === 0) {
        return [];
      }

      // Calculate similarity scores
      const results = fileContents.map(fileContent => {
        if (!fileContent.embedding || fileContent.embedding.length === 0) {
          return { fileContent, score: 0 };
        }

        const similarity = this.cosineSimilarity(queryEmbedding, fileContent.embedding);
        return { fileContent, score: similarity };
      });

      // Sort by similarity score (descending)
      return results
        .filter(result => result.score > config.search.minSimilarityThreshold)
        .sort((a, b) => b.score - a.score);
    } catch (error) {
      console.error('Error in semantic search:', error);
      return [];
    }
  }

  /**
   * Keyword search - searches through extracted text content (not just filenames)
   */
  keywordSearch(query, fileContents) {
    const queryLower = query.toLowerCase();
    const queryWords = queryLower.split(/\s+/).filter(w => w.length > 2); // Ignore very short words

    return fileContents
      .map(fileContent => {
        const text = (fileContent.extractedText || '').toLowerCase();
        const fileName = (fileContent.file?.originalName || '').toLowerCase();
        
        let score = 0;
        const hasContent = text.length > 0;
        
        // PRIORITY 1: Content matches (much higher weight)
        if (hasContent) {
          // Exact phrase match in content (highest priority)
          if (text.includes(queryLower)) {
            score += config.scoring.exactFilenameMatch * 5; // Much higher for content
          }
          
          // Word matches in content
          queryWords.forEach(word => {
            const matches = (text.match(new RegExp(`\\b${word}\\b`, 'g')) || []).length;
            if (matches > 0) {
              score += matches * config.scoring.contentMatch * 3; // Boost content matches
            }
          });
          
          // Partial word matches in content
          queryWords.forEach(word => {
            const partialMatches = (text.match(new RegExp(word, 'g')) || []).length;
            if (partialMatches > 0) {
              score += partialMatches * config.scoring.contentMatch;
            }
          });
        }
        
        // PRIORITY 2: Filename matches (lower weight, only if no content)
        if (!hasContent || score === 0) {
          // Exact match in filename
          if (fileName.includes(queryLower)) {
            score += config.scoring.exactFilenameMatch;
          }
          
          // Word matches in filename
          queryWords.forEach(word => {
            if (fileName.includes(word)) {
              score += config.scoring.partialFilenameMatch;
            }
          });
        }
        
        return { fileContent, score };
      })
      .filter(result => result.score > 0)
      .sort((a, b) => b.score - a.score);
  }
}

module.exports = new AISearch();

