const { HfInference } = require('@huggingface/inference');
const axios = require('axios');
const config = require('../config/aiConfig');

// Initialize Hugging Face (free tier) - fallback only
const hf = config.huggingface.apiKey 
  ? new HfInference(config.huggingface.apiKey)
  : new HfInference(); // Works without API key for free inference

// Helper function to call OpenRouter API with free models
async function callOpenRouter(messages, maxTokens = 2000, temperature = 0.7) {
  const openRouterApiKey = process.env.OPENROUTER_API_KEY;
  
  if (!openRouterApiKey) {
    throw new Error('OpenRouter API key not configured');
  }

  // Use free model for summarization
  const freeModel = 'google/gemini-flash-1.5-8b:free'; // Fast and free

  const response = await axios.post(
    'https://openrouter.ai/api/v1/chat/completions',
    {
      model: freeModel,
      messages,
      max_tokens: maxTokens,
      temperature
    },
    {
      headers: {
        'Authorization': `Bearer ${openRouterApiKey}`,
        'HTTP-Referer': process.env.APP_URL || 'http://localhost:3000',
        'X-Title': 'File Box File Management',
        'Content-Type': 'application/json'
      }
    }
  );

  return response.data.choices[0]?.message?.content || '';
}

class SummarizationService {
  /**
   * Generate a summary of the given text using free AI models
   * @param {string} text - The text to summarize
   * @param {string} mimeType - The MIME type of the file (optional, for DOCX detection)
   */
  async generateSummary(text, mimeType = null) {
    if (!text || text.trim().length === 0) {
      return '';
    }

    if (!config.summarization.enabled) {
      console.log('[Summarization] Summarization is disabled');
      return '';
    }

    try {
      // Check if this is a DOCX file - use expanded summary settings
      const isDocx = mimeType && (
        mimeType.includes('word') ||
        mimeType.includes('document') ||
        mimeType.includes('msword') ||
        mimeType.includes('vnd.openxmlformats-officedocument.wordprocessingml')
      );

      // For DOCX files, use MUCH larger limits for comprehensive summaries
      const maxSummaryLength = isDocx 
        ? Math.max(config.summarization.maxSummaryLength * 10, 1200) // At least 1200 tokens for DOCX (very comprehensive)
        : config.summarization.maxSummaryLength;
      
      const minLength = isDocx
        ? Math.max(config.summarization.minLength * 5, 200) // At least 200 tokens minimum for DOCX
        : config.summarization.minLength;

      // For DOCX, allow MUCH more input text to be processed (process entire document)
      const maxInputChars = isDocx
        ? config.summarization.maxInputLength * 16 // Allow 16x more input for DOCX (process most/all of document)
        : config.summarization.maxInputLength * 4; // Rough estimate: 1 token ≈ 4 chars

      const truncatedText = text.length > maxInputChars 
        ? text.substring(0, maxInputChars) 
        : text;

      console.log(`[Summarization] Generating ${isDocx ? 'EXPANDED' : 'standard'} summary using model: ${config.summarization.model}`);
      console.log(`[Summarization] Input length: ${truncatedText.length} chars`);
      console.log(`[Summarization] Max summary length: ${maxSummaryLength} tokens, Min: ${minLength} tokens`);

      // Use OpenRouter with free models for better summaries
      console.log(`[Summarization] Using OpenRouter with free AI model for ${isDocx ? 'DOCX' : 'TXT'} file...`);
      
      try {
        // Create a professional ChatGPT-level prompt for summarization
        const systemPrompt = `You are an expert academic and professional document analyst with exceptional reading comprehension and writing skills. Your task is to read documents and create comprehensive, professional summaries that rival ChatGPT in quality.

**Your summary must:**

1. **Provide a clear introduction** - Start with 1-2 sentences that explain what this document is about, its purpose, and its main subject matter. Write this as if explaining to an educated professional who hasn't read the document.

2. **Explain the main content** - In 2-4 well-written paragraphs, explain:
   - What the document discusses or analyzes
   - The key arguments, findings, or information presented
   - Important details, examples, or evidence mentioned
   - The structure and flow of ideas

3. **Highlight key points** - Present 3-7 main points or takeaways in a clear, organized manner. Each point should be explained in your own words, not copied verbatim.

4. **Provide context and significance** - Explain why this information matters, what it means, or what implications it has.

5. **Write professionally** - Use clear, professional language. Write in complete sentences with proper flow. Avoid keyword lists or fragmented phrases. Make it read like a well-written academic or professional summary.

**Critical requirements:**
- DO NOT just list keywords or phrases
- DO NOT copy sentences verbatim from the document
- DO write in flowing, professional prose
- DO explain concepts and ideas clearly
- DO make connections between different parts of the document
- DO write as if you're a knowledgeable expert explaining the document to a colleague

Your summary should be informative, well-structured, and professional - similar to what ChatGPT would produce.`;

        const userPrompt = `Please read the following ${isDocx ? 'document' : 'text file'} and create a comprehensive, professional summary:

${truncatedText}

Write a professional summary that:
- Clearly explains what this document is about
- Describes the main content and key ideas
- Identifies and explains the most important points
- Provides context and significance
- Uses clear, professional language throughout

Write in complete sentences and paragraphs. Make it informative and well-structured.`;

        // Calculate max tokens (rough estimate: 1 token ≈ 4 characters)
        // Increase token limit for better summaries
        const maxTokens = Math.min(
          Math.floor(maxSummaryLength * 6), // More tokens for better quality
          6000 // Increased cap for comprehensive summaries
        );

        const summary = await callOpenRouter(
          [
            { role: 'system', content: systemPrompt },
            { role: 'user', content: userPrompt }
          ],
          maxTokens,
          0.4 // Slightly higher temperature for more natural, varied writing
        );

        if (summary && summary.trim().length > 100) {
          console.log(`[Summarization] ✅ Generated summary using OpenRouter (${summary.length} chars)`);
          
          // Parse and structure the summary
          const structuredSummary = this.parseAndStructureSummary(summary.trim());
          return structuredSummary;
        } else {
          console.log('[Summarization] ⚠️ Summary too short, trying fallback...');
          // Fallback to analytical summary
          const fallbackSummary = this.generateAnalyticalSummary(truncatedText, maxSummaryLength);
          return this.parseAndStructureSummary(fallbackSummary);
        }
      } catch (openRouterError) {
        console.error('[Summarization] OpenRouter error:', openRouterError.message);
        console.log('[Summarization] Falling back to Hugging Face...');
        
        // Fallback to Hugging Face if OpenRouter fails
        try {
          const response = await hf.summarization({
            model: config.summarization.model,
            inputs: truncatedText,
            parameters: {
              max_length: maxSummaryLength,
              min_length: minLength,
              do_sample: true,
              temperature: 0.5,
              repetition_penalty: 1.3,
            }
          });

          let summary = response?.summary_text || '';
          
          // Post-process to improve summary quality
          if (summary) {
            summary = this.ensureActualSummary(summary, truncatedText);
          }
          
          if (summary && summary.trim().length > 50) {
            console.log(`[Summarization] ✅ Generated summary using Hugging Face (${summary.length} chars)`);
            return summary.trim();
          }
        } catch (hfError) {
          console.error('[Summarization] Hugging Face error:', hfError.message);
        }
        
        // Final fallback: analytical summary
        console.log('[Summarization] Using analytical summary as final fallback...');
        return this.generateAnalyticalSummary(truncatedText, maxSummaryLength);
      }
    } catch (error) {
      console.error('[Summarization] ❌ Error generating summary:', error.message);
      
      // Fallback: Generate a simple extractive summary
      if (config.summarization.fallbackToExtractive !== false) {
        console.log('[Summarization] Attempting fallback extractive summary...');
        return this.generateExtractiveSummary(text, mimeType);
      }
      
      return '';
    }
  }

  /**
   * Generate summary using text generation with a prompt (better for DOCX files)
   * This ensures actual summarization rather than just text extraction
   */
  async generatePromptBasedSummary(text, maxLength) {
    try {
      // Extract key information first
      const textPreview = text.substring(0, Math.min(text.length, 12000));
      
      // Create a STRONG prompt that forces explanation, not copying
      const prompt = `TASK: Analyze and summarize the following document.

CRITICAL INSTRUCTIONS:
- DO NOT copy sentences verbatim from the document
- EXPLAIN what the document is about in your own words
- DESCRIBE the main topics, themes, and key points
- PROVIDE analysis and context
- Write as if you are explaining the document to someone who hasn't read it

Document:
${textPreview}

Your comprehensive summary explaining what this document is about:`;

      console.log(`[Summarization] Using prompt-based generation with strict instructions...`);
      
      // Try using Mistral for better instruction following
      try {
        const response = await hf.textGeneration({
          model: 'mistralai/Mistral-7B-Instruct-v0.2',
          inputs: prompt,
          parameters: {
            max_new_tokens: Math.floor(maxLength * 0.95),
            temperature: 0.7, // Higher for more creative/analytical output
            top_p: 0.9,
            repetition_penalty: 1.5, // Very strong penalty
            return_full_text: false,
          }
        });

        let generatedText = response?.generated_text || '';
        
        if (generatedText && generatedText.trim().length > 150) {
          // Aggressively check and fix if it's still copying
          const processed = this.ensureActualSummary(generatedText, textPreview);
          console.log(`[Summarization] ✅ Generated prompt-based summary (${processed.length} chars)`);
          return processed.trim();
        }
      } catch (mistralError) {
        console.log(`[Summarization] Mistral unavailable, using analytical approach: ${mistralError.message}`);
      }

      // Fallback: Generate analytical summary directly
      console.log(`[Summarization] Generating analytical summary as fallback...`);
      const analyticalSummary = this.generateAnalyticalSummary(textPreview, maxLength);
      
      if (analyticalSummary && analyticalSummary.length > 100) {
        return analyticalSummary;
      }

      // Last resort: Use BART but with very aggressive post-processing
      const chunks = this.splitIntoChunks(textPreview, 2000);
      const summaries = [];
      
      for (const chunk of chunks.slice(0, 4)) {
        try {
          // Use a prompt that emphasizes explanation
          const chunkWithPrompt = `Summarize and explain what this text is about:\n\n${chunk}`;
          
          const response = await hf.summarization({
            model: config.summarization.model,
            inputs: chunkWithPrompt,
            parameters: {
              max_length: Math.floor(maxLength / 4),
              min_length: Math.floor(maxLength / 4 * 0.4),
              do_sample: true,
              temperature: 0.6,
              repetition_penalty: 1.4,
            }
          });

          if (response?.summary_text) {
            const processed = this.ensureActualSummary(response.summary_text, chunk);
            summaries.push(processed);
          }
        } catch (err) {
          console.log(`[Summarization] Error in chunk: ${err.message}`);
        }
      }

      if (summaries.length > 0) {
        const combined = summaries.join(' ');
        return this.ensureActualSummary(combined, textPreview);
      }

      // Final fallback: analytical summary
      return this.generateAnalyticalSummary(textPreview, maxLength);
    } catch (error) {
      console.error('[Summarization] Error in prompt-based summary:', error.message);
      // Return analytical summary as last resort
      return this.generateAnalyticalSummary(text.substring(0, 5000), 500);
    }
  }

  /**
   * Split text into chunks for processing
   */
  splitIntoChunks(text, chunkSize) {
    const paragraphs = text.split(/\n\s*\n/).filter(p => p.trim().length > 50);
    const chunks = [];
    let currentChunk = '';

    for (const para of paragraphs) {
      if (currentChunk.length + para.length > chunkSize && currentChunk.length > 0) {
        chunks.push(currentChunk.trim());
        currentChunk = para;
      } else {
        currentChunk += (currentChunk ? '\n\n' : '') + para;
      }
    }

    if (currentChunk.trim().length > 0) {
      chunks.push(currentChunk.trim());
    }

    return chunks.length > 0 ? chunks : [text];
  }

  /**
   * Post-process summary to ensure it's actually summarizing, not copying
   */
  postProcessSummary(summary, originalText) {
    return this.ensureActualSummary(summary, originalText);
  }

  /**
   * Check if summary is mostly original text (copying)
   */
  isMostlyOriginal(summary, originalText) {
    if (!summary || summary.length < 50) {
      return false;
    }

    const summaryWords = summary.toLowerCase().split(/\s+/);
    const originalWords = originalText.toLowerCase().split(/\s+/);
    const originalTextLower = originalWords.join(' ');
    
    // Check for long verbatim sequences (6+ words)
    let verbatimMatches = 0;
    const checkLength = 6;
    
    for (let i = 0; i <= summaryWords.length - checkLength; i++) {
      const sequence = summaryWords.slice(i, i + checkLength).join(' ');
      if (originalTextLower.includes(sequence)) {
        verbatimMatches++;
      }
    }
    
    const verbatimRatio = verbatimMatches / Math.max(1, summaryWords.length - checkLength);
    return verbatimRatio > 0.25; // More than 25% verbatim = mostly copying
  }

  /**
   * Ensure the summary is actually summarizing, not just copying text
   */
  ensureActualSummary(summary, originalText) {
    if (!summary || summary.length < 50) {
      return summary;
    }

    // Check if summary is mostly verbatim copies
    if (this.isMostlyOriginal(summary, originalText)) {
      console.log(`[Summarization] ⚠️ Summary is mostly verbatim copying. Replacing with analytical summary...`);
      return this.generateAnalyticalSummary(originalText, summary.length);
    }

    // Add context if summary doesn't explain what the document is about
    const hasContext = summary.toLowerCase().includes('document') || 
                       summary.toLowerCase().includes('about') ||
                       summary.toLowerCase().includes('discusses') ||
                       summary.toLowerCase().includes('explains') ||
                       summary.toLowerCase().includes('describes') ||
                       summary.toLowerCase().includes('analyzes') ||
                       summary.toLowerCase().includes('explores') ||
                       summary.toLowerCase().includes('examines');

    if (!hasContext && summary.length > 100) {
      // Prepend an explanatory introduction
      const firstSentence = summary.split(/[.!?]+/)[0];
      if (firstSentence && firstSentence.length < 150) {
        return `This document discusses and explains: ${firstSentence.toLowerCase()}. ${summary.substring(firstSentence.length).trim()}`;
      } else {
        return `This document is about: ${summary}`;
      }
    }

    return summary;
  }

  /**
   * Generate an analytical summary that explains rather than copies
   * This method analyzes the content and creates an explanation - NO COPYING
   */
  generateAnalyticalSummary(text, targetLength) {
    // Extract key information and create an analytical summary
    const sentences = text.split(/[.!?]+/).filter(s => s.trim().length > 15);
    
    if (sentences.length === 0) {
      return 'This document contains text content that requires analysis.';
    }

    // Identify main topics by looking for repeated significant words (nouns and important terms)
    const words = text.toLowerCase()
      .replace(/[^\w\s]/g, ' ')
      .split(/\s+/)
      .filter(w => w.length > 4 && !['which', 'their', 'there', 'these', 'those', 'where', 'would', 'could', 'should', 'about', 'other', 'first', 'second', 'third'].includes(w));
    
    const wordFreq = {};
    words.forEach(word => {
      wordFreq[word] = (wordFreq[word] || 0) + 1;
    });
    
    const topWords = Object.entries(wordFreq)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([word]) => word);

    // Analyze document structure
    const paragraphs = text.split(/\n\s*\n/).filter(p => p.trim().length > 30);
    const hasHeadings = text.match(/^[A-Z#][^\n]{10,60}$/gm) || [];
    
    // Analyze content by sections
    const firstThird = sentences.slice(0, Math.floor(sentences.length * 0.33));
    const middleThird = sentences.slice(
      Math.floor(sentences.length * 0.33), 
      Math.floor(sentences.length * 0.66)
    );
    const lastThird = sentences.slice(-Math.floor(sentences.length * 0.33));

    // Build comprehensive analytical summary - EXPLAIN, DON'T COPY
    let analyticalSummary = '';
    
    // 1. Document Purpose and Main Subject
    const mainTopics = topWords.slice(0, 6).join(', ');
    const documentType = this.identifyDocumentType(text);
    analyticalSummary += `This ${documentType} focuses on ${mainTopics || 'various topics'}. `;
    
    // 2. Opening Content Analysis
    if (firstThird.length > 0) {
      const openingConcepts = this.extractKeyConcepts(firstThird.join(' '));
      const openingThemes = this.identifyThemes(firstThird.join(' '));
      if (openingConcepts) {
        analyticalSummary += `The document opens by examining ${openingConcepts}. `;
      }
      if (openingThemes.length > 0 && openingThemes.length <= 3) {
        analyticalSummary += `Initial themes explored include ${openingThemes.slice(0, 2).join(' and ')}. `;
      }
    }
    
    // 3. Middle Content Analysis
    if (middleThird.length > 2) {
      const middleConcepts = this.extractKeyConcepts(middleThird.join(' '));
      if (middleConcepts) {
        analyticalSummary += `The middle section delves into ${middleConcepts}. `;
      }
      
      // Identify what the document is explaining or analyzing
      const analysisType = this.identifyAnalysisType(middleThird.join(' '));
      if (analysisType) {
        analyticalSummary += `${analysisType} `;
      }
    }
    
    // 4. Key Themes Throughout
    const allThemes = this.identifyThemes(text);
    if (allThemes.length > 0) {
      analyticalSummary += `Throughout the document, recurring themes include: ${allThemes.slice(0, 4).join(', ')}. `;
    }
    
    // 5. Document Structure and Organization
    if (paragraphs.length > 2) {
      analyticalSummary += `The content is organized into ${paragraphs.length} main sections or paragraphs. `;
    }
    
    if (hasHeadings.length > 0) {
      const headingTopics = hasHeadings.slice(0, 4).map(h => h.replace(/^#+\s*/, '').trim()).join(', ');
      analyticalSummary += `Major topics covered include: ${headingTopics}. `;
    }
    
    // 6. Conclusion and Final Points
    if (lastThird.length > 0) {
      const conclusionConcepts = this.extractKeyConcepts(lastThird.join(' '));
      const conclusionThemes = this.identifyThemes(lastThird.join(' '));
      if (conclusionConcepts) {
        analyticalSummary += `The document concludes by addressing ${conclusionConcepts}. `;
      }
      if (conclusionThemes.length > 0) {
        analyticalSummary += `Final considerations include ${conclusionThemes[0]}. `;
      }
    }
    
    // 7. Overall Document Analysis
    const documentPurpose = this.identifyDocumentPurpose(text);
    if (documentPurpose) {
      analyticalSummary += `Overall, this document serves to ${documentPurpose}.`;
    }

    // Ensure comprehensive length
    if (analyticalSummary.length < Math.min(targetLength * 0.6, 400)) {
      // Add more detailed analysis of key points
      const keyPoints = this.extractKeyPoints(sentences, topWords);
      if (keyPoints.length > 0) {
        analyticalSummary += ` Key points discussed throughout include: ${keyPoints.slice(0, 5).join(', ')}.`;
      }
    }

    return analyticalSummary.trim() || 'This document contains detailed information covering multiple topics and themes.';
  }

  /**
   * Identify what type of document this is
   */
  identifyDocumentType(text) {
    const lowerText = text.toLowerCase();
    if (lowerText.includes('assignment') || lowerText.includes('homework')) return 'assignment';
    if (lowerText.includes('essay') || lowerText.includes('paper')) return 'essay';
    if (lowerText.includes('report')) return 'report';
    if (lowerText.includes('analysis') || lowerText.includes('analyze')) return 'analysis';
    if (lowerText.includes('policy') || lowerText.includes('procedure')) return 'policy document';
    if (lowerText.includes('guide') || lowerText.includes('manual')) return 'guide';
    return 'document';
  }

  /**
   * Identify what type of analysis or explanation the document provides
   */
  identifyAnalysisType(text) {
    const lowerText = text.toLowerCase();
    if (lowerText.includes('compare') || lowerText.includes('comparison')) return 'It provides comparative analysis.';
    if (lowerText.includes('explain') || lowerText.includes('explanation')) return 'It offers detailed explanations.';
    if (lowerText.includes('describe') || lowerText.includes('description')) return 'It provides comprehensive descriptions.';
    if (lowerText.includes('discuss') || lowerText.includes('discussion')) return 'It presents detailed discussions.';
    if (lowerText.includes('analyze') || lowerText.includes('analysis')) return 'It conducts thorough analysis.';
    return null;
  }

  /**
   * Identify the overall purpose of the document
   */
  identifyDocumentPurpose(text) {
    const lowerText = text.toLowerCase();
    if (lowerText.includes('how to') || lowerText.includes('guide')) return 'provide guidance and instructions';
    if (lowerText.includes('explain') || lowerText.includes('understand')) return 'explain concepts and ideas';
    if (lowerText.includes('analyze') || lowerText.includes('examine')) return 'analyze and examine topics';
    if (lowerText.includes('compare') || lowerText.includes('contrast')) return 'compare and contrast different aspects';
    if (lowerText.includes('discuss') || lowerText.includes('explore')) return 'discuss and explore various topics';
    return 'present and discuss information';
  }

  /**
   * Extract key points from sentences (not verbatim)
   */
  extractKeyPoints(sentences, importantWords) {
    const keyPoints = new Set();
    
    sentences.forEach(sentence => {
      const sWords = sentence.toLowerCase().split(/\s+/);
      // Find sentences that contain important words
      const hasImportantWords = sWords.some(w => importantWords.includes(w));
      
      if (hasImportantWords && sentence.length > 30 && sentence.length < 150) {
        // Extract key concepts from this sentence (not the whole sentence)
        const concepts = this.extractKeyConcepts(sentence);
        if (concepts && concepts.split(',').length <= 3) {
          keyPoints.add(concepts);
        }
      }
    });
    
    return Array.from(keyPoints);
  }

  /**
   * Generate enhanced extractive summary that explains rather than copies
   */
  generateEnhancedExtractiveSummary(text) {
    const sentences = text.split(/[.!?]+/).filter(s => s.trim().length > 20);
    
    if (sentences.length === 0) {
      return 'This document contains text content.';
    }

    // Instead of copying sentences, extract concepts and create explanations
    const firstFew = sentences.slice(0, Math.min(5, sentences.length));
    const concepts = [];
    
    firstFew.forEach(sent => {
      const keyConcepts = this.extractKeyConcepts(sent);
      if (keyConcepts) {
        concepts.push(keyConcepts);
      }
    });

    if (concepts.length > 0) {
      return `This document discusses ${concepts.slice(0, 4).join(', ')}. It covers these topics in detail, providing analysis and explanations throughout.`;
    }

    return 'This document contains detailed information on various topics.';
  }

  /**
   * Extract key concepts from text (not verbatim)
   */
  extractKeyConcepts(text) {
    const words = text.toLowerCase()
      .replace(/[^\w\s]/g, ' ')
      .split(/\s+/)
      .filter(w => w.length > 4);
    
    const wordFreq = {};
    words.forEach(word => {
      wordFreq[word] = (wordFreq[word] || 0) + 1;
    });
    
    const topConcepts = Object.entries(wordFreq)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 4)
      .map(([word]) => word);
    
    return topConcepts.join(', ') || null;
  }

  /**
   * Identify main themes in the document
   */
  identifyThemes(text) {
    // Look for repeated phrases and concepts
    const sentences = text.split(/[.!?]+/).filter(s => s.trim().length > 20);
    const themes = new Set();
    
    // Extract noun phrases (simplified)
    sentences.forEach(sentence => {
      const words = sentence.toLowerCase().split(/\s+/);
      // Look for adjective + noun patterns
      for (let i = 0; i < words.length - 1; i++) {
        if (words[i].length > 4 && words[i + 1].length > 4) {
          const phrase = `${words[i]} ${words[i + 1]}`;
          if (phrase.length > 8 && phrase.length < 25) {
            themes.add(phrase);
          }
        }
      }
    });
    
    return Array.from(themes).slice(0, 5);
  }

  /**
   * Generate a more detailed summary for DOCX files by processing text in sections
   * This method processes the entire document in multiple passes for maximum information
   */
  async generateDetailedSummary(text, maxLength, minLength) {
    try {
      // Split text into logical sections (by paragraphs, headings, etc.)
      const paragraphs = text.split(/\n\s*\n/).filter(p => p.trim().length > 30);
      
      if (paragraphs.length === 0) {
        // Fallback: split by sentences if no paragraphs
        const sentences = text.split(/[.!?]+/).filter(s => s.trim().length > 20);
        if (sentences.length === 0) {
          return '';
        }
        // Group sentences into chunks
        const chunkSize = Math.ceil(sentences.length / 5);
        const chunks = [];
        for (let i = 0; i < sentences.length; i += chunkSize) {
          chunks.push(sentences.slice(i, i + chunkSize).join('. '));
        }
        return await this.processMultipleChunks(chunks, maxLength, minLength);
      }

      // Process document in multiple comprehensive passes
      const allSummaries = [];
      
      // Pass 1: Process first 30% of document for main overview
      const mainChunkSize = Math.ceil(paragraphs.length * 0.3);
      const mainText = paragraphs.slice(0, mainChunkSize).join('\n\n');
      const mainLimit = Math.floor(maxLength * 0.4); // Use 40% for main overview
      
      try {
        const mainSummary = await hf.summarization({
          model: config.summarization.model,
          inputs: mainText.substring(0, mainLimit * 4),
          parameters: {
            max_length: mainLimit,
            min_length: Math.floor(minLength * 0.4),
            do_sample: true,
            temperature: 0.3,
            repetition_penalty: 1.2,
          }
        });
        if (mainSummary?.summary_text) {
          allSummaries.push('=== MAIN OVERVIEW ===\n' + mainSummary.summary_text);
        }
      } catch (err) {
        console.log('[Summarization] Error in main summary:', err.message);
      }

      // Pass 2: Process middle sections (30-70%) for detailed content
      const middleStart = mainChunkSize;
      const middleEnd = Math.ceil(paragraphs.length * 0.7);
      if (middleEnd > middleStart) {
        const middleText = paragraphs.slice(middleStart, middleEnd).join('\n\n');
        const middleLimit = Math.floor(maxLength * 0.35); // Use 35% for detailed content
        
        try {
          const middleSummary = await hf.summarization({
            model: config.summarization.model,
            inputs: middleText.substring(0, middleLimit * 4),
            parameters: {
              max_length: middleLimit,
              min_length: Math.floor(minLength * 0.35),
              do_sample: true,
              temperature: 0.3,
              repetition_penalty: 1.2,
            }
          });
          if (middleSummary?.summary_text) {
            allSummaries.push('\n\n=== DETAILED CONTENT ===\n' + middleSummary.summary_text);
          }
        } catch (err) {
          console.log('[Summarization] Error in middle summary:', err.message);
        }
      }

      // Pass 3: Process remaining sections (70-100%) for additional key points
      if (middleEnd < paragraphs.length) {
        const remainingText = paragraphs.slice(middleEnd).join('\n\n');
        const remainingLimit = Math.floor(maxLength * 0.25); // Use 25% for key points
        
        try {
          const remainingSummary = await hf.summarization({
            model: config.summarization.model,
            inputs: remainingText.substring(0, remainingLimit * 4),
            parameters: {
              max_length: remainingLimit,
              min_length: Math.floor(minLength * 0.25),
              do_sample: true,
              temperature: 0.3,
              repetition_penalty: 1.2,
            }
          });
          if (remainingSummary?.summary_text) {
            allSummaries.push('\n\n=== ADDITIONAL KEY POINTS ===\n' + remainingSummary.summary_text);
          }
        } catch (err) {
          console.log('[Summarization] Error in remaining summary:', err.message);
        }
      }

      const combinedSummary = allSummaries.join('');
      
      // If combined summary is still shorter than desired, add extractive summary
      if (combinedSummary.length < minLength * 4) {
        const extractive = this.generateExtractiveSummary(text, 'application/vnd.openxmlformats-officedocument.wordprocessingml.document');
        if (extractive && extractive.length > 100) {
          return combinedSummary + '\n\n=== KEY EXTRACTS ===\n' + extractive;
        }
      }

      return combinedSummary.trim();
    } catch (error) {
      console.error('[Summarization] Error generating detailed summary:', error.message);
      // Fallback to extractive summary
      return this.generateExtractiveSummary(text, 'application/vnd.openxmlformats-officedocument.wordprocessingml.document');
    }
  }

  /**
   * Process multiple chunks of text and combine summaries
   */
  async processMultipleChunks(chunks, maxLength, minLength) {
    const summaries = [];
    const chunkLimit = Math.floor(maxLength / chunks.length);
    
    for (let i = 0; i < Math.min(chunks.length, 5); i++) {
      try {
        const chunkSummary = await hf.summarization({
          model: config.summarization.model,
          inputs: chunks[i].substring(0, chunkLimit * 4),
          parameters: {
            max_length: chunkLimit,
            min_length: Math.floor(minLength / chunks.length),
            do_sample: false,
          }
        });
        if (chunkSummary?.summary_text) {
          summaries.push(chunkSummary.summary_text);
        }
      } catch (err) {
        console.log(`[Summarization] Error processing chunk ${i}:`, err.message);
      }
    }
    
    return summaries.join('\n\n');
  }

  /**
   * Fallback: Generate a simple extractive summary (first N sentences)
   * @param {string} text - The text to summarize
   * @param {string} mimeType - The MIME type (for DOCX, use more sentences)
   */
  generateExtractiveSummary(text, mimeType = null) {
    const isDocx = mimeType && (
      mimeType.includes('word') ||
      mimeType.includes('document') ||
      mimeType.includes('msword') ||
      mimeType.includes('vnd.openxmlformats-officedocument.wordprocessingml')
    );

    const sentences = text.split(/[.!?]+/).filter(s => s.trim().length > 0);
    
    // For DOCX files, use more sentences (up to 15 or 30% of total)
    const maxSentences = isDocx
      ? Math.min(15, Math.ceil(sentences.length * 0.3))
      : Math.min(3, Math.ceil(sentences.length * 0.2));
    
    if (sentences.length === 0) {
      return '';
    }

    const summary = sentences.slice(0, maxSentences).join('. ').trim();
    return summary + (summary.endsWith('.') ? '' : '.');
  }

  /**
   * Check if summarization is available
   */
  isAvailable() {
    return config.summarization.enabled;
  }

  /**
   * Get summarization configuration
   */
  getConfig() {
    return {
      enabled: config.summarization.enabled,
      model: config.summarization.model,
      maxInputLength: config.summarization.maxInputLength,
      maxSummaryLength: config.summarization.maxSummaryLength,
      minLength: config.summarization.minLength,
    };
  }
}

module.exports = new SummarizationService();









