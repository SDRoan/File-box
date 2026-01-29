const { HfInference } = require('@huggingface/inference');
const File = require('../models/File');
const FileContent = require('../models/FileContent');
const Folder = require('../models/Folder');
const textExtractor = require('./textExtractor');
const config = require('../config/aiConfig');

// Initialize Hugging Face (free tier)
const hf = config.huggingface.apiKey 
  ? new HfInference(config.huggingface.apiKey)
  : new HfInference(); // Works without API key for free inference

class SmartOrganizationService {
  /**
   * Analyze a file and suggest folder organization
   * @param {Object} file - File document from database
   * @param {string} filePath - Physical file path
   * @returns {Promise<Object>} Organization suggestions
   */
  async analyzeFile(file, filePath) {
    try {
      // Get file content if available
      let fileContent = await FileContent.findOne({ file: file._id });
      let extractedText = '';

      if (fileContent && fileContent.extractedText) {
        extractedText = fileContent.extractedText.substring(0, 1000); // Limit for analysis
      } else {
        // Try to extract text if not available
        try {
          extractedText = await textExtractor.extractText(filePath, file.mimeType);
          extractedText = extractedText.substring(0, 1000);
        } catch (error) {
          console.log(`[SmartOrg] Could not extract text from ${file.originalName}`);
        }
      }

      // Analyze filename and content
      const filename = file.originalName.toLowerCase();
      const analysis = await this.analyzeContent(filename, extractedText, file.mimeType);

      return {
        suggestedFolder: analysis.folderName,
        category: analysis.category,
        tags: analysis.tags,
        confidence: analysis.confidence,
        reasoning: analysis.reasoning
      };
    } catch (error) {
      console.error('[SmartOrg] Error analyzing file:', error);
      return {
        suggestedFolder: null,
        category: 'other',
        tags: [],
        confidence: 0,
        reasoning: 'Could not analyze file'
      };
    }
  }

  /**
   * Analyze content using AI or rule-based approach
   */
  async analyzeContent(filename, content, mimeType) {
    // Combine filename and content for analysis
    const analysisText = `Filename: ${filename}\nContent preview: ${content.substring(0, 500)}`;

    // Try AI analysis first (if enabled)
    if (config.smartOrganization?.enabled !== false) {
      try {
        const aiAnalysis = await this.aiAnalyze(analysisText, filename, mimeType);
        if (aiAnalysis && aiAnalysis.folderName) {
          return aiAnalysis;
        }
      } catch (error) {
        console.log('[SmartOrg] AI analysis failed, using rule-based:', error.message);
      }
    }

    // Fallback to rule-based analysis
    return this.ruleBasedAnalysis(filename, content, mimeType);
  }

  /**
   * AI-powered content analysis using Hugging Face
   * Falls back to rule-based if AI fails
   */
  async aiAnalyze(text, filename, mimeType) {
    // For now, use rule-based analysis as it's more reliable
    // AI analysis can be enabled later with proper model configuration
    // This ensures the feature works out of the box
    return null; // Will fall back to rule-based
  }

  /**
   * Rule-based analysis (fallback)
   */
  ruleBasedAnalysis(filename, content, mimeType) {
    const lowerFilename = filename.toLowerCase();
    const lowerContent = content.toLowerCase();

    // Define patterns
    const patterns = {
      homework: {
        keywords: ['homework', 'hw', 'assignment', 'hw#', 'homework #', 'due', 'submit'],
        folderName: 'Homework',
        category: 'academic',
        tags: ['homework', 'assignment']
      },
      resume: {
        keywords: ['resume', 'cv', 'curriculum vitae', 'cover letter', 'application'],
        folderName: 'Resumes',
        category: 'professional',
        tags: ['resume', 'cv', 'job']
      },
      project: {
        keywords: ['project', 'proj', 'final project', 'capstone'],
        folderName: 'Projects',
        category: 'projects',
        tags: ['project']
      },
      exam: {
        keywords: ['exam', 'midterm', 'final', 'test', 'quiz', 'practice exam'],
        folderName: 'Exams',
        category: 'academic',
        tags: ['exam', 'test']
      },
      lecture: {
        keywords: ['lecture', 'lec', 'notes', 'class notes', 'slides'],
        folderName: 'Lectures',
        category: 'academic',
        tags: ['lecture', 'notes']
      },
      code: {
        keywords: ['.js', '.py', '.java', '.cpp', '.ts', '.jsx', 'function', 'class', 'import'],
        folderName: 'Code',
        category: 'code',
        tags: ['code', 'programming']
      },
      documents: {
        keywords: ['.pdf', '.doc', '.docx', '.txt', 'document', 'report'],
        folderName: 'Documents',
        category: 'documents',
        tags: ['document']
      },
      photos: {
        keywords: ['.jpg', '.jpeg', '.png', '.gif', '.heic', 'photo', 'image'],
        folderName: 'Photos',
        category: 'media',
        tags: ['photo', 'image']
      }
    };

    // Check patterns
    for (const [key, pattern] of Object.entries(patterns)) {
      const matches = pattern.keywords.filter(kw => 
        lowerFilename.includes(kw) || lowerContent.includes(kw)
      );

      if (matches.length > 0) {
        return {
          folderName: pattern.folderName,
          category: pattern.category,
          tags: pattern.tags,
          confidence: 0.7,
          reasoning: `Matched keywords: ${matches.join(', ')}`
        };
      }
    }

    // Default
    return {
      folderName: 'Other',
      category: 'other',
      tags: [],
      confidence: 0.3,
      reasoning: 'No specific pattern matched'
    };
  }

  /**
   * Get organization suggestions for multiple files
   */
  async getBulkSuggestions(files, userId) {
    const suggestions = [];
    const fs = require('fs-extra');

    for (const file of files) {
      try {
        const filePath = file.path;
        if (await fs.pathExists(filePath)) {
          const suggestion = await this.analyzeFile(file, filePath);
          suggestions.push({
            fileId: file._id,
            fileName: file.originalName,
            ...suggestion
          });
        }
      } catch (error) {
        console.error(`[SmartOrg] Error analyzing ${file.originalName}:`, error);
      }
    }

    // Group suggestions by folder
    const folderGroups = {};
    suggestions.forEach(s => {
      const folderName = s.suggestedFolder || 'Other';
      if (!folderGroups[folderName]) {
        folderGroups[folderName] = [];
      }
      folderGroups[folderName].push(s);
    });

    return {
      suggestions,
      folderGroups,
      totalFiles: files.length
    };
  }

  /**
   * Sanitize folder name
   */
  sanitizeFolderName(name) {
    if (!name) return 'Other';
    
    // Remove special characters, keep alphanumeric, spaces, hyphens, underscores
    let sanitized = name
      .replace(/[^a-zA-Z0-9\s\-_]/g, '')
      .replace(/\s+/g, ' ')
      .trim();

    // Limit length
    if (sanitized.length > 50) {
      sanitized = sanitized.substring(0, 50);
    }

    // Ensure it's not empty
    if (!sanitized) {
      sanitized = 'Other';
    }

    return sanitized;
  }
}

module.exports = new SmartOrganizationService();

