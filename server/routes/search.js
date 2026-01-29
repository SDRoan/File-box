const express = require('express');
const auth = require('../middleware/auth');
const File = require('../models/File');
const Folder = require('../models/Folder');
const FileContent = require('../models/FileContent');
const aiSearch = require('../services/aiSearch');
const config = require('../config/aiConfig');
const router = express.Router();

/**
 * AI-powered semantic search
 * Searches through file contents, not just filenames
 */
router.get('/ai', auth, async (req, res) => {
  try {
    const { q } = req.query;
    
    if (!q || q.trim().length === 0) {
      return res.json({ files: [], folders: [] });
    }

    const query = q.trim();
    const userId = req.user._id;
    
    console.log(`[AI Search] Query: "${query}" from user ${userId}`);

    // Get all user's files
    const files = await File.find({
      owner: userId,
      isTrashed: { $ne: true }
    }).populate('parentFolder');

    // Get file contents with embeddings
    const fileIds = files.map(f => f._id);
    const fileContents = await FileContent.find({
      file: { $in: fileIds }
    }).populate({
      path: 'file',
      populate: { path: 'parentFolder' }
    });

    // Perform semantic search on files with embeddings (content-based)
    const semanticResults = await aiSearch.semanticSearch(query, fileContents);
    
    // Also do keyword search on extracted text content (even without embeddings)
    // This searches through the actual text content, not just filenames
    const keywordResults = aiSearch.keywordSearch(query, fileContents);
    
    // Also search files without any content extraction (filename only)
    const filesWithoutContent = files.filter(
      f => !fileContents.some(fc => {
        const fileContentFileId = fc.file && fc.file._id ? fc.file._id.toString() : null;
        return fileContentFileId === f._id.toString();
      })
    );
    
    const filenameOnlyResults = aiSearch.keywordSearch(query, 
      filesWithoutContent.map(f => ({
        file: f,
        extractedText: '',
        embedding: []
      }))
    );

    // Combine results - prioritize semantic > content keyword > filename only
    const allResults = [
      ...semanticResults.map(r => ({ file: r.fileContent.file, score: r.score * 1.5, type: 'semantic' })), // Boost semantic results
      ...keywordResults.map(r => ({ file: r.fileContent.file, score: r.score, type: 'content-keyword' })),
      ...filenameOnlyResults.map(r => ({ file: r.fileContent.file, score: r.score * 0.3, type: 'filename-only' })) // Lower priority for filename-only
    ];

    // Remove duplicates and sort by score
    const uniqueResults = [];
    const seenIds = new Set();
    
    allResults
      .sort((a, b) => b.score - a.score)
      .forEach(result => {
        const fileId = result.file._id.toString();
        if (!seenIds.has(fileId)) {
          seenIds.add(fileId);
          uniqueResults.push(result.file);
        }
      });

    // Also search folders by name
    const folders = await Folder.find({
      owner: userId,
      isTrashed: { $ne: true },
      name: { $regex: query, $options: 'i' }
    }).limit(config.search.folderSearchLimit);

    // Log search stats for debugging
    console.log(`[AI Search] Results: ${semanticResults.length} semantic, ${keywordResults.length} content-keyword, ${filenameOnlyResults.length} filename-only`);
    console.log(`[AI Search] Total unique results: ${uniqueResults.length}`);
    console.log(`[AI Search] Files with content extracted: ${fileContents.length}/${files.length}`);

    // Return results (already sorted by relevance score)
    const allFiles = uniqueResults.slice(0, config.search.maxResults);

    res.json({
      files: allFiles,
      folders: folders,
      query: query,
      searchType: 'ai',
      debug: {
        semanticResults: semanticResults.length,
        contentKeywordResults: keywordResults.length,
        filenameOnlyResults: filenameOnlyResults.length,
        filesWithContent: fileContents.length,
        totalFiles: files.length
      }
    });
  } catch (error) {
    console.error('AI search error:', error);
    res.status(500).json({ message: 'Search failed', error: error.message });
  }
});

/**
 * Extract text from all user's files (useful for existing files)
 */
router.post('/extract-all', auth, async (req, res) => {
  try {
    const { force } = req.body; // Allow force re-extraction
    console.log('[Extract-All] User ID:', req.user._id, force ? '(FORCE MODE)' : '');
    
    const files = await File.find({
      owner: req.user._id,
      isTrashed: { $ne: true }
    });
    
    console.log('[Extract-All] Found', files.length, 'files');
    files.forEach(f => {
      console.log(`  - ${f.originalName} (${f.mimeType})`);
    });

    const textExtractor = require('../services/textExtractor');
    const FileContent = require('../models/FileContent');
    const aiSearch = require('../services/aiSearch');

    let extracted = 0;
    let skipped = 0;
    let errors = 0;
    const errorDetails = [];
    const skipReasons = [];

    for (const file of files) {
      try {
        console.log(`[Extract-All] Processing: ${file.originalName} (${file.mimeType})`);
        
        // Check if already extracted (but allow re-extraction if text is empty or force mode)
        const existing = await FileContent.findOne({ file: file._id });
        if (!force && existing && existing.extractionStatus === 'completed' && existing.extractedText && existing.extractedText.length > 0) {
          console.log(`[Extract-All] ⏭️ Skipping ${file.originalName} - already extracted`);
          skipReasons.push({ filename: file.originalName, reason: 'Already extracted' });
          skipped++;
          continue;
        }
        
        // Delete existing record if force mode or if it has no content
        if (existing && (force || !existing.extractedText || existing.extractedText.length === 0)) {
          console.log(`[Extract-All] 🗑️ Removing existing record for ${file.originalName} (force: ${force})`);
          await FileContent.deleteOne({ file: file._id });
        }

        if (!textExtractor.isSupported(file.mimeType)) {
          console.log(`[Extract-All] ⏭️ Skipping ${file.originalName} - unsupported type: ${file.mimeType}`);
          skipReasons.push({ filename: file.originalName, reason: `Unsupported type: ${file.mimeType}` });
          skipped++;
          continue;
        }

        // Check if file exists
        const fs = require('fs-extra');
        const fileExists = await fs.pathExists(file.path);
        if (!fileExists) {
          console.log(`[Extract-All] ❌ File not found at path: ${file.path}`);
          errors++;
          continue;
        }

        console.log(`[Extract-All] 🔄 Extracting text from: ${file.originalName}`);
        let extractedText;
        try {
          extractedText = await textExtractor.extractText(file.path, file.mimeType);
          console.log(`[Extract-All] 📝 Extracted ${extractedText ? extractedText.length : 0} characters from: ${file.originalName}`);
        } catch (extractError) {
          console.error(`[Extract-All] ❌ Extraction error for ${file.originalName}:`, extractError.message);
          errors++;
          errorDetails.push({
            filename: file.originalName,
            error: `Extraction failed: ${extractError.message}`,
            type: 'extraction_error'
          });
          continue;
        }
        
        if (extractedText && extractedText.length > 0) {
          console.log(`[Extract-All] ֎ Generating embedding for: ${file.originalName}`);
          const embedding = await aiSearch.generateEmbedding(extractedText);
          console.log(`[Extract-All] ✅ Generated embedding (${embedding.length} dimensions) for: ${file.originalName}`);
          
          if (existing) {
            existing.extractedText = extractedText;
            existing.embedding = embedding;
            existing.extractionStatus = 'completed';
            await existing.save();
          } else {
            const fileContent = new FileContent({
              file: file._id,
              extractedText,
              embedding,
              extractionStatus: 'completed'
            });
            await fileContent.save();
          }
          extracted++;
          console.log(`[Extract-All] ✅ Successfully processed: ${file.originalName}`);
        } else {
          // Determine reason for no text
          let reason = 'No text found';
          if (file.mimeType.includes('pdf')) {
            reason = 'No text found - PDF may be scanned/image-based (OCR attempted but found no text)';
          } else {
            reason = 'No text found (file may be empty or unsupported format)';
          }
          
          console.log(`[Extract-All] ⚠️ No text extracted from: ${file.originalName}`);
          skipReasons.push({ filename: file.originalName, reason });
          // Still create a record so we know we tried
          if (!existing) {
            const fileContent = new FileContent({
              file: file._id,
              extractedText: '',
              embedding: [],
              extractionStatus: 'failed'
            });
            await fileContent.save();
          }
          skipped++;
        }
      } catch (error) {
        console.error(`[Extract-All] ❌ Error extracting ${file.originalName}:`, error.message);
        console.error(error.stack);
        errors++;
        errorDetails.push({
          filename: file.originalName,
          error: error.message,
          stack: error.stack
        });
      }
    }

    res.json({
      message: 'Extraction completed',
      extracted,
      skipped,
      errors,
      total: files.length,
      errorDetails: errorDetails.length > 0 ? errorDetails : undefined,
      skipReasons: skipReasons.length > 0 ? skipReasons : undefined,
      details: {
        filesProcessed: files.map(f => ({
          name: f.originalName,
          type: f.mimeType,
          path: f.path
        }))
      }
    });
  } catch (error) {
    console.error('Bulk extraction error:', error);
    res.status(500).json({ message: 'Extraction failed', error: error.message });
  }
});

/**
 * Test PDF extraction on a specific file (for debugging)
 */
router.get('/test-extract/:fileId', auth, async (req, res) => {
  try {
    const file = await File.findOne({
      _id: req.params.fileId,
      owner: req.user._id
    });

    if (!file) {
      return res.status(404).json({ message: 'File not found' });
    }

    if (!file.mimeType.includes('pdf')) {
      return res.json({ message: 'File is not a PDF', mimeType: file.mimeType });
    }

    const textExtractor = require('../services/textExtractor');
    const fs = require('fs-extra');
    
    // Check if file exists
    const fileExists = await fs.pathExists(file.path);
    if (!fileExists) {
      return res.status(404).json({ message: 'File not found on disk', path: file.path });
    }

    // Extract text with detailed logging
    console.log(`[Test Extract] Testing extraction for: ${file.originalName}`);
    const extractedText = await textExtractor.extractText(file.path, file.mimeType);

    res.json({
      filename: file.originalName,
      path: file.path,
      fileSize: file.size,
      mimeType: file.mimeType,
      extractedTextLength: extractedText.length,
      extractedTextPreview: extractedText.substring(0, 500),
      fullText: extractedText.length < 10000 ? extractedText : extractedText.substring(0, 10000) + '... (truncated)',
      success: extractedText.length > 0
    });
  } catch (error) {
    console.error('Test extraction error:', error);
    res.status(500).json({ message: 'Extraction failed', error: error.message, stack: error.stack });
  }
});

/**
 * Extract text from a file (triggered manually or on upload)
 */
router.post('/extract/:fileId', auth, async (req, res) => {
  try {
    const file = await File.findOne({
      _id: req.params.fileId,
      owner: req.user._id
    });

    if (!file) {
      return res.status(404).json({ message: 'File not found' });
    }

    const textExtractor = require('../services/textExtractor');
    const path = require('path');
    const filePath = file.path;

    // Check if extraction is supported
    if (!textExtractor.isSupported(file.mimeType)) {
      return res.json({ 
        message: 'File type not supported for text extraction',
        supported: false
      });
    }

    // Extract text
    console.log(`[Extract] Extracting text from: ${file.originalName} (${file.mimeType})`);
    console.log(`[Extract] File path: ${filePath}`);
    
    const extractedText = await textExtractor.extractText(filePath, file.mimeType);
    console.log(`[Extract] Extracted ${extractedText.length} characters`);

    if (!extractedText || extractedText.length === 0) {
      return res.status(400).json({ 
        message: 'No text could be extracted from this file',
        textLength: 0,
        suggestion: 'The file may be image-based, empty, or in an unsupported format. Check server logs for details.'
      });
    }

    // Generate embedding
    const embedding = await aiSearch.generateEmbedding(extractedText);
    console.log(`[Extract] Generated embedding (${embedding.length} dimensions)`);

    // Save or update FileContent
    let fileContent = await FileContent.findOne({ file: file._id });
    if (fileContent) {
      fileContent.extractedText = extractedText;
      fileContent.embedding = embedding;
      fileContent.extractionStatus = 'completed';
      await fileContent.save();
    } else {
      fileContent = new FileContent({
        file: file._id,
        extractedText,
        embedding,
        extractionStatus: 'completed'
      });
      await fileContent.save();
    }

    res.json({
      message: 'Text extracted successfully',
      textLength: extractedText.length,
      hasEmbedding: embedding.length > 0,
      preview: extractedText.substring(0, 200)
    });
  } catch (error) {
    console.error('Extraction error:', error);
    res.status(500).json({ message: 'Extraction failed', error: error.message });
  }
});

module.exports = router;

