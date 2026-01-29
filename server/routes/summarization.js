const express = require('express');
const auth = require('../middleware/auth');
const File = require('../models/File');
const FileContent = require('../models/FileContent');
const summarizationService = require('../services/summarization');
const textExtractor = require('../services/textExtractor');
const router = express.Router();

/**
 * Generate summary for a file
 */
router.post('/:fileId', auth, async (req, res) => {
  try {
    const { fileId } = req.params;
    const { force } = req.body; // Force re-generation

    if (!summarizationService.isAvailable()) {
      return res.status(400).json({ 
        message: 'Summarization is disabled',
        enabled: false 
      });
    }

    // Find file
    const file = await File.findOne({
      _id: fileId,
      owner: req.user._id,
      isTrashed: { $ne: true }
    });

    if (!file) {
      return res.status(404).json({ message: 'File not found' });
    }

    // Check if file type is supported
    if (!textExtractor.isSupported(file.mimeType)) {
      return res.status(400).json({ 
        message: 'File type not supported for summarization',
        supported: false 
      });
    }

    // Get or extract text content
    let fileContent = await FileContent.findOne({ file: file._id });
    let extractedText = '';

    // Check if we have existing extracted text
    if (fileContent && fileContent.extractedText && fileContent.extractedText.length > 0 && !force) {
      extractedText = fileContent.extractedText;
      console.log(`[Summarization] Using existing extracted text (${extractedText.length} chars)`);
    } else {
      // Extract text if not available
      console.log(`[Summarization] Extracting text from file: ${file.originalName}...`);
      const fs = require('fs-extra');
      const fileExists = await fs.pathExists(file.path);
      
      if (!fileExists) {
        return res.status(404).json({ 
          message: 'File not found on disk',
          path: file.path 
        });
      }

      try {
        extractedText = await textExtractor.extractText(file.path, file.mimeType);
        console.log(`[Summarization] Extraction result: ${extractedText ? extractedText.length : 0} characters`);
        console.log(`[Summarization] Extracted text preview: ${extractedText ? extractedText.substring(0, 200) : 'EMPTY'}`);
        
        // Check if we got meaningful text (at least 10 characters after trimming)
        const trimmedText = extractedText ? extractedText.trim() : '';
        console.log(`[Summarization] Trimmed text length: ${trimmedText.length} characters`);
        console.log(`[Summarization] First 500 chars: ${trimmedText.substring(0, 500)}`);
        
        if (!trimmedText || trimmedText.length < 10) {
          console.warn(`[Summarization] ⚠️ Extracted text is too short or empty: ${trimmedText.length} characters`);
          console.warn(`[Summarization] Raw extractedText type: ${typeof extractedText}, value: ${extractedText ? extractedText.substring(0, 100) : 'null/undefined'}`);
          
          // For PDFs, try multiple extraction methods
          if (file.mimeType.includes('pdf')) {
            console.log(`[Summarization] PDF extraction failed, trying alternative methods...`);
            
            // Method 1: Try OCR
            try {
              const fs = require('fs-extra');
              const dataBuffer = await fs.readFile(file.path);
              console.log(`[Summarization] Attempting OCR extraction...`);
              const ocrText = await textExtractor.extractFromScannedPDF(file.path, dataBuffer, 10); // Try first 10 pages
              if (ocrText && ocrText.trim().length > 10) {
                extractedText = ocrText.trim();
                console.log(`[Summarization] ✅ OCR extraction successful: ${extractedText.length} characters`);
              } else {
                console.log(`[Summarization] OCR returned insufficient text: ${ocrText ? ocrText.length : 0} characters`);
              }
            } catch (ocrError) {
              console.error('[Summarization] OCR extraction failed:', ocrError.message);
            }
            
            // Method 2: Try to extract using pdfjs-dist directly (if OCR didn't work)
            if (!extractedText || extractedText.trim().length < 10) {
              try {
                console.log(`[Summarization] Attempting direct pdfjs-dist extraction...`);
                const pdfjsLib = require('pdfjs-dist/legacy/build/pdf.js');
                const fs = require('fs-extra');
                const dataBuffer = await fs.readFile(file.path);
                const loadingTask = pdfjsLib.getDocument({ data: dataBuffer });
                const pdf = await loadingTask.promise;
                
                let allText = '';
                const pagesToTry = Math.min(pdf.numPages, 10);
                for (let pageNum = 1; pageNum <= pagesToTry; pageNum++) {
                  try {
                    const page = await pdf.getPage(pageNum);
                    const textContent = await page.getTextContent();
                    if (textContent && textContent.items) {
                      const pageText = textContent.items
                        .map(item => item.str || '')
                        .join(' ')
                        .trim();
                      if (pageText.length > 0) {
                        allText += (allText ? '\n\n' : '') + pageText;
                      }
                    }
                  } catch (pageError) {
                    console.log(`[Summarization] Error extracting page ${pageNum}: ${pageError.message}`);
                  }
                }
                
                if (allText.trim().length > 10) {
                  extractedText = allText.trim();
                  console.log(`[Summarization] ✅ pdfjs-dist extraction successful: ${extractedText.length} characters`);
                }
              } catch (pdfjsError) {
                console.error('[Summarization] pdfjs-dist extraction failed:', pdfjsError.message);
              }
            }
            
            // If we got text from any method, save it
            if (extractedText && extractedText.trim().length > 10) {
              const finalTrimmed = extractedText.trim();
              if (!fileContent) {
                fileContent = new FileContent({
                  file: file._id,
                  extractedText: finalTrimmed,
                  extractionStatus: 'completed'
                });
              } else {
                fileContent.extractedText = finalTrimmed;
                fileContent.extractionStatus = 'completed';
              }
              await fileContent.save();
              extractedText = finalTrimmed;
            } else {
              // Final fallback: Return helpful error
              console.error(`[Summarization] ❌ All extraction methods failed. Text length: ${extractedText ? extractedText.trim().length : 0}`);
              return res.status(400).json({ 
                message: 'No text could be extracted from this PDF file. The PDF may be scanned/image-based, corrupted, or in an unsupported format.',
                extracted: false,
                suggestion: 'Please ensure the PDF contains selectable text. If it\'s a scanned PDF, the system will attempt OCR, but results may vary.'
              });
            }
          } else {
            // Non-PDF files - return error if extraction failed
            return res.status(400).json({ 
              message: 'No text could be extracted from this file. The file may be empty or in an unsupported format.',
              extracted: false,
              suggestion: 'Please ensure the file contains readable text content.'
            });
          }
        } else {
          // Use the normally extracted text
          extractedText = trimmedText;
        }

        // Save extracted text for future use
        if (!fileContent) {
          fileContent = new FileContent({
            file: file._id,
            extractedText,
            extractionStatus: 'completed'
          });
        } else {
          fileContent.extractedText = extractedText;
          fileContent.extractionStatus = 'completed';
        }
        await fileContent.save();
        console.log(`[Summarization] Saved extracted text (${extractedText.length} chars)`);
      } catch (extractError) {
        console.error(`[Summarization] Extraction error:`, extractError);
        return res.status(500).json({ 
          message: 'Failed to extract text from file',
          error: extractError.message,
          suggestion: 'Make sure the file is not corrupted and try again.'
        });
      }
    }

    // Check if summary already exists and not forcing
    if (fileContent.summary && fileContent.summary.length > 0 && !force) {
      console.log(`[Summarization] Using existing summary`);
      return res.json({
        summary: fileContent.summary,
        keyPoints: [], // Legacy summaries don't have extracted key points
        cached: true,
        generatedAt: fileContent.summaryGeneratedAt,
        model: fileContent.summaryModel
      });
    }

    // Generate summary (pass mimeType for DOCX detection to get expanded summaries)
    console.log(`[Summarization] Generating summary for: ${file.originalName} (${file.mimeType})`);
    const summaryResult = await summarizationService.generateSummary(extractedText, file.mimeType);

    if (!summaryResult || (typeof summaryResult === 'string' && summaryResult.length === 0) || (typeof summaryResult === 'object' && !summaryResult.summary)) {
      return res.status(500).json({ 
        message: 'Failed to generate summary',
        error: 'Summary generation returned empty result'
      });
    }

    // Handle both string and object formats
    const summaryText = typeof summaryResult === 'string' ? summaryResult : summaryResult.summary;
    const keyPoints = typeof summaryResult === 'object' && summaryResult.keyPoints ? summaryResult.keyPoints : [];

    // Save summary (store as JSON string to preserve structure)
    fileContent.summary = summaryText;
    fileContent.summaryGeneratedAt = new Date();
    fileContent.summaryModel = summarizationService.getConfig().model;
    
    // Store key points if available (we can extend FileContent schema later if needed)
    // For now, we'll return them in the response
    await fileContent.save();

    res.json({
      summary: summaryText,
      keyPoints: keyPoints,
      cached: false,
      generatedAt: fileContent.summaryGeneratedAt,
      model: fileContent.summaryModel
    });
  } catch (error) {
    console.error('Summarization error:', error);
    res.status(500).json({ 
      message: 'Failed to generate summary', 
      error: error.message 
    });
  }
});

/**
 * Get summary for a file (if exists)
 */
router.get('/:fileId', auth, async (req, res) => {
  try {
    const { fileId } = req.params;

    const file = await File.findOne({
      _id: fileId,
      owner: req.user._id
    });

    if (!file) {
      return res.status(404).json({ message: 'File not found' });
    }

    const fileContent = await FileContent.findOne({ file: file._id });

    if (!fileContent || !fileContent.summary || fileContent.summary.length === 0) {
      return res.json({
        summary: null,
        keyPoints: [],
        hasSummary: false
      });
    }

    // Try to extract key points from existing summary if possible
    // For now, return empty array - key points will be generated with new summaries
    res.json({
      summary: fileContent.summary,
      keyPoints: [], // Legacy summaries don't have key points extracted
      hasSummary: true,
      generatedAt: fileContent.summaryGeneratedAt,
      model: fileContent.summaryModel
    });
  } catch (error) {
    console.error('Error fetching summary:', error);
    res.status(500).json({ message: 'Failed to fetch summary', error: error.message });
  }
});

/**
 * Get summarization configuration
 */
router.get('/config', auth, async (req, res) => {
  try {
    res.json({
      ...summarizationService.getConfig(),
      available: summarizationService.isAvailable()
    });
  } catch (error) {
    res.status(500).json({ message: 'Failed to get config', error: error.message });
  }
});

module.exports = router;

