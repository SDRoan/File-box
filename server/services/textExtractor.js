const fs = require('fs-extra');
const path = require('path');
const pdfParse = require('pdf-parse');
const Tesseract = require('tesseract.js');
const mammoth = require('mammoth');
const config = require('../config/aiConfig');

// PDF.js for OCR on scanned PDFs (optional - only if canvas is available)
let pdfjsLib = null;
let createCanvas = null;
try {
  pdfjsLib = require('pdfjs-dist/legacy/build/pdf.js');
  const canvasModule = require('canvas');
  createCanvas = canvasModule.createCanvas;
  console.log('[PDF Extract] OCR support enabled for scanned PDFs');
} catch (error) {
  console.log('[PDF Extract] OCR support disabled (canvas/pdfjs not available) - scanned PDFs will be skipped');
}

class TextExtractor {
  /**
   * Extract text from a file based on its MIME type
   */
  async extractText(filePath, mimeType) {
    try {
      if (!await fs.pathExists(filePath)) {
        throw new Error('File not found');
      }

      // PDF files
      if (mimeType.includes('pdf')) {
        const extracted = await this.extractFromPDF(filePath);
        console.log(`[TextExtractor] PDF extraction result: ${extracted ? extracted.length : 0} characters`);
        if (!extracted || extracted.trim().length === 0) {
          console.warn(`[TextExtractor] ⚠️ PDF extraction returned empty text for: ${filePath}`);
        }
        return extracted || '';
      }

      // Word documents
      if (mimeType.includes('word') || mimeType.includes('document') || 
          mimeType.includes('application/vnd.openxmlformats-officedocument.wordprocessingml')) {
        return await this.extractFromWord(filePath);
      }

      // Text files
      if (mimeType.startsWith('text/') || 
          mimeType.includes('json') || 
          mimeType.includes('xml') ||
          mimeType.includes('javascript') ||
          mimeType.includes('css') ||
          mimeType.includes('html')) {
        return await this.extractFromText(filePath);
      }

      // Images (OCR)
      if (mimeType.startsWith('image/')) {
        return await this.extractFromImage(filePath);
      }

      return '';
    } catch (error) {
      console.error('Error extracting text:', error);
      return '';
    }
  }

  async extractFromPDF(filePath) {
    try {
      console.log(`[PDF Extract] Reading file: ${filePath}`);
      const dataBuffer = await fs.readFile(filePath);
      console.log(`[PDF Extract] File size: ${dataBuffer.length} bytes`);
      
      let text = '';
      let numPages = 0;
      let extractionMethod = 'none';
      
      // Method 1: Try pdf-parse (similar to Python's pypdf approach - simple and reliable)
      try {
        console.log(`[PDF Extract] Trying pdf-parse (like pypdf)...`);
        const data = await pdfParse(dataBuffer);
        const parsedText = data.text || '';
        numPages = data.numpages || 0;
        
        console.log(`[PDF Extract] pdf-parse result: ${parsedText.length} chars from ${numPages} pages`);
        
        if (parsedText && parsedText.trim().length > 0) {
          text = parsedText.trim();
          console.log(`[PDF Extract] ✅ pdf-parse extracted ${text.length} chars`);
          console.log(`[PDF Extract] Preview: ${text.substring(0, 200).replace(/\n/g, ' ')}`);
          
          // If we got good text, return it (like the Python version does)
          if (text.length > 10) {
            extractionMethod = 'pdf-parse';
            return text;
          }
        } else {
          console.log(`[PDF Extract] pdf-parse returned empty text`);
        }
      } catch (parseError) {
        console.error(`[PDF Extract] pdf-parse error: ${parseError.message}`);
        console.error(`[PDF Extract] pdf-parse stack: ${parseError.stack}`);
        // Continue to try other methods
      }
      
      // Method 2: Try pdfjs-dist as backup (for PDFs that pdf-parse can't handle)
      if (text.length < 10) {
        if (!pdfjsLib) {
          console.log(`[PDF Extract] ⚠️ pdfjs-dist not available, trying to load...`);
          try {
            pdfjsLib = require('pdfjs-dist/legacy/build/pdf.js');
            console.log(`[PDF Extract] ✅ pdfjs-dist loaded successfully`);
          } catch (loadError) {
            console.error(`[PDF Extract] ❌ Failed to load pdfjs-dist: ${loadError.message}`);
          }
        }
        
        if (pdfjsLib) {
          try {
            console.log(`[PDF Extract] Trying pdfjs-dist as backup...`);
            const loadingTask = pdfjsLib.getDocument({ data: dataBuffer });
            const pdf = await loadingTask.promise;
            numPages = pdf.numPages;
            
            let allText = '';
            // Extract from all pages (like Python version does)
            for (let pageNum = 1; pageNum <= numPages; pageNum++) {
              try {
                const page = await pdf.getPage(pageNum);
                const textContent = await page.getTextContent();
                
                if (textContent && textContent.items && textContent.items.length > 0) {
                  const pageText = textContent.items
                    .map((item) => item.str || '')
                    .join(' ')
                    .trim();
                  
                  if (pageText.length > 0) {
                    allText += (allText ? '\n' : '') + pageText;
                    console.log(`[PDF Extract] Page ${pageNum}: Extracted ${pageText.length} chars`);
                  }
                }
              } catch (pageError) {
                console.log(`[PDF Extract] Error on page ${pageNum}: ${pageError.message}`);
              }
            }
            
            if (allText.trim().length > text.length) {
              text = allText.trim();
              extractionMethod = 'pdfjs-dist';
              console.log(`[PDF Extract] ✅ pdfjs-dist extracted ${text.length} chars`);
              // If we got good text, return it immediately
              if (text.length > 10) {
                return text;
              }
            }
          } catch (pdfjsError) {
            console.error(`[PDF Extract] pdfjs-dist error: ${pdfjsError.message}`);
            console.error(`[PDF Extract] pdfjs-dist stack: ${pdfjsError.stack}`);
          }
        }
      }
      
      // Step 2: If no text or very little text, ALWAYS try OCR (for scanned/image-based PDFs)
      // OCR should be attempted if we have less than 100 characters
      if (text.length < 100) {
        console.log(`[PDF Extract] ⚠️ Little/no text found (${text.length} chars) - attempting OCR for image-based PDF...`);
        
        // Try OCR with pdfjs + canvas if available
        if (pdfjsLib && createCanvas) {
          try {
            // Process more pages for OCR - up to 20 pages or all pages if less than 20
            const pagesToProcess = numPages ? Math.min(numPages, 20) : 20;
            console.log(`[PDF Extract] Attempting OCR on ${pagesToProcess} pages...`);
            
            const ocrText = await this.extractFromScannedPDF(filePath, dataBuffer, pagesToProcess);
            
            if (ocrText && ocrText.trim().length > 0) {
              if (ocrText.length > text.length) {
                console.log(`[PDF Extract] ✅ OCR extracted ${ocrText.length} characters (better than text layer)`);
                text = ocrText;
              } else {
                console.log(`[PDF Extract] ⚠️ OCR found ${ocrText.length} chars (less than text layer, but keeping OCR result)`);
                // Still use OCR if text layer is empty or very short
                if (text.length < 50) {
                  text = ocrText;
                }
              }
            } else {
              console.log(`[PDF Extract] ⚠️ OCR found no text`);
            }
          } catch (ocrError) {
            console.error(`[PDF Extract] ⚠️ OCR failed: ${ocrError.message}`);
            console.error(ocrError.stack);
            // Continue - maybe we can try alternative OCR method
          }
        } else {
          console.log(`[PDF Extract] ⚠️ OCR not available (pdfjsLib: ${!!pdfjsLib}, createCanvas: ${!!createCanvas})`);
          console.log(`[PDF Extract] Attempting alternative OCR method...`);
          
          // Try alternative: convert PDF pages to images and use Tesseract directly
          try {
            const altOcrText = await this.extractFromPDFAlternative(filePath, dataBuffer);
            if (altOcrText && altOcrText.trim().length > 0 && altOcrText.length > text.length) {
              console.log(`[PDF Extract] ✅ Alternative OCR extracted ${altOcrText.length} characters`);
              text = altOcrText;
            }
          } catch (altError) {
            console.error(`[PDF Extract] Alternative OCR also failed: ${altError.message}`);
          }
        }
      }
      
      if (text.length === 0) {
        console.log(`[PDF Extract] ⚠️ No text found - PDF might be scanned, empty, or corrupted`);
        console.log(`[PDF Extract] Extraction methods tried: pdf-parse, pdfjs-dist`);
      } else if (text.length < 50) {
        console.log(`[PDF Extract] ⚠️ Very little text found (${text.length} chars) using ${extractionMethod}`);
      } else {
        console.log(`[PDF Extract] ✅ Successfully extracted ${text.length} characters using ${extractionMethod}`);
      }
      
      // Return text even if it's short - let the caller decide what to do
      return text || '';
    } catch (error) {
      console.error(`[PDF Extract] ❌ Error extracting PDF ${filePath}:`, error.message);
      console.error(error.stack);
      return '';
    }
  }

  /**
   * Extract text from scanned PDFs using OCR
   * Renders PDF pages as images and runs OCR on them
   */
  async extractFromScannedPDF(filePath, dataBuffer, maxPages = 20) {
    if (!pdfjsLib || !createCanvas) {
      console.log(`[PDF OCR] pdfjsLib or createCanvas not available`);
      return '';
    }

    try {
      const loadingTask = pdfjsLib.getDocument({ data: dataBuffer });
      const pdf = await loadingTask.promise;
      
      let allText = '';
      const totalPages = pdf.numPages;
      const pagesToProcess = Math.min(totalPages, maxPages);
      
      console.log(`[PDF OCR] Processing ${pagesToProcess} of ${totalPages} pages for OCR...`);
      
      for (let pageNum = 1; pageNum <= pagesToProcess; pageNum++) {
        try {
          console.log(`[PDF OCR] Processing page ${pageNum}/${pagesToProcess}...`);
          const page = await pdf.getPage(pageNum);
          
          // Use higher scale for better OCR accuracy (3.0 instead of 2.0)
          const viewport = page.getViewport({ scale: 3.0 });
          
          // Create canvas
          const canvas = createCanvas(viewport.width, viewport.height);
          const context = canvas.getContext('2d');
          
          // Render PDF page to canvas
          const renderContext = {
            canvasContext: context,
            viewport: viewport
          };
          await page.render(renderContext).promise;
          
          // Convert canvas to buffer
          const imageBuffer = canvas.toBuffer('image/png');
          
          // Run OCR on the image buffer with better options
          console.log(`[PDF OCR] Running Tesseract OCR on page ${pageNum}...`);
          const { data: { text } } = await Tesseract.recognize(imageBuffer, config.extraction.ocrLanguage, {
            logger: m => {
              // Only log important progress updates
              if (m.status === 'recognizing text') {
                console.log(`[PDF OCR] Page ${pageNum}: ${Math.round(m.progress * 100)}%`);
              }
            },
            // OCR options for better accuracy
            tessedit_pageseg_mode: '1', // Automatic page segmentation with OSD
            tessedit_char_whitelist: null, // Allow all characters
          });
          
          if (text && text.trim().length > 0) {
            const cleanText = text.trim();
            allText += (allText ? '\n\n' : '') + `--- Page ${pageNum} ---\n\n${cleanText}`;
            console.log(`[PDF OCR] ✅ Page ${pageNum}: Extracted ${cleanText.length} characters`);
          } else {
            console.log(`[PDF OCR] ⚠️ Page ${pageNum}: No text found`);
          }
        } catch (pageError) {
          console.error(`[PDF OCR] Error processing page ${pageNum}:`, pageError.message);
          // Continue with next page
        }
      }
      
      const result = allText.trim();
      console.log(`[PDF OCR] ✅ Total OCR extraction: ${result.length} characters from ${pagesToProcess} pages`);
      return result;
    } catch (error) {
      console.error(`[PDF OCR] Error in OCR extraction:`, error.message);
      console.error(error.stack);
      return '';
    }
  }

  /**
   * Alternative OCR method using pdf-poppler or similar (fallback)
   */
  async extractFromPDFAlternative(filePath, dataBuffer) {
    // This is a fallback method if pdfjs + canvas isn't available
    // For now, we'll just return empty - can be enhanced later with pdf-poppler
    console.log(`[PDF OCR] Alternative OCR method not yet implemented`);
    return '';
  }

  async extractFromWord(filePath) {
    try {
      console.log(`[Word Extract] Extracting text from: ${filePath}`);
      
      // First try extractRawText (faster, simpler)
      try {
        const result = await mammoth.extractRawText({ path: filePath });
        const text = result.value || '';
        if (text && text.trim().length > 0) {
          console.log(`[Word Extract] ✅ Extracted ${text.length} characters using extractRawText`);
          return text;
        }
      } catch (rawError) {
        console.log(`[Word Extract] extractRawText failed, trying convertToHtml: ${rawError.message}`);
      }
      
      // Fallback: try convertToHtml and extract text from HTML
      try {
        const htmlResult = await mammoth.convertToHtml({ path: filePath });
        const html = htmlResult.value || '';
        if (html && html.trim().length > 0) {
          // Extract text from HTML (remove tags)
          const text = html.replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim();
          if (text.length > 0) {
            console.log(`[Word Extract] ✅ Extracted ${text.length} characters using convertToHtml`);
            return text;
          }
        }
      } catch (htmlError) {
        console.error(`[Word Extract] convertToHtml also failed: ${htmlError.message}`);
      }
      
      console.warn(`[Word Extract] ⚠️ All extraction methods failed for: ${filePath}`);
      return '';
    } catch (error) {
      console.error('[Word Extract] Error extracting Word document:', error);
      return '';
    }
  }

  async extractFromText(filePath) {
    try {
      return await fs.readFile(filePath, 'utf-8');
    } catch (error) {
      console.error('Error reading text file:', error);
      return '';
    }
  }

  async extractFromImage(filePath) {
    try {
      console.log(`[Image OCR] Processing image: ${filePath}`);
      // Use Tesseract.js for OCR with better options
      const { data: { text } } = await Tesseract.recognize(filePath, config.extraction.ocrLanguage, {
        logger: m => {
          if (m.status === 'recognizing text') {
            console.log(`[Image OCR] Progress: ${Math.round(m.progress * 100)}%`);
          }
        },
        tessedit_pageseg_mode: '1', // Automatic page segmentation
      });
      const result = text || '';
      console.log(`[Image OCR] ✅ Extracted ${result.length} characters`);
      return result;
    } catch (error) {
      console.error('[Image OCR] Error extracting text from image:', error);
      return '';
    }
  }

  /**
   * Check if file type is supported for text extraction
   */
  isSupported(mimeType) {
    return config.extraction.supportedMimeTypes.some(supportedType => 
      mimeType.includes(supportedType) || 
      mimeType.startsWith(supportedType.split('/')[0] + '/')
    );
  }
}

module.exports = new TextExtractor();

