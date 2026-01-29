const fs = require('fs-extra');
const path = require('path');

// Try to load docx library (optional)
let docxLib = null;
try {
  docxLib = require('docx');
  console.log('[PDF->DOCX] docx library loaded successfully');
} catch (error) {
  console.log('[PDF->DOCX] docx library not available - conversion will use simple text extraction');
}

/**
 * Convert PDF text to DOCX file
 * This creates a simple DOCX file from extracted PDF text
 */
class PDFToDocxConverter {
  /**
   * Convert extracted PDF text to a DOCX file
   * @param {string} pdfText - Extracted text from PDF
   * @param {string} outputPath - Path where DOCX file should be saved
   * @param {string} originalFileName - Original PDF filename (for naming)
   * @returns {Promise<string>} Path to created DOCX file
   */
  async convertTextToDocx(pdfText, outputPath, originalFileName) {
    try {
      if (!pdfText || pdfText.trim().length === 0) {
        throw new Error('No text content to convert');
      }

      // If docx library is available, use it
      if (docxLib) {
        const { Document, Packer, Paragraph, TextRun } = docxLib;
        
        // Split text into paragraphs (by double newlines or long single newlines)
        const paragraphs = pdfText
          .split(/\n\s*\n/)
          .map(p => p.trim())
          .filter(p => p.length > 0)
          .map(text => new Paragraph({
            children: [new TextRun(text)]
          }));

        // If no paragraphs found, create one from the whole text
        if (paragraphs.length === 0) {
          paragraphs.push(new Paragraph({
            children: [new TextRun(pdfText)]
          }));
        }

        // Create DOCX document
        const doc = new Document({
          sections: [{
            properties: {},
            children: paragraphs
          }]
        });

        // Ensure output directory exists
        await fs.ensureDir(path.dirname(outputPath));

        // Generate DOCX file
        const buffer = await Packer.toBuffer(doc);
        await fs.writeFile(outputPath, buffer);

        console.log(`[PDF->DOCX] ✅ Created DOCX file using docx library: ${outputPath}`);
        return outputPath;
      } else {
        // Fallback: Use mammoth to create DOCX (mammoth can also create simple DOCX files)
        // Actually, mammoth is read-only. Let's create a simple workaround.
        // For now, we'll inform the user that the docx library needs to be installed
        console.log(`[PDF->DOCX] docx library not available`);
        throw new Error('DOCX library not installed. Please install it with: npm install docx');
      }
    } catch (error) {
      console.error('[PDF->DOCX] ❌ Error converting to DOCX:', error);
      throw error;
    }
  }

  /**
   * Convert PDF file to DOCX (extracts text first, then creates DOCX)
   * @param {string} pdfPath - Path to PDF file
   * @param {string} outputDir - Directory where DOCX should be saved
   * @param {string} originalFileName - Original PDF filename
   * @returns {Promise<string>} Path to created DOCX file
   */
  async convertPdfToDocx(pdfPath, outputDir, originalFileName) {
    const textExtractor = require('./textExtractor');
    
    // Extract text from PDF
    console.log(`[PDF->DOCX] Extracting text from PDF: ${pdfPath}`);
    const extractedText = await textExtractor.extractText(pdfPath, 'application/pdf');
    
    if (!extractedText || extractedText.trim().length === 0) {
      throw new Error('Could not extract text from PDF');
    }

    // Generate output filename
    const baseName = path.basename(originalFileName, path.extname(originalFileName));
    const docxFileName = `${baseName}_converted.docx`;
    const outputPath = path.join(outputDir, docxFileName);

    // Convert to DOCX
    return await this.convertTextToDocx(extractedText, outputPath, originalFileName);
  }
}

module.exports = new PDFToDocxConverter();

