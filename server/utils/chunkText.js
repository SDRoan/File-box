/**
 * Utility functions for chunking text for AI processing
 * Based on best practices for handling long documents
 */

/**
 * Chunk text into smaller pieces, trying to split on sentence boundaries
 * @param {string} text - The text to chunk
 * @param {number} maxChars - Maximum characters per chunk (default: 1500)
 * @returns {string[]} Array of text chunks
 */
function chunkText(text, maxChars = 1500) {
  if (!text || text.length === 0) {
    return [];
  }

  // If text is shorter than maxChars, return as single chunk
  if (text.length <= maxChars) {
    return [text];
  }

  const chunks = [];
  let currentIndex = 0;

  while (currentIndex < text.length) {
    // Calculate the end index for this chunk
    let endIndex = currentIndex + maxChars;

    // If we're not at the end of the text, try to find a good break point
    if (endIndex < text.length) {
      // Try to find the last sentence boundary (period, exclamation, question mark + space/newline)
      const searchStart = Math.max(currentIndex, endIndex - 200); // Look back up to 200 chars
      const searchText = text.substring(searchStart, endIndex);
      // Find last occurrence of sentence-ending punctuation followed by whitespace
      let sentenceEnd = -1;
      for (let i = searchText.length - 2; i >= 0; i--) {
        if (/[.!?]/.test(searchText[i]) && /\s/.test(searchText[i + 1])) {
          sentenceEnd = i;
          break;
        }
      }

      if (sentenceEnd !== -1) {
        endIndex = searchStart + sentenceEnd + 2; // Include the punctuation and space
      } else {
        // If no sentence boundary, try to find a paragraph break
        const paragraphEnd = text.substring(searchStart, endIndex).lastIndexOf('\n\n');
        if (paragraphEnd !== -1) {
          endIndex = searchStart + paragraphEnd + 2; // Include the double newline
        } else {
          // Last resort: find a word boundary (space)
          const wordEnd = text.substring(searchStart, endIndex).lastIndexOf(' ');
          if (wordEnd !== -1) {
            endIndex = searchStart + wordEnd + 1; // Include the space
          }
        }
      }
    }

    // Extract the chunk
    const chunk = text.substring(currentIndex, endIndex).trim();
    if (chunk.length > 0) {
      chunks.push(chunk);
    }

    // Move to the next chunk
    currentIndex = endIndex;
  }

  return chunks;
}

/**
 * Chunk text with overlap to preserve context between chunks
 * @param {string} text - The text to chunk
 * @param {number} maxChars - Maximum characters per chunk
 * @param {number} overlapChars - Number of characters to overlap between chunks (default: 200)
 * @returns {string[]} Array of text chunks with overlap
 */
function chunkTextWithOverlap(text, maxChars = 1500, overlapChars = 200) {
  if (!text || text.length === 0) {
    return [];
  }

  if (text.length <= maxChars) {
    return [text];
  }

  const chunks = [];
  let currentIndex = 0;

  while (currentIndex < text.length) {
    let endIndex = currentIndex + maxChars;

    if (endIndex < text.length) {
      // Try to find a good break point
      const searchStart = Math.max(currentIndex, endIndex - 200);
      const sentenceEnd = text.substring(searchStart, endIndex).lastIndexOf(/[.!?]\s+/);

      if (sentenceEnd !== -1) {
        endIndex = searchStart + sentenceEnd + 1;
      } else {
        const paragraphEnd = text.substring(searchStart, endIndex).lastIndexOf('\n\n');
        if (paragraphEnd !== -1) {
          endIndex = searchStart + paragraphEnd + 2;
        } else {
          const wordEnd = text.substring(searchStart, endIndex).lastIndexOf(' ');
          if (wordEnd !== -1) {
            endIndex = searchStart + wordEnd + 1;
          }
        }
      }
    }

    const chunk = text.substring(currentIndex, endIndex).trim();
    if (chunk.length > 0) {
      chunks.push(chunk);
    }

    // Move forward, but overlap by going back a bit
    currentIndex = Math.max(currentIndex + 1, endIndex - overlapChars);
  }

  return chunks;
}

/**
 * Estimate number of tokens (rough approximation: 1 token ≈ 4 characters)
 * @param {string} text - The text to estimate
 * @returns {number} Estimated token count
 */
function estimateTokens(text) {
  if (!text) return 0;
  return Math.ceil(text.length / 4);
}

module.exports = {
  chunkText,
  chunkTextWithOverlap,
  estimateTokens
};

