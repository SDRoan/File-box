const express = require('express');
const router = express.Router();
const auth = require('../middleware/auth');
const File = require('../models/File');
const FileContent = require('../models/FileContent');
const FileSummary = require('../models/FileSummary');
const FileMemory = require('../models/FileMemory');
const textExtractor = require('../services/textExtractor');
const { chunkText, estimateTokens } = require('../utils/chunkText');
const aiActionExecutor = require('../services/aiActionExecutor');
const axios = require('axios');

// Helper function to call OpenRouter API
async function callOpenRouter(messages, maxTokens = 2000, temperature = 0.7, useFreeModel = false) {
  const openRouterApiKey = process.env.OPENROUTER_API_KEY;
  
  if (!openRouterApiKey) {
    throw new Error('OpenRouter API key not configured');
  }

  // Use free model if requested, otherwise use default
  const model = useFreeModel 
    ? 'google/gemini-flash-1.5-8b:free' // Fast and free
    : 'openai/gpt-4o-mini'; // Default paid model

  const response = await axios.post(
    'https://openrouter.ai/api/v1/chat/completions',
    {
      model: model,
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

// Chunked summarization following Adrian Twarog's approach
async function summarizeWithChunking(text, fileName) {
  const CHUNK_SIZE = 1500; // Characters per chunk
  const MAX_DIRECT_LENGTH = 8000; // If text is shorter, summarize directly
  
  console.log(`[Chunked Summarization] Processing ${text.length} characters from ${fileName}`);
  
  // If text is short enough, summarize directly
  if (text.length <= MAX_DIRECT_LENGTH) {
    console.log(`[Chunked Summarization] Text is short enough, summarizing directly`);
    
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
    
    const userPrompt = `Please read the following document and create a comprehensive, professional summary:

${text}

Write a professional summary that:
- Clearly explains what this document is about
- Describes the main content and key ideas
- Identifies and explains the most important points
- Provides context and significance
- Uses clear, professional language throughout

Write in complete sentences and paragraphs. Make it informative and well-structured.`;

    const summary = await callOpenRouter(
      [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: userPrompt }
      ],
      4000, // Increased tokens for better quality
      0.4, // Slightly higher temperature for more natural writing
      true // Use free model
    );

    return summary;
  }

  // For long documents, use chunked approach
  console.log(`[Chunked Summarization] Text is long (${text.length} chars), using chunked approach`);
  
  // Step 1: Split into chunks
  const chunks = chunkText(text, CHUNK_SIZE);
  console.log(`[Chunked Summarization] Split into ${chunks.length} chunks`);

  // Step 2: Summarize each chunk individually
  const chunkSummaries = [];
  const chunkSystemPrompt = `You are an expert document analyst. Summarize the following section of a document professionally and clearly. 

**Requirements:**
- Explain what this section discusses in your own words
- Identify the main points and important information
- Write in complete sentences and paragraphs
- Use professional, clear language
- DO NOT just list keywords or copy text verbatim
- Make it read like a well-written summary`;

  for (let i = 0; i < chunks.length; i++) {
    console.log(`[Chunked Summarization] Summarizing chunk ${i + 1}/${chunks.length}...`);
    
    const chunkPrompt = `This is part ${i + 1} of ${chunks.length} from a document. Please provide a professional summary of this section:

${chunks[i]}

Write a clear, well-structured summary explaining what this section discusses and its key points. Use complete sentences and professional language.`;

    try {
      const chunkSummary = await callOpenRouter(
        [
          { role: 'system', content: chunkSystemPrompt },
          { role: 'user', content: chunkPrompt }
        ],
        1000,
        0.3, // Lower temperature
        true // Use free model
      );

      chunkSummaries.push(`Section ${i + 1} Summary:\n${chunkSummary}`);
      
      // Small delay to avoid rate limiting
      if (i < chunks.length - 1) {
        await new Promise(resolve => setTimeout(resolve, 500));
      }
    } catch (error) {
      console.error(`[Chunked Summarization] Error summarizing chunk ${i + 1}:`, error.message);
      // Continue with other chunks even if one fails
      chunkSummaries.push(`Section ${i + 1}: [Summary unavailable due to processing error]`);
    }
  }

  console.log(`[Chunked Summarization] Completed ${chunkSummaries.length} chunk summaries`);

  // Step 3: Create final "super summary" from chunk summaries
  console.log(`[Chunked Summarization] Creating final summary from ${chunkSummaries.length} chunk summaries...`);
  
  const finalSystemPrompt = `You are an expert academic and professional document analyst. Combine the following section summaries into one comprehensive, professional final summary that rivals ChatGPT in quality.

**Your final summary must:**

1. **Provide a clear introduction** - Start with 1-2 sentences explaining what the entire document is about, its purpose, and main subject matter.

2. **Explain the main content** - In 2-4 well-written paragraphs, synthesize the information from all sections to explain:
   - What the document discusses or analyzes overall
   - The key arguments, findings, or information presented
   - Important details, examples, or evidence mentioned
   - How different sections connect and relate to each other

3. **Highlight key points** - Present 3-7 main points or takeaways from across all sections. Each point should be explained clearly in your own words.

4. **Provide context and significance** - Explain why this information matters, what it means, or what implications it has.

5. **Write professionally** - Use clear, professional language. Write in complete sentences with proper flow. Avoid keyword lists or fragmented phrases. Make it read like a well-written academic or professional summary.

**Critical requirements:**
- DO NOT just list keywords or phrases
- DO NOT copy text verbatim
- DO write in flowing, professional prose
- DO synthesize information from all sections into a coherent whole
- DO write as if you're a knowledgeable expert explaining the document to a colleague`;

  const finalUserPrompt = `Please combine these section summaries into one comprehensive, professional summary of the entire document:

${chunkSummaries.join('\n\n---\n\n')}

Write a professional summary that:
- Clearly explains what this entire document is about
- Synthesizes the main content and key ideas from all sections
- Identifies and explains the most important points across the document
- Provides context and significance
- Uses clear, professional language throughout

Write in complete sentences and paragraphs. Make it informative, well-structured, and professional.`;

  const finalSummary = await callOpenRouter(
    [
      { role: 'system', content: finalSystemPrompt },
      { role: 'user', content: finalUserPrompt }
    ],
    5000, // Increased tokens for comprehensive final summary
    0.4, // Slightly higher temperature for more natural writing
    true // Use free model
  );

  console.log(`[Chunked Summarization] ✅ Final summary generated (${finalSummary.length} characters)`);
  
  return finalSummary;
}

// Chat with AI assistant about files
router.post('/chat', auth, async (req, res) => {
  try {
    const { question, fileId, context } = req.body;
    
    if (!question) {
      return res.status(400).json({ message: 'Question is required' });
    }
    
    // Check if this is a "how to" question (instructional) vs action request
    const lowerQuestion = question.toLowerCase();
    const isHowToQuestion = /^(how|what|where|when|why|can you explain|tell me|show me|help me understand)/i.test(question.trim()) ||
                            lowerQuestion.includes('how do i') ||
                            lowerQuestion.includes('how can i') ||
                            lowerQuestion.includes('how to') ||
                            lowerQuestion.includes('what is') ||
                            lowerQuestion.includes('what are') ||
                            lowerQuestion.includes('explain') ||
                            lowerQuestion.includes('guide') ||
                            lowerQuestion.includes('steps') ||
                            lowerQuestion.includes('instructions');
    
    // Only try to execute actions if it's NOT a "how to" question AND has file names
    let action = null;
    
    if (!isHowToQuestion) {
      // First, try to extract file names to see if this might be an action request
      const fileNames = aiActionExecutor.extractFileNames(question);
      const hasMultipleFiles = fileNames && fileNames.length >= 2;
      const hasFiles = fileNames && fileNames.length > 0;
      
      // Parse action with improved detection
      action = aiActionExecutor.parseAction(question);
      
      // If we have multiple files but no action detected, check if it's a relationship request
      if (hasMultipleFiles && !action) {
        if (lowerQuestion.includes('relationship') || lowerQuestion.includes('relate') || 
            lowerQuestion.includes('link') || lowerQuestion.includes('connect')) {
          action = {
            type: 'create_relationship',
            confidence: 0.8
          };
        }
      }
      
      // Also check for common action patterns even if parseAction didn't catch them
      if (!action && hasFiles) {
        // Check for social media post
        if ((lowerQuestion.includes('post') || lowerQuestion.includes('share')) && 
            (lowerQuestion.includes('social') || lowerQuestion.includes('feed') || lowerQuestion.includes('media'))) {
          action = { type: 'post_to_social', confidence: 0.8 };
        }
        // Check for star/favorite
        else if (lowerQuestion.includes('star') || lowerQuestion.includes('favorite') || lowerQuestion.includes('bookmark')) {
          action = { type: 'star_file', confidence: 0.75 };
        }
        // Check for share (but not "how to share")
        else if (lowerQuestion.includes('share') && !lowerQuestion.includes('how')) {
          action = { type: 'share_file', confidence: 0.75 };
        }
        // Check for move
        else if ((lowerQuestion.includes('move') || lowerQuestion.includes('transfer') || lowerQuestion.includes('put')) && 
                 !lowerQuestion.includes('how')) {
          action = { type: 'move_file', confidence: 0.7 };
        }
        // Check for rename
        else if ((lowerQuestion.includes('rename') || lowerQuestion.includes('change name') || lowerQuestion.includes('call')) &&
                 !lowerQuestion.includes('how')) {
          action = { type: 'rename_file', confidence: 0.75 };
        }
        // Check for relationship with multiple files
        else if (hasMultipleFiles && (lowerQuestion.includes('relationship') || lowerQuestion.includes('relate') || lowerQuestion.includes('link'))) {
          action = { type: 'create_relationship', confidence: 0.75 };
        }
        // Check for delete
        else if ((lowerQuestion.includes('delete') || lowerQuestion.includes('remove')) && 
                 !lowerQuestion.includes('how')) {
          action = { type: 'delete_file', confidence: 0.75 };
        }
      }
    }
    
    if (action && action.confidence >= 0.7) {
      console.log(`[AI Assistant] Detected action: ${action.type} (confidence: ${action.confidence})`);
      console.log(`[AI Assistant] Extracted file names: ${fileNames ? fileNames.join(', ') : 'none'}`);
      
      try {
        const result = await aiActionExecutor.executeAction(action, question, req.user._id);
        
        if (result.success) {
          return res.json({
            answer: result.message,
            action: {
              type: action.type,
              success: true,
              data: result.data
            },
            fileId: fileId || null,
            timestamp: new Date()
          });
        } else {
          // Action failed, but continue with normal chat flow
          // The error message will be included in the response
          return res.json({
            answer: result.message + '\n\nWould you like me to help you with something else?',
            action: {
              type: action.type,
              success: false,
              error: result.message
            },
            fileId: fileId || null,
            timestamp: new Date()
          });
        }
      } catch (actionError) {
        console.error('[AI Assistant] Action execution error:', actionError);
        // Continue with normal chat flow if action fails
      }
    }
    
    // Detect if user wants to summarize a file
    const isSummarizationRequest = /summar(?:ize|y|ies)|what (?:is|are|does)|tell me (?:about|what)|explain|describe|overview|key points|main (?:points|ideas|topics)/i.test(question);
    
    let fileContext = '';
    let targetFile = null;
    let fullFileContent = '';
    
    // If fileId provided, get file
    if (fileId) {
      targetFile = await File.findById(fileId);
      
      if (!targetFile) {
        return res.status(404).json({ message: 'File not found' });
      }
      
      // Check permissions
      if (targetFile.owner.toString() !== req.user._id.toString() &&
          !targetFile.sharedWith.some(s => s.user.toString() === req.user._id.toString())) {
        return res.status(403).json({ message: 'Access denied' });
      }
    } else {
      // Try to find file by name in question
      const fileMatch = question.match(/(?:the\s+)?([a-zA-Z0-9._-]+\.(?:pdf|docx?|txt|md|rtf|odt))/i);
      if (fileMatch) {
        const fileName = fileMatch[1];
        // Search for file by name
        const files = await File.find({
          $or: [
            { owner: req.user._id },
            { 'sharedWith.user': req.user._id }
          ],
          originalName: { $regex: fileName, $options: 'i' },
          isTrashed: { $ne: true }
        }).limit(1);
        
        if (files.length > 0) {
          targetFile = files[0];
        }
      }
    }
    
    // If we have a target file, extract full content for summarization
    if (targetFile) {
      // Check permissions
      if (targetFile.owner.toString() !== req.user._id.toString() &&
          !targetFile.sharedWith.some(s => s.user.toString() === req.user._id.toString())) {
        return res.status(403).json({ message: 'Access denied' });
      }
      
      // For summarization requests, extract full content
      if (isSummarizationRequest) {
        let fileContent = await FileContent.findOne({ file: targetFile._id });
        
        if (fileContent && fileContent.extractedText && fileContent.extractedText.trim().length > 0) {
          fullFileContent = fileContent.extractedText;
          console.log(`[AI Assistant] Using cached extracted text: ${fullFileContent.length} characters`);
        } else {
          // Extract text from file
          try {
            if (textExtractor.isSupported(targetFile.mimeType)) {
              console.log(`[AI Assistant] Extracting text from: ${targetFile.originalName} (${targetFile.mimeType})`);
              console.log(`[AI Assistant] File path: ${targetFile.path}`);
              
              const fs = require('fs-extra');
              const path = require('path');
              
              // Resolve absolute path
              let filePath = targetFile.path;
              if (!path.isAbsolute(filePath)) {
                filePath = path.resolve(__dirname, '..', filePath);
              }
              
              console.log(`[AI Assistant] Checking file at path: ${filePath}`);
              console.log(`[AI Assistant] Original path from DB: ${targetFile.path}`);
              
              const fileExists = await fs.pathExists(filePath);
              if (!fileExists) {
                // Try alternative path resolution
                const altPath = path.join(__dirname, '..', 'uploads', targetFile.owner.toString(), targetFile.name);
                console.log(`[AI Assistant] File not found at primary path, trying alternative: ${altPath}`);
                const altExists = await fs.pathExists(altPath);
                
                if (altExists) {
                  filePath = altPath;
                  console.log(`[AI Assistant] ✅ Found file at alternative path`);
                } else {
                  return res.status(404).json({ 
                    message: `File not found on disk. Tried: ${filePath} and ${altPath}`,
                    debug: {
                      originalPath: targetFile.path,
                      resolvedPath: filePath,
                      alternativePath: altPath,
                      fileName: targetFile.name,
                      originalName: targetFile.originalName
                    }
                  });
                }
              } else {
                console.log(`[AI Assistant] ✅ File exists at: ${filePath}`);
              }
              
              // Check file size
              const stats = await fs.stat(filePath);
              console.log(`[AI Assistant] File size: ${stats.size} bytes`);
              
              if (stats.size === 0) {
                return res.status(400).json({ 
                  message: 'File is empty (0 bytes)' 
                });
              }
              
              // Try extraction with retry logic
              let extractionAttempts = 0;
              const maxAttempts = 3;
              
              while (extractionAttempts < maxAttempts && (!fullFileContent || fullFileContent.trim().length < 10)) {
                extractionAttempts++;
                console.log(`[AI Assistant] Extraction attempt ${extractionAttempts}/${maxAttempts} for: ${targetFile.originalName}`);
                console.log(`[AI Assistant] File type: ${targetFile.mimeType}`);
                console.log(`[AI Assistant] Is supported: ${textExtractor.isSupported(targetFile.mimeType)}`);
                
                try {
                  fullFileContent = await textExtractor.extractText(filePath, targetFile.mimeType);
                  console.log(`[AI Assistant] Extraction result: ${fullFileContent ? fullFileContent.length : 0} characters`);
                  
                  if (fullFileContent && fullFileContent.trim().length > 0) {
                    console.log(`[AI Assistant] ✅ Successfully extracted ${fullFileContent.length} characters`);
                    console.log(`[AI Assistant] Extracted text preview: ${fullFileContent.substring(0, 300).replace(/\n/g, ' ')}...`);
                    break; // Success, exit retry loop
                  } else {
                    console.log(`[AI Assistant] ⚠️ Extraction returned empty or very short text`);
                    console.log(`[AI Assistant] Raw extraction result type: ${typeof fullFileContent}`);
                    console.log(`[AI Assistant] Raw extraction result: ${fullFileContent ? fullFileContent.substring(0, 100) : 'null/undefined'}`);
                    
                    // If this is a PDF and we got no text, it's likely image-based
                    // The textExtractor should have tried OCR, but let's log this
                    if (targetFile.mimeType.includes('pdf')) {
                      console.log(`[AI Assistant] PDF returned no text - OCR should have been attempted automatically`);
                      console.log(`[AI Assistant] If OCR was attempted, check logs above for OCR results`);
                    }
                    
                    if (extractionAttempts < maxAttempts) {
                      console.log(`[AI Assistant] Retrying extraction in 2 seconds...`);
                      await new Promise(resolve => setTimeout(resolve, 2000)); // Wait 2 seconds before retry
                    }
                  }
                } catch (extractError) {
                  console.error(`[AI Assistant] Extraction attempt ${extractionAttempts} failed:`, extractError.message);
                  console.error(`[AI Assistant] Extraction error stack:`, extractError.stack);
                  if (extractionAttempts >= maxAttempts) {
                    return res.status(500).json({ 
                      message: `Failed to extract text after ${maxAttempts} attempts: ${extractError.message}. This PDF may be image-based and OCR processing may have failed.`,
                      error: process.env.NODE_ENV === 'development' ? extractError.stack : undefined
                    });
                  }
                  await new Promise(resolve => setTimeout(resolve, 2000)); // Wait before retry
                }
              }
              
              // Save extracted text for future use (even if short)
              if (!fileContent) {
                fileContent = new FileContent({
                  file: targetFile._id,
                  extractedText: fullFileContent || '',
                  extractionStatus: fullFileContent && fullFileContent.trim().length > 0 ? 'completed' : 'failed'
                });
              } else {
                fileContent.extractedText = fullFileContent || '';
                fileContent.extractionStatus = fullFileContent && fullFileContent.trim().length > 0 ? 'completed' : 'failed';
              }
              await fileContent.save();
            } else {
              return res.status(400).json({ 
                message: `Cannot summarize this file type (${targetFile.mimeType}). Supported types: PDF, Word documents, text files, and images.` 
              });
            }
          } catch (error) {
            console.error('[AI Assistant] Error extracting text:', error);
            console.error('[AI Assistant] Error stack:', error.stack);
            return res.status(500).json({ 
              message: `Failed to extract text from file: ${error.message}`,
              error: process.env.NODE_ENV === 'development' ? error.stack : undefined
            });
          }
        }
        
        // Lower threshold and provide better error message
        const textLength = fullFileContent ? fullFileContent.trim().length : 0;
        if (!fullFileContent || textLength < 10) {
          return res.status(400).json({ 
            message: `File does not contain enough text to summarize. Extracted ${textLength} characters. The file may be empty, scanned (image-based), or corrupted.`,
            extractedLength: textLength,
            suggestion: textLength === 0 ? 'Try using OCR or check if the file is a scanned PDF/image.' : 'The file contains very little text. Please check if the file is readable.'
          });
        }
        
        console.log(`[AI Assistant] Proceeding with summarization. Text length: ${textLength} characters`);
        
        // Store full content for chunked summarization
        // We'll use chunked summarization for long PDFs (following Adrian Twarog's approach)
        fileContext = fullFileContent; // Store raw text for chunked processing
      } else {
        // For regular questions, use preview
        let summary = await FileSummary.findOne({ file: targetFile._id });
        
        if (!summary) {
          let fileContent = await FileContent.findOne({ file: targetFile._id });
          let extractedText = '';
          
          if (fileContent && fileContent.extractedText) {
            extractedText = fileContent.extractedText.substring(0, 2000);
          } else {
            try {
              if (textExtractor.isSupported(targetFile.mimeType)) {
                extractedText = await textExtractor.extractText(targetFile.path, targetFile.mimeType);
                extractedText = extractedText.substring(0, 2000);
              }
            } catch (error) {
              // Can't extract text
            }
          }
          
          if (extractedText) {
            fileContext = `File: ${targetFile.originalName}\nContent preview: ${extractedText.substring(0, 1000)}...`;
          } else {
            fileContext = `File: ${targetFile.originalName}\nType: ${targetFile.mimeType}\nSize: ${(targetFile.size / 1024 / 1024).toFixed(2)} MB`;
          }
        } else {
          fileContext = `File: ${targetFile.originalName}\nSummary: ${summary.summary}\nKey Points: ${summary.keyPoints.join(', ')}`;
        }
      }
    }
    
    // Build comprehensive system prompt for OpenRouter
    const systemPrompt = isSummarizationRequest && fullFileContent
      ? `You are an intelligent AI assistant for File Box, an AI-powered cloud storage and file management platform. The user has asked you to summarize a file. 

Your task is to read the full file content provided and generate a comprehensive, well-structured summary that includes:
1. **Main Topic/Subject**: What is this document about?
2. **Key Points**: The most important points, findings, or information (3-5 main points)
3. **Important Details**: Any significant dates, numbers, names, or facts
4. **Conclusion/Summary**: A brief overall summary (2-3 sentences)

Be thorough but concise. Focus on the most important information. Use clear, organized formatting with bullet points or sections.`
      : `You are an intelligent AI assistant for File Box, an AI-powered cloud storage and file management platform. You are like ChatGPT but specifically for File Box - you can answer ANY question about how to use the platform, its features, and help users accomplish their tasks.

## FILE BOX PLATFORM - COMPLETE FEATURE GUIDE:

### 📁 CORE FILE MANAGEMENT:
- **Upload Files**: Click the "→ Upload" button in the file browser, or drag and drop files directly into the browser
- **View Files**: Click on any file to open/preview it. PDFs, images, videos, and text files can be previewed directly in the browser
- **Download Files**: Click the download icon on any file to download it
- **Delete Files**: Click the delete/trash icon. Files go to Trash and can be restored
- **Restore Files**: Go to "Trash" section, click on a file, and click "Restore"
- **Star Files**: Click the star icon to mark files as favorites. Access starred files from "Starred" in sidebar
- **Create Folders**: Click "New Folder" button, enter a name, and click Create
- **Navigate Folders**: Click on any folder to open it. Use breadcrumbs or "Back" button to navigate up
- **Search Files**: Use the search bar at the top to search by filename or file content (AI-powered semantic search)

### 🔗 FILE RELATIONSHIPS:
- **Create Relationships**: Go to "Relationships" in sidebar → Click "Add Relationship" → Select source file → Select target file → Choose relationship type (Related to, Depends on, References, Part of, Version of, Duplicate of, Custom) → Add optional label and description → Click Create
- **View Relationship Graph**: Go to "Relationships" → Click "View Graph" to see visual representation of all file relationships
- **Edit Relationship Type**: In the graph, click on any relationship arrow → Select new type from dropdown → Click "Update Type"
- **Delete Relationships**: In Relationships section, click delete button on any relationship, or in graph click relationship and click "Delete Relationship"
- **Relationship Types**: 
  - Related to: General connection
  - Depends on: One file depends on another
  - References: One file references another
  - Part of: One file is part of another
  - Version of: One file is a version of another
  - Duplicate of: Files are duplicates
  - Custom: Custom relationship with your own label

### 👥 SHARING & COLLABORATION:
- **Share with Users**: Click "Share" button on any file → Select "Share with User" tab → Search for registered users → Select users → Choose permission (View Only or Can Edit) → Optionally add password protection and expiration date → Click Share
- **View Shared Files**: Go to "Shared" in sidebar → See "Shared with Me" (files others shared) and "Shared by Me" (files you shared)
- **Remove Share**: In "Shared by Me" tab, click "Remove Share" button on any file
- **File Requests**: Go to "File Requests" → Click "Create Request" → Enter title and description → Set expiration date → Share the request link with others → They can upload files to your request
- **Team Folders**: Go to "Team Folders" → Click "Create Team Folder" → Add members with roles (admin, editor, viewer) → Members can collaborate on files in the folder
- **Team Folder Roles**: Admin (full control), Editor (can edit files), Viewer (read-only)

### 📚 STUDENT FEATURES:
- **Student Dashboard**: Go to "Student" in sidebar → Manage courses, assignments, and study groups
- **Courses**: Create courses with course codes and names → Each course has its own folder
- **Assignments**: Track assignments with due dates, status (pending, in progress, completed), and associated files
- **Study Groups**: 
  - Create: Go to Student Dashboard → Select a course → Click "Study Groups" tab → Click "Create Study Group" → Enter name, description, course info
  - Join: Accept invitations or join public groups
  - Invite Users: In a study group, go to "Members" tab → Click "Invite Users" → Select users to invite
  - Study Tools in Groups:
    - **Files**: Shared file browser for the group
    - **Notes**: Create collaborative study notes with tags
    - **Flashcards**: Create flashcards with front/back, decks, and difficulty levels
    - **Whiteboard**: Collaborative text-based whiteboard for brainstorming
    - **Chat**: Real-time group chat for discussions
    - **Members**: View and manage group members

### 📊 ANALYTICS:
- **Access Analytics**: Go to "Analytics" in sidebar
- **View Statistics**: See file access stats, storage breakdown by type, activity timeline, top file types
- **Access Heatmap**: See when you access files most (by day of week and hour)
- **Storage Breakdown**: See how much storage each file type uses
- **Unused Files**: Identify files not accessed in a specified period

### 🛡️ SECURITY:
- **Security Dashboard**: Go to "Security" in sidebar → View security settings, audit logs, data classification
- **Data Classification**: Mark files as Public, Internal, Confidential, or Top Secret
- **Watermark**: Enable watermarking for sensitive files
- **Audit Logs**: View all security-related activities

### 🤖 AI FEATURES:
- **AI Summary**: Click on any PDF/document → Click "AI Summary" button → Get comprehensive summary
- **Smart Organization**: Click "Smart Organize" button → AI suggests folder organization for your files
- **AI Search**: Use search bar for semantic search through file contents (not just filenames)
- **AI Assistant**: This chat interface - ask anything about File Box or your files

### 📱 SOCIAL FEATURES:
- **Social Feed**: Go to "Social Feed" in sidebar → See posts from users you follow → Like, comment, repost
- **Create Post**: Share files or folders to social feed with descriptions
- **Follow Users**: Search for users and follow them to see their shared content
- **Groups**: Create or join groups → Share files within groups

### 🎯 NAVIGATION GUIDE:
- **Left Sidebar**: All main features accessible here
  - **MAIN**: Files, Shared, Starred, Trash
  - **COLLABORATION**: Team Folders, File Requests, Relationships, Social Feed
  - **TOOLS**: Analytics, Security, AI Assistant, Student
- **Top Search Bar**: Search files and folders by name or content
- **File Browser**: Main area showing files and folders with grid/list view toggle

### 💡 COMMON TASKS - STEP BY STEP:

**How to create a relationship between two files:**
1. Go to "Relationships" in the sidebar (under Collaboration)
2. Click "Add Relationship" or "Create Relationship" button
3. Select the source file (first file)
4. Select the target file (second file)
5. Choose relationship type from dropdown
6. Optionally add a custom label and description
7. Click "Create" button
8. The relationship will appear in the graph and relationships list

**How to share a file:**
1. Click on any file to select it
2. Click the "Share" button (or right-click → Share)
3. In the Share modal, go to "Share with User" tab
4. Search for registered users by name or email
5. Select the users you want to share with
6. Choose permission: "View Only" or "Can Edit"
7. Optionally set password protection and expiration date
8. Click "Share with X User(s)" button

**How to create a study group:**
1. Go to "Student" in sidebar
2. Select a course (or create one first)
3. Click "Study Groups" tab
4. Click "Create Study Group" button
5. Enter group name, description, course code
6. Choose if it's public or private
7. Click "Create"
8. Invite members from the "Members" tab

**How to upload files:**
1. Click the "→ Upload" button in the file browser
2. Select files from your computer
3. Files will upload automatically
4. Or drag and drop files directly into the browser window

**How to organize files:**
1. Use "Smart Organize" button for AI suggestions
2. Or manually create folders and move files
3. Click "New Folder" to create folders
4. Use move/copy actions to organize files

## YOUR ROLE:
- Answer ANY question about how to use File Box platform
- Provide step-by-step instructions for any task
- Explain features clearly and concisely
- Help troubleshoot issues
- Guide users through workflows
- If asked about unrelated topics, politely redirect to File Box features
- Be like ChatGPT but specifically for File Box - knowledgeable, helpful, and conversational

## RESPONSE STYLE:
- Be friendly, helpful, and conversational (like ChatGPT)
- Provide clear step-by-step instructions when needed
- Use examples and specific feature names
- Be concise but thorough
- Use emojis sparingly for clarity (📁 📄 👥 etc.)
- If you don't know something specific, say so but offer related help
- Always be helpful and encouraging

Remember: You are the ChatGPT for File Box platform. You know everything about how to use File Box and can help users accomplish any task. Answer questions about features, guide users through workflows, and help them get the most out of the platform.`;

    try {
      let answer;
      
      // For summarization requests with file content, use chunked summarization
      if (isSummarizationRequest && fullFileContent) {
        console.log(`[AI Assistant] Starting chunked summarization for: ${targetFile.originalName}`);
        
        try {
          answer = await summarizeWithChunking(fullFileContent, targetFile.originalName);
          
          if (!answer || answer.trim().length === 0) {
            throw new Error('Summarization returned empty result');
          }
          
          console.log(`[AI Assistant] ✅ Summarization completed successfully`);
        } catch (summarizationError) {
          console.error('[AI Assistant] Summarization error:', summarizationError);
          throw summarizationError;
        }
      } else {
        // Check for file memory if we have a target file
        let memoryContext = '';
        if (targetFile) {
          try {
            const fileMemory = await FileMemory.findOne({ 
              file: targetFile._id, 
              owner: req.user._id 
            }).populate('creationContext.relatedFiles', 'originalName')
              .populate('creationContext.relatedFolders', 'name');
            
            if (fileMemory) {
              memoryContext = `\n\nFile Memory Context (why this file was saved, project info, etc.):\n`;
              if (fileMemory.creationContext.userAction) {
                memoryContext += `- Why you saved it: ${fileMemory.creationContext.userAction}\n`;
              }
              if (fileMemory.creationContext.projectContext) {
                memoryContext += `- Project: ${fileMemory.creationContext.projectContext}\n`;
              }
              if (fileMemory.creationContext.meetingContext) {
                memoryContext += `- Meeting/Event: ${fileMemory.creationContext.meetingContext}\n`;
              }
              if (fileMemory.creationContext.deadlineContext) {
                memoryContext += `- Deadline: ${new Date(fileMemory.creationContext.deadlineContext).toLocaleDateString()}\n`;
              }
              if (fileMemory.aiInsights && fileMemory.aiInsights.purpose) {
                memoryContext += `- AI-detected purpose: ${fileMemory.aiInsights.purpose}\n`;
              }
              if (fileMemory.userNotes && fileMemory.userNotes.length > 0) {
                memoryContext += `- Your notes: ${fileMemory.userNotes[fileMemory.userNotes.length - 1].content}\n`;
              }
            }
          } catch (memoryError) {
            console.error('Error fetching file memory:', memoryError);
            // Continue without memory context if there's an error
          }
        }
        
        // For regular questions, use standard chat flow
        const userPrompt = `${fileContext ? `File Context:\n${fileContext}\n` : ''}${memoryContext}${context ? `Additional Context:\n${context}\n\n` : ''}
User Question: ${question}

Answer the user's question about File Box platform. Be helpful, clear, and provide step-by-step instructions if needed. If the question is about why a file was saved or its context, use the File Memory Context provided above.`;

        answer = await callOpenRouter(
          [
            {
              role: 'system',
              content: systemPrompt
            },
            {
              role: 'user',
              content: userPrompt
            }
          ],
          800,
          0.7
        );
      }
      
      res.json({
        answer: answer.trim(),
        fileId: fileId || null,
        timestamp: new Date()
      });
    } catch (error) {
      console.error('OpenRouter API error:', error.response?.data || error.message);
      console.error('Full error:', error);
      
      // More detailed error handling
      let errorMessage = 'I apologize, but I encountered an error. ';
      
      if (error.response) {
        // API responded with error
        const status = error.response.status;
        const data = error.response.data;
        
        if (status === 401) {
          errorMessage += 'The API key is invalid. Please check your OpenRouter API key configuration.';
        } else if (status === 429) {
          errorMessage += 'Too many requests. Please wait a moment and try again.';
        } else if (data?.error?.message) {
          errorMessage += `Error: ${data.error.message}`;
        } else {
          errorMessage += `API error (${status}). Please try again.`;
        }
      } else if (error.request) {
        // Request made but no response
        errorMessage += 'Could not connect to the AI service. Please check your internet connection.';
      } else {
        // Error setting up request
        errorMessage += error.message || 'Unknown error occurred.';
      }
      
      res.status(500).json({
        answer: errorMessage,
        fileId: fileId || null,
        timestamp: new Date(),
        error: process.env.NODE_ENV === 'development' ? {
          message: error.message,
          response: error.response?.data,
          stack: error.stack
        } : undefined
      });
    }
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Debug: Test text extraction for a file
router.get('/debug/extract/:fileId', auth, async (req, res) => {
  try {
    const file = await File.findById(req.params.fileId);
    
    if (!file) {
      return res.status(404).json({ message: 'File not found' });
    }
    
    // Check permissions
    if (file.owner.toString() !== req.user._id.toString() &&
        !file.sharedWith.some(s => s.user.toString() === req.user._id.toString())) {
      return res.status(403).json({ message: 'Access denied' });
    }
    
    const fs = require('fs-extra');
    const fileExists = await fs.pathExists(file.path);
    
    let result = {
      file: {
        name: file.originalName,
        path: file.path,
        mimeType: file.mimeType,
        size: file.size,
        exists: fileExists
      },
      extraction: {
        supported: textExtractor.isSupported(file.mimeType),
        extractedText: '',
        textLength: 0,
        error: null
      }
    };
    
    if (!fileExists) {
      result.extraction.error = 'File not found on disk';
      return res.json(result);
    }
    
    if (!textExtractor.isSupported(file.mimeType)) {
      result.extraction.error = 'File type not supported for text extraction';
      return res.json(result);
    }
    
    try {
      const extractedText = await textExtractor.extractText(file.path, file.mimeType);
      result.extraction.extractedText = extractedText || '';
      result.extraction.textLength = extractedText ? extractedText.trim().length : 0;
      result.extraction.preview = extractedText ? extractedText.substring(0, 500) : '';
    } catch (error) {
      result.extraction.error = error.message;
      result.extraction.errorStack = error.stack;
    }
    
    res.json(result);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Get file insights
router.get('/insights/:fileId', auth, async (req, res) => {
  try {
    const file = await File.findById(req.params.fileId);
    
    if (!file) {
      return res.status(404).json({ message: 'File not found' });
    }
    
    // Check permissions
    if (file.owner.toString() !== req.user._id.toString() &&
        !file.sharedWith.some(s => s.user.toString() === req.user._id.toString())) {
      return res.status(403).json({ message: 'Access denied' });
    }
    
    const summary = await FileSummary.findOne({ file: file._id });
    
    const insights = {
      file: {
        name: file.originalName,
        type: file.mimeType,
        size: file.size,
        createdAt: file.createdAt
      },
      summary: summary ? {
        summary: summary.summary,
        keyPoints: summary.keyPoints,
        readingTime: summary.readingTime,
        wordCount: summary.wordCount
      } : null,
      access: {
        viewCount: file.accessLog.filter(a => a.action === 'view').length,
        downloadCount: file.accessLog.filter(a => a.action === 'download').length,
        lastAccessed: file.accessLog.length > 0 ? file.accessLog[file.accessLog.length - 1].timestamp : null
      },
      suggestions: []
    };
    
    // Generate suggestions
    if (summary && summary.extractedData) {
      if (summary.extractedData.dates && summary.extractedData.dates.length > 0) {
        insights.suggestions.push('This file contains dates - consider adding to calendar');
      }
      if (summary.extractedData.amounts && summary.extractedData.amounts.length > 0) {
        insights.suggestions.push('This file contains financial information - consider marking as confidential');
      }
    }
    
    if (file.accessLog.length === 0) {
      insights.suggestions.push('This file has not been accessed yet');
    }
    
    res.json(insights);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});


module.exports = router;

