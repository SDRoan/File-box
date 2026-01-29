const File = require('../models/File');
const Folder = require('../models/Folder');
const FileRelationship = require('../models/FileRelationship');
const User = require('../models/User');
const SocialPost = require('../models/SocialPost');
const Share = require('../models/Share');

/**
 * AI Action Executor - Executes actions requested by users through the AI assistant
 */
class AIActionExecutor {
  /**
   * Parse user message to detect action intent - improved to handle natural language
   */
  parseAction(message) {
    const lowerMessage = message.toLowerCase();
    
    // Relationship actions - more flexible patterns
    if (/create.*relationship|relate|link|connect.*file|relationship.*between|make.*relationship|add.*relationship/i.test(message) ||
        (lowerMessage.includes('relationship') && (lowerMessage.includes('create') || lowerMessage.includes('make') || lowerMessage.includes('add')))) {
      return {
        type: 'create_relationship',
        confidence: 0.9
      };
    }
    
    // Also check if message contains file names and relationship keywords
    const hasFileNames = this.extractFileNames(message);
    if (hasFileNames && hasFileNames.length >= 2 && 
        (lowerMessage.includes('relationship') || lowerMessage.includes('relate') || lowerMessage.includes('link') || lowerMessage.includes('connect'))) {
      return {
        type: 'create_relationship',
        confidence: 0.85
      };
    }
    
    // Delete actions
    if (/delete|remove|trash/i.test(message) && /file|document/i.test(message)) {
      return {
        type: 'delete_file',
        confidence: 0.8
      };
    }
    
    // Create folder
    if (/create.*folder|make.*folder|new.*folder/i.test(message)) {
      return {
        type: 'create_folder',
        confidence: 0.9
      };
    }
    
    // Post to social feed
    if (/post.*social|share.*social|post.*feed|share.*feed|post.*media/i.test(message) ||
        (lowerMessage.includes('post') && (lowerMessage.includes('social') || lowerMessage.includes('feed') || lowerMessage.includes('media')))) {
      return {
        type: 'post_to_social',
        confidence: 0.9
      };
    }
    
    // Share file (with user or create link)
    if (/share.*file|share.*with|create.*share|share.*link/i.test(message)) {
      return {
        type: 'share_file',
        confidence: 0.8
      };
    }
    
    // Star file
    if (/star|favorite|bookmark/i.test(message) && /file|document/i.test(message)) {
      return {
        type: 'star_file',
        confidence: 0.8
      };
    }
    
    // Move file
    if (/move|transfer|put.*in|move.*to/i.test(message)) {
      return {
        type: 'move_file',
        confidence: 0.7
      };
    }
    
    // Rename file
    if (/rename|change.*name|call.*file|name.*file/i.test(message)) {
      return {
        type: 'rename_file',
        confidence: 0.8
      };
    }
    
    return null;
  }
  
  /**
   * Extract file names from message - improved to handle natural language
   */
  extractFileNames(message) {
    const fileNames = [];
    
    // Pattern 1: Find file names with extensions (most reliable)
    // This handles: "file1.pdf", "file1.pdf and file2.pdf", "file1.pdf, file2.pdf"
    // Improved regex to match file names more accurately
    const filePattern = /([a-zA-Z0-9][a-zA-Z0-9._-]*\.(?:pdf|docx?|txt|md|rtf|odt|jpg|jpeg|png|gif|mp4|mp3|zip|rar|pptx?|xlsx?|csv|json|xml|html|css|js|ts|py|java|cpp|c|h|go|rs|rb|php|swift|kt|dart|sh|bat|ps1))/gi;
    let match;
    const seen = new Set();
    
    while ((match = filePattern.exec(message)) !== null) {
      let fileName = match[1].trim();
      
      // Remove any trailing words that aren't part of the filename
      // This handles cases like "file1.pdf and" -> "file1.pdf"
      fileName = fileName.replace(/\s+(and|or|create|relationship|relate|link|connect|between|from|to|delete|remove|share|star)\s*$/i, '').trim();
      
      // Clean up any extra whitespace within the filename
      fileName = fileName.replace(/\s+/g, '');
      
      if (fileName && fileName.length > 0 && fileName.length < 200 && !seen.has(fileName.toLowerCase())) {
        fileNames.push(fileName);
        seen.add(fileName.toLowerCase());
      }
    }
    
    if (fileNames.length > 0) {
      return fileNames;
    }
    
    // Pattern 2: Try to find quoted file names
    const quotedPattern = /["']([^"']+\.(?:pdf|docx?|txt|md|rtf|odt|jpg|jpeg|png|gif|mp4|mp3|zip|rar|pptx?|xlsx?))["']/gi;
    const quotedMatches = [];
    while ((match = quotedPattern.exec(message)) !== null) {
      quotedMatches.push(match[1].trim());
    }
    
    if (quotedMatches.length > 0) {
      return [...new Set(quotedMatches)];
    }
    
    // Pattern 3: Try to extract file names from common phrases
    // "between file1 and file2", "file1 and file2", etc.
    const phrasePatterns = [
      /(?:between|from)\s+([a-zA-Z0-9._-]+\.(?:pdf|docx?|txt|md|rtf|odt|jpg|jpeg|png|gif|mp4|mp3|zip|rar|pptx?|xlsx?))\s+and\s+([a-zA-Z0-9._-]+\.(?:pdf|docx?|txt|md|rtf|odt|jpg|jpeg|png|gif|mp4|mp3|zip|rar|pptx?|xlsx?))/gi,
      /([a-zA-Z0-9._-]+\.(?:pdf|docx?|txt|md|rtf|odt|jpg|jpeg|png|gif|mp4|mp3|zip|rar|pptx?|xlsx?))\s+and\s+([a-zA-Z0-9._-]+\.(?:pdf|docx?|txt|md|rtf|odt|jpg|jpeg|png|gif|mp4|mp3|zip|rar|pptx?|xlsx?))/gi,
      /([a-zA-Z0-9._-]+\.(?:pdf|docx?|txt|md|rtf|odt|jpg|jpeg|png|gif|mp4|mp3|zip|rar|pptx?|xlsx?))\s*,\s*([a-zA-Z0-9._-]+\.(?:pdf|docx?|txt|md|rtf|odt|jpg|jpeg|png|gif|mp4|mp3|zip|rar|pptx?|xlsx?))/gi
    ];
    
    for (const pattern of phrasePatterns) {
      const matches = [];
      while ((match = pattern.exec(message)) !== null) {
        if (match[1]) matches.push(match[1].trim());
        if (match[2]) matches.push(match[2].trim());
      }
      if (matches.length > 0) {
        return [...new Set(matches)];
      }
    }
    
    // Pattern 4: Try to find file names after keywords
    const keywordPatterns = [
      /(?:file|document|the)\s+([a-zA-Z0-9._-]+\.(?:pdf|docx?|txt|md|rtf|odt|jpg|jpeg|png|gif|mp4|mp3|zip|rar|pptx?|xlsx?))/gi,
      /([a-zA-Z0-9._-]+\.(?:pdf|docx?|txt|md|rtf|odt|jpg|jpeg|png|gif|mp4|mp3|zip|rar|pptx?|xlsx?))\s+(?:file|document)/gi
    ];
    
    for (const pattern of keywordPatterns) {
      const matches = [];
      while ((match = pattern.exec(message)) !== null) {
        matches.push(match[1].trim());
      }
      if (matches.length > 0) {
        return [...new Set(matches)];
      }
    }
    
    return null;
  }
  
  /**
   * Find files by name for a user
   */
  async findFilesByName(fileNames, userId) {
    const files = [];
    
    for (const fileName of fileNames) {
      // Clean up the file name (remove extra spaces, etc.)
      const cleanName = fileName.trim();
      
      // Try exact match first
      let file = await File.findOne({
        owner: userId,
        originalName: cleanName,
        isTrashed: { $ne: true }
      });
      
      // If not found, try partial match
      if (!file) {
        // Escape special regex characters but allow partial matching
        const escapedName = cleanName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        file = await File.findOne({
          owner: userId,
          originalName: { $regex: escapedName, $options: 'i' },
          isTrashed: { $ne: true }
        });
      }
      
      // If still not found, try matching just the base name (without extension)
      if (!file && cleanName.includes('.')) {
        const baseName = cleanName.split('.')[0];
        const escapedBase = baseName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        file = await File.findOne({
          owner: userId,
          originalName: { $regex: `^${escapedBase}`, $options: 'i' },
          isTrashed: { $ne: true }
        });
      }
      
      if (file) {
        files.push(file);
      }
    }
    
    return files;
  }
  
  /**
   * Execute create relationship action
   */
  async createRelationship(message, userId) {
    let fileNames = this.extractFileNames(message);
    console.log(`[Action Executor] Extracted file names: ${JSON.stringify(fileNames)}`);
    
    // If we couldn't extract file names, try a more aggressive approach
    if (!fileNames || fileNames.length < 2) {
      // Try to find any file names in the message, even without explicit structure
      const allFiles = await File.find({
        owner: userId,
        isTrashed: { $ne: true }
      }).select('originalName');
      
      // Look for file names mentioned in the message
      const mentionedFiles = [];
      for (const file of allFiles) {
        const fileName = file.originalName.toLowerCase();
        const messageLower = message.toLowerCase();
        // Check if file name appears in message (allowing for partial matches)
        if (messageLower.includes(fileName) || fileName.includes(messageLower.split(/\s+/).find(w => w.includes('.')) || '')) {
          mentionedFiles.push(file.originalName);
        }
      }
      
      if (mentionedFiles.length >= 2) {
        fileNames = mentionedFiles.slice(0, 2);
      }
    }
    
    if (!fileNames || fileNames.length < 2) {
      return {
        success: false,
        message: "I need at least two file names to create a relationship. I found these files in your message, but couldn't identify two distinct files. Please try: 'Create a relationship between file1.pdf and file2.pdf' or just list the file names like 'file1.pdf and file2.pdf create relationship'"
      };
    }
    
    // Clean up file names - remove any extra words that might have been captured
    fileNames = fileNames.map(name => {
      // Remove common words that might have been captured
      return name.replace(/\s+(and|or|create|relationship|relate|link|connect|between|from|to)\s+/gi, ' ').trim();
    }).filter(name => name.length > 0);
    
    console.log(`[Action Executor] Cleaned file names: ${JSON.stringify(fileNames)}`);
    const files = await this.findFilesByName(fileNames, userId);
    console.log(`[Action Executor] Found ${files.length} files: ${files.map(f => f.originalName).join(', ')}`);
    
    if (files.length < 2) {
      const found = files.map(f => f.originalName).join(', ');
      const notFound = fileNames.filter(name => !files.some(f => {
        const fileNameLower = f.originalName.toLowerCase();
        const searchNameLower = name.toLowerCase();
        return fileNameLower === searchNameLower || fileNameLower.includes(searchNameLower) || searchNameLower.includes(fileNameLower);
      }));
      
      // Try to find files with partial matches
      if (files.length < 2) {
        const allUserFiles = await File.find({
          owner: userId,
          isTrashed: { $ne: true }
        }).select('originalName');
        
        // Show suggestions
        const suggestions = allUserFiles.slice(0, 5).map(f => f.originalName).join(', ');
        return {
          success: false,
          message: `I couldn't find both files. Looking for: ${fileNames.join(' and ')}. Found: ${found || 'none'}. Not found: ${notFound.join(', ')}. Your recent files include: ${suggestions}. Please check the file names and try again.`
        };
      }
    }
    
    // Extract relationship type from message
    let relationshipType = 'related';
    if (/version|v\d+/i.test(message)) {
      relationshipType = 'version_of';
    } else if (/depends|dependency/i.test(message)) {
      relationshipType = 'depends_on';
    } else if (/references|refers/i.test(message)) {
      relationshipType = 'references';
    } else if (/part|contains/i.test(message)) {
      relationshipType = 'part_of';
    }
    
    // Check if relationship already exists
    const existing = await FileRelationship.findOne({
      sourceFile: files[0]._id,
      targetFile: files[1]._id,
      owner: userId
    });
    
    if (existing) {
      return {
        success: false,
        message: `A relationship already exists between "${files[0].originalName}" and "${files[1].originalName}".`
      };
    }
    
    // Create relationship
    const relationship = new FileRelationship({
      sourceFile: files[0]._id,
      targetFile: files[1]._id,
      relationshipType,
      owner: userId
    });
    
    await relationship.save();
    
    return {
      success: true,
      message: `✅ Successfully created a relationship between "${files[0].originalName}" and "${files[1].originalName}" (${relationshipType}).`,
      data: {
        relationshipId: relationship._id,
        sourceFile: files[0].originalName,
        targetFile: files[1].originalName,
        relationshipType
      }
    };
  }
  
  /**
   * Execute delete file action
   */
  async deleteFile(message, userId) {
    const fileNames = this.extractFileNames(message);
    
    if (!fileNames || fileNames.length === 0) {
      return {
        success: false,
        message: "I need a file name to delete. Please specify which file you want to delete."
      };
    }
    
    const files = await this.findFilesByName(fileNames, userId);
    
    if (files.length === 0) {
      return {
        success: false,
        message: `Could not find file(s): ${fileNames.join(', ')}. Please check the file names and try again.`
      };
    }
    
    // Delete files (move to trash)
    const deletedFiles = [];
    for (const file of files) {
      file.isTrashed = true;
      file.trashedAt = new Date();
      await file.save();
      deletedFiles.push(file.originalName);
    }
    
    return {
      success: true,
      message: `✅ Successfully deleted ${deletedFiles.length} file(s): ${deletedFiles.join(', ')}. They have been moved to Trash.`,
      data: {
        deletedFiles: deletedFiles
      }
    };
  }
  
  /**
   * Execute create folder action
   */
  async createFolder(message, userId) {
    // Extract folder name from message
    const folderNameMatch = message.match(/(?:create|make|new).*folder.*(?:called|named|with.*name)?\s*["']?([a-zA-Z0-9._\s-]+)["']?/i);
    const folderName = folderNameMatch ? folderNameMatch[1].trim() : null;
    
    if (!folderName) {
      return {
        success: false,
        message: "I need a folder name to create. Please specify the folder name, for example: 'Create a folder called My Documents'"
      };
    }
    
    // Check if folder already exists
    const existing = await Folder.findOne({
      name: folderName,
      owner: userId,
      isTrashed: { $ne: true }
    });
    
    if (existing) {
      return {
        success: false,
        message: `A folder named "${folderName}" already exists.`
      };
    }
    
    // Create folder
    const folder = new Folder({
      name: folderName,
      owner: userId
    });
    
    await folder.save();
    
    return {
      success: true,
      message: `✅ Successfully created folder "${folderName}".`,
      data: {
        folderId: folder._id,
        folderName: folder.name
      }
    };
  }
  
  /**
   * Extract caption/description from message
   */
  extractCaption(message) {
    // Try to find quoted text (caption) - most reliable
    const quotedPatterns = [
      /caption\s*["']([^"']+)["']/i,
      /with\s+["']([^"']+)["']/i,
      /description\s*["']([^"']+)["']/i,
      /["']([^"']+)["']/g  // Any quoted text as fallback
    ];
    
    for (const pattern of quotedPatterns) {
      const match = message.match(pattern);
      if (match && match[1]) {
        // Make sure it's not a filename
        const text = match[1];
        if (!text.match(/\.(pdf|docx?|txt|md|rtf|odt|jpg|jpeg|png|gif|mp4|mp3|zip|rar|pptx?|xlsx?)$/i)) {
          return text;
        }
      }
    }
    
    // Try to find text after "caption", "with", or "description"
    const captionPatterns = [
      /caption[:\s]+(.+?)(?:\s+post|\s+share|\s+create|$)/i,
      /with\s+caption[:\s]+(.+?)(?:\s+post|\s+share|\s+create|$)/i,
      /description[:\s]+(.+?)(?:\s+post|\s+share|\s+create|$)/i
    ];
    
    for (const pattern of captionPatterns) {
      const match = message.match(pattern);
      if (match && match[1]) {
        const text = match[1].trim();
        // Remove common trailing words
        const cleaned = text.replace(/\s+(post|share|create|to|social|media|feed)$/i, '').trim();
        if (cleaned.length > 0 && cleaned.length < 500) {
          return cleaned;
        }
      }
    }
    
    return null;
  }
  
  /**
   * Execute post to social feed action
   */
  async postToSocial(message, userId) {
    const fileNames = this.extractFileNames(message);
    
    if (!fileNames || fileNames.length === 0) {
      return {
        success: false,
        message: "I need a file name to post. Please specify which file you want to post, for example: 'Post file.pdf to social media with caption \"My caption\"'"
      };
    }
    
    const files = await this.findFilesByName(fileNames, userId);
    
    if (files.length === 0) {
      return {
        success: false,
        message: `Could not find file(s): ${fileNames.join(', ')}. Please check the file names and try again.`
      };
    }
    
    // Extract caption from message
    const caption = this.extractCaption(message) || '';
    
    // Post each file to social feed
    const postedFiles = [];
    for (const file of files) {
      try {
        const post = new SocialPost({
          owner: userId,
          file: file._id,
          description: caption || '',
          isPublic: true
        });
        
        await post.save();
        await post.populate('file', 'originalName mimeType size');
        postedFiles.push(file.originalName);
      } catch (error) {
        console.error(`[AI Action Executor] Error posting ${file.originalName}:`, error);
      }
    }
    
    if (postedFiles.length === 0) {
      return {
        success: false,
        message: 'Failed to post file(s) to social feed. Please try again.'
      };
    }
    
    return {
      success: true,
      message: `✅ Successfully posted ${postedFiles.length} file(s) to your social feed${caption ? ` with caption "${caption}"` : ''}: ${postedFiles.join(', ')}.`,
      data: {
        postedFiles: postedFiles,
        caption: caption
      }
    };
  }
  
  /**
   * Execute star file action
   */
  async starFile(message, userId) {
    const fileNames = this.extractFileNames(message);
    
    if (!fileNames || fileNames.length === 0) {
      return {
        success: false,
        message: "I need a file name to star. Please specify which file you want to star."
      };
    }
    
    const files = await this.findFilesByName(fileNames, userId);
    
    if (files.length === 0) {
      return {
        success: false,
        message: `Could not find file(s): ${fileNames.join(', ')}. Please check the file names and try again.`
      };
    }
    
    // Star files
    const starredFiles = [];
    for (const file of files) {
      file.isStarred = true;
      await file.save();
      starredFiles.push(file.originalName);
    }
    
    return {
      success: true,
      message: `✅ Successfully starred ${starredFiles.length} file(s): ${starredFiles.join(', ')}.`,
      data: {
        starredFiles: starredFiles
      }
    };
  }
  
  /**
   * Execute share file action
   */
  async shareFile(message, userId) {
    const fileNames = this.extractFileNames(message);
    
    if (!fileNames || fileNames.length === 0) {
      return {
        success: false,
        message: "I need a file name to share. Please specify which file you want to share."
      };
    }
    
    const files = await this.findFilesByName(fileNames, userId);
    
    if (files.length === 0) {
      return {
        success: false,
        message: `Could not find file(s): ${fileNames.join(', ')}. Please check the file names and try again.`
      };
    }
    
    // Extract user to share with (if mentioned)
    const userMatch = message.match(/with\s+([a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/i) ||
                     message.match(/to\s+([a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/i);
    
    if (userMatch) {
      // Share with specific user
      const userEmail = userMatch[1];
      const userToShare = await User.findOne({ email: userEmail });
      
      if (!userToShare) {
        return {
          success: false,
          message: `User with email ${userEmail} not found.`
        };
      }
      
      const sharedFiles = [];
      for (const file of files) {
        const alreadyShared = file.sharedWith.find(
          s => s.user.toString() === userToShare._id.toString()
        );
        
        if (!alreadyShared) {
          file.sharedWith.push({
            user: userToShare._id,
            permission: 'view'
          });
          await file.save();
        }
        sharedFiles.push(file.originalName);
      }
      
      return {
        success: true,
        message: `✅ Successfully shared ${sharedFiles.length} file(s) with ${userEmail}: ${sharedFiles.join(', ')}.`,
        data: {
          sharedFiles: sharedFiles,
          sharedWith: userEmail
        }
      };
    } else {
      // Create share link
      const sharedLinks = [];
      
      for (const file of files) {
        const share = new Share({
          file: file._id,
          owner: userId,
          accessType: 'view'
        });
        await share.save();
        sharedLinks.push({
          fileName: file.originalName,
          shareId: share.shareId
        });
      }
      
      return {
        success: true,
        message: `✅ Successfully created share links for ${sharedLinks.length} file(s): ${sharedLinks.map(s => s.fileName).join(', ')}.`,
        data: {
          sharedFiles: sharedLinks.map(s => s.fileName),
          shareLinks: sharedLinks
        }
      };
    }
  }
  
  /**
   * Execute move file action
   */
  async moveFile(message, userId) {
    const fileNames = this.extractFileNames(message);
    
    if (!fileNames || fileNames.length === 0) {
      return {
        success: false,
        message: "I need a file name to move. Please specify which file you want to move and where."
      };
    }
    
    const files = await this.findFilesByName(fileNames, userId);
    
    if (files.length === 0) {
      return {
        success: false,
        message: `Could not find file(s): ${fileNames.join(', ')}. Please check the file names and try again.`
      };
    }
    
    // Extract folder name from message
    const folderMatch = message.match(/(?:to|into|in)\s+["']?([a-zA-Z0-9._\s-]+)["']?/i) ||
                       message.match(/folder\s+["']?([a-zA-Z0-9._\s-]+)["']?/i);
    
    if (!folderMatch) {
      return {
        success: false,
        message: "I need a folder name to move the file to. Please specify the destination folder, for example: 'Move file.pdf to folder Documents'"
      };
    }
    
    const folderName = folderMatch[1].trim();
    const folder = await Folder.findOne({
      name: folderName,
      owner: userId,
      isTrashed: { $ne: true }
    });
    
    if (!folder) {
      return {
        success: false,
        message: `Folder "${folderName}" not found. Please check the folder name and try again.`
      };
    }
    
    // Move files
    const movedFiles = [];
    for (const file of files) {
      file.parentFolder = folder._id;
      await file.save();
      movedFiles.push(file.originalName);
    }
    
    return {
      success: true,
      message: `✅ Successfully moved ${movedFiles.length} file(s) to folder "${folderName}": ${movedFiles.join(', ')}.`,
      data: {
        movedFiles: movedFiles,
        targetFolder: folderName
      }
    };
  }
  
  /**
   * Execute rename file action
   */
  async renameFile(message, userId) {
    const fileNames = this.extractFileNames(message);
    
    if (!fileNames || fileNames.length === 0) {
      return {
        success: false,
        message: "I need a file name to rename. Please specify which file you want to rename and the new name."
      };
    }
    
    const files = await this.findFilesByName(fileNames, userId);
    
    if (files.length === 0) {
      return {
        success: false,
        message: `Could not find file(s): ${fileNames.join(', ')}. Please check the file names and try again.`
      };
    }
    
    // Extract new name from message
    const newNameMatch = message.match(/(?:to|as|named|call)\s+["']?([a-zA-Z0-9._\s-]+\.(?:pdf|docx?|txt|md|rtf|odt|jpg|jpeg|png|gif|mp4|mp3|zip|rar|pptx?|xlsx?))["']?/i) ||
                        message.match(/(?:to|as|named|call)\s+["']?([a-zA-Z0-9._\s-]+)["']?/i);
    
    if (!newNameMatch) {
      return {
        success: false,
        message: "I need a new name for the file. Please specify the new name, for example: 'Rename file.pdf to newfile.pdf'"
      };
    }
    
    const newName = newNameMatch[1].trim();
    
    // Rename file (only first file if multiple)
    const file = files[0];
    const oldName = file.originalName;
    file.originalName = newName;
    await file.save();
    
    return {
      success: true,
      message: `✅ Successfully renamed "${oldName}" to "${newName}".`,
      data: {
        oldName: oldName,
        newName: newName
      }
    };
  }
  
  /**
   * Execute action based on parsed intent
   */
  async executeAction(action, message, userId) {
    try {
      switch (action.type) {
        case 'create_relationship':
          return await this.createRelationship(message, userId);
        
        case 'delete_file':
          return await this.deleteFile(message, userId);
        
        case 'create_folder':
          return await this.createFolder(message, userId);
        
        case 'post_to_social':
          return await this.postToSocial(message, userId);
        
        case 'star_file':
          return await this.starFile(message, userId);
        
        case 'share_file':
          return await this.shareFile(message, userId);
        
        case 'move_file':
          return await this.moveFile(message, userId);
        
        case 'rename_file':
          return await this.renameFile(message, userId);
        
        default:
          return {
            success: false,
            message: `Action type "${action.type}" is not yet supported.`
          };
      }
    } catch (error) {
      console.error('[AI Action Executor] Error executing action:', error);
      return {
        success: false,
        message: `An error occurred while executing the action: ${error.message}`
      };
    }
  }
}

module.exports = new AIActionExecutor();

