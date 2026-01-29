const FileOrganizationPattern = require('../models/FileOrganizationPattern');
const File = require('../models/File');
const Folder = require('../models/Folder');
const axios = require('axios');

/**
 * Analyze file movement patterns and generate AI-powered organization suggestions
 */
class PredictiveOrganizationService {
  /**
   * Record a file movement pattern
   */
  async recordPattern(userId, file, sourceFolderId, destinationFolderId, context = {}) {
    try {
      const fileExtension = file.originalName.split('.').pop()?.toLowerCase() || '';
      const now = new Date();
      const dayOfWeek = now.getDay();
      const hour = now.getHours();

      // Determine pattern type
      let patternType = 'file_type_to_folder';
      if (context.projectContext) {
        patternType = 'project_based';
      } else if (sourceFolderId) {
        patternType = 'source_folder_to_destination';
      }

      // Check if similar pattern exists
      const existingPattern = await FileOrganizationPattern.findOne({
        user: userId,
        patternType,
        'trigger.fileType': file.mimeType,
        'trigger.fileExtension': fileExtension,
        'trigger.sourceFolder': sourceFolderId || null,
        destinationFolder: destinationFolderId,
        isActive: true
      });

      if (existingPattern) {
        // Update existing pattern
        existingPattern.occurrences += 1;
        existingPattern.lastOccurrence = now;
        
        // Recalculate confidence based on occurrences
        existingPattern.confidence = Math.min(0.95, 0.5 + (existingPattern.occurrences * 0.05));
        
        // Update context
        if (context.actionBefore) {
          existingPattern.context.actionBefore = context.actionBefore;
        }
        
        await existingPattern.save();
        return existingPattern;
      } else {
        // Create new pattern
        const destinationFolder = await Folder.findById(destinationFolderId);
        
        const newPattern = new FileOrganizationPattern({
          user: userId,
          patternType,
          trigger: {
            fileType: file.mimeType,
            fileExtension,
            sourceFolder: sourceFolderId || null,
            projectContext: context.projectContext || null,
            timeOfDay: hour,
            dayOfWeek
          },
          destinationFolder: destinationFolderId,
          destinationFolderName: destinationFolder?.name || 'Unknown',
          confidence: 0.5,
          occurrences: 1,
          lastOccurrence: now,
          context: {
            actionBefore: context.actionBefore || null,
            timeAfterUpload: context.timeAfterUpload || null,
            fileSizeRange: {
              min: file.size,
              max: file.size
            }
          }
        });

        await newPattern.save();
        
        // Generate AI explanation for new pattern
        await this.generateAIExplanation(newPattern);
        
        return newPattern;
      }
    } catch (error) {
      console.error('Error recording pattern:', error);
      throw error;
    }
  }

  /**
   * Generate AI-powered explanation for a pattern
   */
  async generateAIExplanation(pattern) {
    try {
      const openRouterApiKey = process.env.OPENROUTER_API_KEY;
      if (!openRouterApiKey) {
        return; // Skip if no API key
      }

      const destinationFolder = await Folder.findById(pattern.destinationFolder);
      const sourceFolder = pattern.trigger.sourceFolder 
        ? await Folder.findById(pattern.trigger.sourceFolder)
        : null;

      const prompt = `Based on this file organization pattern, generate a natural, conversational explanation:

Pattern Type: ${pattern.patternType}
File Type: ${pattern.trigger.fileType || pattern.trigger.fileExtension || 'various'}
Source: ${sourceFolder ? sourceFolder.name : 'root/anywhere'}
Destination: ${destinationFolder ? destinationFolder.name : 'unknown'}
Occurrences: ${pattern.occurrences} time(s)
Confidence: ${(pattern.confidence * 100).toFixed(0)}%

Generate a friendly, natural explanation like:
- "I noticed you always move PDFs to the 'Documents' folder after reviewing them"
- "You typically organize project files into the 'Projects' folder"
- "Files from 'Downloads' usually end up in 'Archive' folder"

Make it conversational and helpful. Keep it under 100 characters.`;

      const response = await axios.post(
        'https://openrouter.ai/api/v1/chat/completions',
        {
          model: 'openai/gpt-4o-mini',
          messages: [
            {
              role: 'system',
              content: 'You are a helpful assistant that explains file organization patterns in a natural, conversational way.'
            },
            {
              role: 'user',
              content: prompt
            }
          ],
          max_tokens: 150,
          temperature: 0.7
        },
        {
          headers: {
            'Authorization': `Bearer ${openRouterApiKey}`,
            'Content-Type': 'application/json'
          }
        }
      );

      if (response.data && response.data.choices && response.data.choices[0]) {
        pattern.aiExplanation = response.data.choices[0].message.content.trim();
        await pattern.save();
      }
    } catch (error) {
      console.error('Error generating AI explanation:', error);
      // Don't fail if AI explanation fails
    }
  }

  /**
   * Get AI-powered organization suggestions for a file
   */
  async getSuggestions(userId, file, context = {}) {
    try {
      // Find matching patterns
      const fileExtension = file.originalName.split('.').pop()?.toLowerCase() || '';
      const now = new Date();
      const dayOfWeek = now.getDay();
      const hour = now.getHours();

      // Query patterns that match this file
      const matchingPatterns = await FileOrganizationPattern.find({
        user: userId,
        isActive: true,
        $or: [
          { 'trigger.fileType': file.mimeType },
          { 'trigger.fileExtension': fileExtension },
          { 'trigger.sourceFolder': file.parentFolder || null },
          { 'trigger.fileNamePattern': { $exists: false } } // Will be checked separately
        ]
      })
      .populate('destinationFolder', 'name')
      .sort({ confidence: -1, occurrences: -1 })
      .limit(10);

      if (matchingPatterns.length === 0) {
        return [];
      }

      // Use AI to analyze and rank suggestions
      const suggestions = await this.generateAISuggestions(
        file,
        matchingPatterns,
        context
      );

      return suggestions;
    } catch (error) {
      console.error('Error getting suggestions:', error);
      return [];
    }
  }

  /**
   * Use AI to generate and rank organization suggestions
   */
  async generateAISuggestions(file, patterns, context) {
    try {
      const openRouterApiKey = process.env.OPENROUTER_API_KEY;
      if (!openRouterApiKey) {
        // Fallback: return patterns sorted by confidence
        return patterns.map(p => ({
          patternId: p._id,
          destinationFolder: p.destinationFolder,
          destinationFolderName: p.destinationFolderName,
          confidence: p.confidence,
          explanation: p.aiExplanation || `Move to ${p.destinationFolderName}`,
          occurrences: p.occurrences
        }));
      }

      // Prepare pattern data for AI
      const patternData = patterns.map(p => ({
        id: p._id.toString(),
        type: p.patternType,
        fileType: p.trigger.fileType || p.trigger.fileExtension,
        sourceFolder: p.trigger.sourceFolder?.toString() || 'root',
        destinationFolder: p.destinationFolder.name,
        confidence: p.confidence,
        occurrences: p.occurrences,
        explanation: p.aiExplanation || '',
        lastSeen: p.lastOccurrence
      }));

      const prompt = `Analyze these file organization patterns and suggest the best destination folder for this file:

File: ${file.originalName}
File Type: ${file.mimeType}
Current Location: ${file.parentFolder ? 'in a folder' : 'root'}
File Size: ${(file.size / 1024 / 1024).toFixed(2)} MB
Context: ${context.actionBefore || 'uploaded'}

Patterns Found:
${JSON.stringify(patternData, null, 2)}

Analyze which pattern best matches this file and generate suggestions. Consider:
1. Pattern confidence and frequency
2. File type matching
3. Context relevance
4. Recency of pattern

Return a JSON array of suggestions, each with:
- patternId: the pattern ID
- destinationFolderName: folder name
- confidence: 0-1 score
- explanation: natural language explanation (like "I noticed you always move PDFs here after reviewing them")
- reason: why this suggestion is relevant

Return ONLY valid JSON, no other text. Example format:
[
  {
    "patternId": "...",
    "destinationFolderName": "Documents",
    "confidence": 0.85,
    "explanation": "I noticed you always move PDFs to Documents after reviewing them",
    "reason": "High pattern match (8 occurrences, 85% confidence)"
  }
]`;

      const response = await axios.post(
        'https://openrouter.ai/api/v1/chat/completions',
        {
          model: 'openai/gpt-4o-mini',
          messages: [
            {
              role: 'system',
              content: 'You are an AI assistant that analyzes file organization patterns and suggests where files should be moved. Always return valid JSON only.'
            },
            {
              role: 'user',
              content: prompt
            }
          ],
          max_tokens: 1000,
          temperature: 0.3 // Lower temperature for more consistent JSON
        },
        {
          headers: {
            'Authorization': `Bearer ${openRouterApiKey}`,
            'Content-Type': 'application/json'
          }
        }
      );

      if (response.data && response.data.choices && response.data.choices[0]) {
        const content = response.data.choices[0].message.content.trim();
        
        // Extract JSON from response (handle markdown code blocks)
        let jsonStr = content;
        if (content.startsWith('```')) {
          jsonStr = content.replace(/```json\n?/g, '').replace(/```\n?/g, '').trim();
        }
        
        const aiSuggestions = JSON.parse(jsonStr);
        
        // Map AI suggestions back to patterns with folder objects
        const suggestions = aiSuggestions.map(aiSuggestion => {
          const pattern = patterns.find(p => p._id.toString() === aiSuggestion.patternId);
          if (!pattern) return null;
          
          return {
            patternId: pattern._id,
            destinationFolder: pattern.destinationFolder._id,
            destinationFolderName: aiSuggestion.destinationFolderName || pattern.destinationFolderName,
            confidence: aiSuggestion.confidence || pattern.confidence,
            explanation: aiSuggestion.explanation || pattern.aiExplanation || `Move to ${pattern.destinationFolderName}`,
            reason: aiSuggestion.reason || `${pattern.occurrences} occurrences`,
            occurrences: pattern.occurrences
          };
        }).filter(s => s !== null);

        return suggestions;
      }
    } catch (error) {
      console.error('Error generating AI suggestions:', error);
      // Fallback to pattern-based suggestions
      return patterns.map(p => ({
        patternId: p._id,
        destinationFolder: p.destinationFolder._id,
        destinationFolderName: p.destinationFolderName,
        confidence: p.confidence,
        explanation: p.aiExplanation || `Move to ${p.destinationFolderName}`,
        occurrences: p.occurrences
      }));
    }
  }

  /**
   * Record user feedback on a suggestion
   */
  async recordFeedback(userId, patternId, action) {
    try {
      const pattern = await FileOrganizationPattern.findOne({
        _id: patternId,
        user: userId
      });

      if (!pattern) {
        throw new Error('Pattern not found');
      }

      pattern.userFeedback.push({
        action,
        timestamp: new Date()
      });

      // Adjust confidence based on feedback
      if (action === 'accepted') {
        pattern.confidence = Math.min(0.95, pattern.confidence + 0.1);
      } else if (action === 'rejected') {
        pattern.confidence = Math.max(0.1, pattern.confidence - 0.2);
        // Deactivate if confidence drops too low
        if (pattern.confidence < 0.3) {
          pattern.isActive = false;
        }
      }

      await pattern.save();
      return pattern;
    } catch (error) {
      console.error('Error recording feedback:', error);
      throw error;
    }
  }

  /**
   * Get all active patterns for a user
   */
  async getUserPatterns(userId) {
    try {
      return await FileOrganizationPattern.find({
        user: userId,
        isActive: true
      })
      .populate('destinationFolder', 'name')
      .populate('trigger.sourceFolder', 'name')
      .sort({ confidence: -1, occurrences: -1 });
    } catch (error) {
      console.error('Error getting user patterns:', error);
      return [];
    }
  }
}

module.exports = new PredictiveOrganizationService();

