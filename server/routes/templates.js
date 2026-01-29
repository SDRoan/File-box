const express = require('express');
const router = express.Router();
const auth = require('../middleware/auth');
const Template = require('../models/Template');
const File = require('../models/File');
const Folder = require('../models/Folder');
const User = require('../models/User');
const fs = require('fs-extra');
const path = require('path');
const docx = require('docx');

// Get all templates (public + user's private templates)
router.get('/', auth, async (req, res) => {
  try {
    const { category, search, tags } = req.query;
    const query = {
      $or: [
        { isPublic: true },
        { createdBy: req.user._id }
      ]
    };

    if (category) {
      query.category = category;
    }

    if (search) {
      query.$or = [
        { name: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } },
        { tags: { $in: [new RegExp(search, 'i')] } }
      ];
    }

    if (tags) {
      const tagArray = Array.isArray(tags) ? tags : [tags];
      query.tags = { $in: tagArray };
    }

    const templates = await Template.find(query)
      .populate('createdBy', 'name email')
      .sort({ usageCount: -1, createdAt: -1 });

    res.json(templates);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Get template by ID
router.get('/:id', auth, async (req, res) => {
  try {
    const template = await Template.findById(req.params.id)
      .populate('createdBy', 'name email');

    if (!template) {
      return res.status(404).json({ message: 'Template not found' });
    }

    // Check if user has access
    if (!template.isPublic && template.createdBy?._id?.toString() !== req.user._id.toString()) {
      return res.status(403).json({ message: 'Access denied' });
    }

    res.json(template);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Create template from existing file
router.post('/create-from-file/:fileId', auth, async (req, res) => {
  try {
    const { name, description, category, tags, isPublic } = req.body;
    const file = await File.findById(req.params.fileId);

    if (!file || file.owner.toString() !== req.user._id.toString()) {
      return res.status(404).json({ message: 'File not found' });
    }

    // Read file content
    let content = '';
    if (file.mimeType.includes('text') || file.mimeType.includes('document')) {
      content = await fs.readFile(file.path, 'utf-8');
    }

    const template = new Template({
      name: name || file.originalName,
      description: description || '',
      category: category || 'other',
      tags: tags || [],
      content: content,
      filePath: file.path,
      mimeType: file.mimeType,
      isPublic: isPublic !== undefined ? isPublic : false,
      createdBy: req.user._id
    });

    await template.save();
    res.json(template);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Create new template
router.post('/', auth, async (req, res) => {
  try {
    const { name, description, category, content, tags, isPublic, mimeType } = req.body;

    if (!name) {
      return res.status(400).json({ message: 'Template name is required' });
    }

    const template = new Template({
      name,
      description: description || '',
      category: category || 'other',
      content: content || '',
      tags: tags || [],
      isPublic: isPublic !== undefined ? isPublic : false,
      mimeType: mimeType || 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      createdBy: req.user._id
    });

    await template.save();
    res.json(template);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Use template to create a new file
router.post('/:id/use', auth, async (req, res) => {
  try {
    const { fileName, parentFolder } = req.body;
    const template = await Template.findById(req.params.id);

    if (!template) {
      return res.status(404).json({ message: 'Template not found' });
    }

    // Check if user has access
    if (!template.isPublic && template.createdBy?.toString() !== req.user._id.toString()) {
      return res.status(403).json({ message: 'Access denied' });
    }

    const user = await User.findById(req.user._id);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Create file from template
    const uploadsDir = path.join(__dirname, '..', 'uploads', req.user._id.toString());
    await fs.ensureDir(uploadsDir);

    let filePath;
    let fileSize;
    let finalMimeType = template.mimeType;

    if (template.content) {
      // Create file from template content
      if (template.mimeType.includes('word') || template.mimeType.includes('document')) {
        // Create DOCX file
        const paragraphs = template.content.split('\n').map((line) =>
          new docx.Paragraph({
            children: [new docx.TextRun(line || ' ')],
          })
        );

        const doc = new docx.Document({
          sections: [{
            properties: {},
            children: paragraphs,
          }],
        });

        const buffer = await docx.Packer.toBuffer(doc);
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        filePath = path.join(uploadsDir, `${uniqueSuffix}.docx`);
        await fs.writeFile(filePath, buffer);
        fileSize = buffer.length;
        finalMimeType = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document';
      } else {
        // Create text file
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        filePath = path.join(uploadsDir, `${uniqueSuffix}.txt`);
        await fs.writeFile(filePath, template.content);
        fileSize = Buffer.byteLength(template.content, 'utf-8');
        finalMimeType = 'text/plain';
      }
    } else if (template.filePath && await fs.pathExists(template.filePath)) {
      // Copy template file
      const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
      const ext = path.extname(template.filePath);
      filePath = path.join(uploadsDir, `${uniqueSuffix}${ext}`);
      await fs.copy(template.filePath, filePath);
      const stats = await fs.stat(filePath);
      fileSize = stats.size;
    } else {
      return res.status(400).json({ message: 'Template has no content or file' });
    }

    // Check storage limit
    if (user.storageUsed + fileSize > user.storageLimit) {
      await fs.remove(filePath);
      return res.status(400).json({ message: 'Storage limit exceeded' });
    }

    // Create file record
    const finalFileName = fileName || `${template.name} - Copy`;
    const file = new File({
      name: path.basename(filePath),
      originalName: finalFileName,
      path: filePath,
      size: fileSize,
      mimeType: finalMimeType,
      owner: req.user._id,
      parentFolder: parentFolder && parentFolder !== 'root' ? parentFolder : null
    });

    await file.save();
    user.storageUsed += fileSize;
    await user.save();

    // Update template usage count
    template.usageCount += 1;
    await template.save();

    // Extract text immediately for DOCX files (don't wait for background)
    if (finalMimeType.includes('word') || finalMimeType.includes('document')) {
      try {
        const textExtractor = require('../services/textExtractor');
        const FileContent = require('../models/FileContent');
        
        console.log(`[Template] Extracting text immediately for file: ${file.originalName}`);
        const extractedText = await textExtractor.extractText(filePath, finalMimeType);
        
        if (extractedText && extractedText.trim().length > 0) {
          const fileContent = new FileContent({
            file: file._id,
            extractedText: extractedText.trim(),
            extractionStatus: 'completed'
          });
          await fileContent.save();
          console.log(`[Template] ✅ Text extraction completed for ${file.originalName} (${extractedText.length} chars)`);
        } else {
          console.warn(`[Template] ⚠️ Text extraction returned empty for ${file.originalName}`);
        }
      } catch (extractError) {
        console.error(`[Template] ⚠️ Text extraction failed:`, extractError.message);
        // Don't fail the request if extraction fails - file is still created
      }
    }

    res.json(file);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Update template
router.put('/:id', auth, async (req, res) => {
  try {
    const template = await Template.findById(req.params.id);

    if (!template) {
      return res.status(404).json({ message: 'Template not found' });
    }

    // Check ownership
    if (template.createdBy?.toString() !== req.user._id.toString()) {
      return res.status(403).json({ message: 'Access denied' });
    }

    const { name, description, category, content, tags, isPublic } = req.body;
    if (name) template.name = name;
    if (description !== undefined) template.description = description;
    if (category) template.category = category;
    if (content !== undefined) template.content = content;
    if (tags) template.tags = tags;
    if (isPublic !== undefined) template.isPublic = isPublic;
    template.updatedAt = new Date();

    await template.save();
    res.json(template);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Rate template
router.post('/:id/rate', auth, async (req, res) => {
  try {
    const { rating } = req.body;
    if (!rating || rating < 1 || rating > 5) {
      return res.status(400).json({ message: 'Rating must be between 1 and 5' });
    }

    const template = await Template.findById(req.params.id);
    if (!template) {
      return res.status(404).json({ message: 'Template not found' });
    }

    // Update rating
    const currentTotal = template.rating * template.ratingCount;
    template.ratingCount += 1;
    template.rating = (currentTotal + rating) / template.ratingCount;

    await template.save();
    res.json({ rating: template.rating, ratingCount: template.ratingCount });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Delete template
router.delete('/:id', auth, async (req, res) => {
  try {
    const template = await Template.findById(req.params.id);

    if (!template) {
      return res.status(404).json({ message: 'Template not found' });
    }

    // Check ownership
    if (template.createdBy?.toString() !== req.user._id.toString()) {
      return res.status(403).json({ message: 'Access denied' });
    }

    await template.deleteOne();
    res.json({ message: 'Template deleted' });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

module.exports = router;

