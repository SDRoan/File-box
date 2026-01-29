const mongoose = require('mongoose');
const aiResourceGenerator = require('../services/aiResourceGenerator');
const LearningResource = require('../models/LearningResource');
require('dotenv').config();

async function generateAndSaveResources() {
  try {
    // Connect to MongoDB
    const mongoUri = process.env.MONGODB_URI || 'mongodb://localhost:27017/dropbox-clone';
    await mongoose.connect(mongoUri);
    console.log('Connected to MongoDB');

    // Generate new AI resources using configured count
    const config = require('../config/aiConfig');
    const resourceCount = config.learningResources.count;
    
    console.log(`Generating ${resourceCount} AI learning resources...`);
    const newResources = await aiResourceGenerator.generateMultipleResources(resourceCount);
    console.log(`Generated ${newResources.length} resources`);

    // Delete old resources
    await LearningResource.deleteMany({});
    console.log('Cleared old resources');

    // Insert new resources
    const inserted = await LearningResource.insertMany(newResources);
    console.log(`✅ Successfully created ${inserted.length} AI-generated learning resources!`);

    // Display what was created
    console.log('\nCreated resources:');
    inserted.forEach((resource, index) => {
      console.log(`${index + 1}. ${resource.title} (${resource.type}, ${resource.difficulty})`);
    });

    process.exit(0);
  } catch (error) {
    console.error('Error generating resources:', error);
    process.exit(1);
  }
}

generateAndSaveResources();
