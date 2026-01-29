const mongoose = require('mongoose');
require('dotenv').config();
const LearningResource = require('../models/LearningResource');

const sampleResources = [
  {
    title: 'Getting Started with File Box',
    description: 'Learn the basics of File Box - how to upload files, create folders, and organize your documents.',
    type: 'tutorial',
    category: 'getting-started',
    content: `
      <h2>Welcome to File Box!</h2>
      <p>File Box is your personal cloud storage solution. Here's how to get started:</p>
      
      <h3>1. Upload Files</h3>
      <p>Click the "Upload" button to add files to your storage. You can upload multiple files at once.</p>
      
      <h3>2. Create Folders</h3>
      <p>Organize your files by creating folders. Click "New Folder" and give it a name.</p>
      
      <h3>3. Navigate</h3>
      <p>Click on folders to open them and see their contents. Use the back button to go up one level.</p>
      
      <h3>4. Manage Files</h3>
      <p>Use the action buttons to download, star, share, or delete files.</p>
    `,
    tags: ['basics', 'upload', 'folders', 'getting-started'],
    difficulty: 'beginner',
    duration: 5,
    isPublished: true,
  },
  {
    title: 'Sharing Files with Others',
    description: 'Discover how to share files and folders with other users or create shareable links.',
    type: 'guide',
    category: 'sharing',
    content: `
      <h2>Sharing Files</h2>
      <p>File Box makes it easy to share your files with others.</p>
      
      <h3>Share with Users</h3>
      <p>Click the share button on any file or folder, then search for users by email to share with them directly.</p>
      
      <h3>Create Share Links</h3>
      <p>Generate a shareable link that anyone with the link can access. You can set permissions (view or edit) and expiration dates.</p>
      
      <h3>Manage Shared Files</h3>
      <p>View all files shared with you in the "Shared" section of the sidebar.</p>
    `,
    tags: ['sharing', 'collaboration', 'links'],
    difficulty: 'beginner',
    duration: 8,
    isPublished: true,
  },
  {
    title: 'Smart Organization Features',
    description: 'Learn how to use AI-powered smart organization to automatically organize your files.',
    type: 'guide',
    category: 'file-management',
    content: `
      <h2>Smart Organization</h2>
      <p>File Box uses AI to help organize your files automatically.</p>
      
      <h3>How It Works</h3>
      <p>The smart organization feature analyzes your files and suggests where they should be organized based on their content and type.</p>
      
      <h3>Using Suggestions</h3>
      <p>When you see organization suggestions, you can accept them to automatically move files to suggested folders.</p>
      
      <h3>Custom Rules</h3>
      <p>Create custom organization rules based on file types, names, or content patterns.</p>
    `,
    tags: ['ai', 'organization', 'smart', 'automation'],
    difficulty: 'intermediate',
    duration: 12,
    isPublished: true,
  },
  {
    title: 'Security Best Practices',
    description: 'Essential security tips to keep your files safe and secure in File Box.',
    type: 'article',
    category: 'security',
    content: `
      <h2>Security Best Practices</h2>
      <p>Protect your files with these security recommendations:</p>
      
      <h3>1. Strong Passwords</h3>
      <p>Use a strong, unique password for your File Box account. Consider using a password manager.</p>
      
      <h3>2. Two-Factor Authentication</h3>
      <p>Enable two-factor authentication for an extra layer of security.</p>
      
      <h3>3. Share Links Carefully</h3>
      <p>Be cautious when sharing files via links. Set expiration dates and use passwords for sensitive files.</p>
      
      <h3>4. Regular Backups</h3>
      <p>Use the Cloud Backup feature to keep copies of important files.</p>
      
      <h3>5. Review Shared Access</h3>
      <p>Regularly review who has access to your shared files and remove access when no longer needed.</p>
    `,
    tags: ['security', 'password', 'privacy', 'best-practices'],
    difficulty: 'beginner',
    duration: 10,
    isPublished: true,
  },
  {
    title: 'Collaboration with Team Folders',
    description: 'Work together with your team using shared team folders and collaboration features.',
    type: 'tutorial',
    category: 'collaboration',
    content: `
      <h2>Team Collaboration</h2>
      <p>File Box makes team collaboration easy with Team Folders.</p>
      
      <h3>Creating Team Folders</h3>
      <p>Create a team folder and invite team members to collaborate on shared files.</p>
      
      <h3>Permissions</h3>
      <p>Set different permission levels for team members - view only, edit, or admin access.</p>
      
      <h3>Real-time Updates</h3>
      <p>See changes made by team members in real-time. No need to refresh the page.</p>
      
      <h3>Activity Tracking</h3>
      <p>Track who made what changes and when in the activity log.</p>
    `,
    tags: ['team', 'collaboration', 'folders', 'permissions'],
    difficulty: 'intermediate',
    duration: 15,
    isPublished: true,
  },
  {
    title: 'File Box API Documentation',
    description: 'Complete API reference for developers who want to integrate File Box into their applications.',
    type: 'documentation',
    category: 'api',
    externalUrl: 'https://api.filebox.example.com/docs',
    tags: ['api', 'developer', 'integration', 'rest'],
    difficulty: 'advanced',
    duration: 30,
    isPublished: true,
  },
  {
    title: 'Frequently Asked Questions',
    description: 'Common questions and answers about File Box features and usage.',
    type: 'faq',
    category: 'getting-started',
    content: `
      <h2>Frequently Asked Questions</h2>
      
      <h3>What file types are supported?</h3>
      <p>File Box supports all file types. There are no restrictions on file formats.</p>
      
      <h3>What is the storage limit?</h3>
      <p>Free accounts get 10GB of storage. Premium plans offer more storage options.</p>
      
      <h3>Can I access my files offline?</h3>
      <p>Files are stored in the cloud, but you can download them for offline access.</p>
      
      <h3>How do I recover deleted files?</h3>
      <p>Deleted files go to the Trash folder and can be restored within 30 days.</p>
      
      <h3>Is my data encrypted?</h3>
      <p>Yes, File Box uses encryption to protect your files both in transit and at rest.</p>
    `,
    tags: ['faq', 'help', 'questions'],
    difficulty: 'beginner',
    duration: 5,
    isPublished: true,
  },
];

async function seedResources() {
  try {
    // Connect to MongoDB
    const mongoUri = process.env.MONGODB_URI || 'mongodb://localhost:27017/dropbox-clone';
    await mongoose.connect(mongoUri);
    console.log('Connected to MongoDB');

    // Clear existing resources (optional - comment out if you want to keep existing)
    // await LearningResource.deleteMany({});
    // console.log('Cleared existing resources');

    // Insert sample resources
    const inserted = await LearningResource.insertMany(sampleResources);
    console.log(`✅ Successfully seeded ${inserted.length} learning resources!`);

    // Display what was created
    console.log('\nCreated resources:');
    inserted.forEach((resource, index) => {
      console.log(`${index + 1}. ${resource.title} (${resource.type})`);
    });

    process.exit(0);
  } catch (error) {
    console.error('Error seeding resources:', error);
    process.exit(1);
  }
}

seedResources();
