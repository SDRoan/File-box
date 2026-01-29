const axios = require('axios');
const { HfInference } = require('@huggingface/inference');
const config = require('../config/aiConfig');

// Initialize Hugging Face (free tier)
const hf = config.huggingface.apiKey 
  ? new HfInference(config.huggingface.apiKey)
  : new HfInference(); // Works without API key for free inference

// Helper function to call OpenRouter API with free models
async function callOpenRouter(messages, maxTokens = 2000, temperature = 0.7) {
  const openRouterApiKey = process.env.OPENROUTER_API_KEY;
  
  if (!openRouterApiKey) {
    throw new Error('OpenRouter API key not configured');
  }

  // Use configured model for text generation
  const model = config.learningResources.openRouterModel;

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
        'X-Title': 'File Box Learning Resources',
        'Content-Type': 'application/json'
      }
    }
  );

  return response.data.choices[0]?.message?.content || '';
}

// Helper function to use Hugging Face text generation (fallback)
async function callHuggingFace(prompt, maxLength = 500) {
  try {
    // Use a free text generation model
    const model = 'gpt2'; // Free model
    
    const response = await hf.textGeneration({
      model,
      inputs: prompt,
      parameters: {
        max_new_tokens: maxLength,
        return_full_text: false,
        temperature: 0.7,
      }
    });

    return response.generated_text || '';
  } catch (error) {
    console.error('Hugging Face text generation error:', error.message);
    throw error;
  }
}

class AIResourceGenerator {
  /**
   * Generate detailed tutorial content
   */
  generateTutorialContent(topic, category, difficulty, isFileManagement, isSharing, isSecurity) {
    const examples = this.getTopicExamples(topic, category, isFileManagement, isSharing, isSecurity);
    
    return `<h2>Introduction to ${topic}</h2>
<p>Welcome to this comprehensive tutorial on ${topic} in File Box. ${topic} is an essential feature that helps you ${this.getTopicPurpose(topic, category)}. Whether you're a beginner or looking to enhance your skills, this guide will walk you through everything you need to know.</p>

<h3>What You'll Learn</h3>
<p>By the end of this tutorial, you'll be able to:</p>
<ul>
  <li>Understand the core concepts and benefits of ${topic}</li>
  <li>${examples.step1 || 'Navigate the interface and locate relevant features'}</li>
  <li>${examples.step2 || 'Apply best practices in your daily workflow'}</li>
  <li>${examples.step3 || 'Troubleshoot common issues effectively'}</li>
</ul>

<h3>Getting Started</h3>
<p>To begin working with ${topic}, you'll need a File Box account. Once logged in, navigate to the ${this.getCategoryLocation(category)} section. ${examples.gettingStarted || 'Look for the main feature icon in the sidebar or use the search bar to locate it quickly.'}</p>

<h3>Step-by-Step Instructions</h3>
<p>Follow these detailed steps to master ${topic}:</p>
<ol>
  <li><strong>Access the Feature:</strong> ${examples.access || 'Click on the feature name in the sidebar or use the search functionality to find it.'}</li>
  <li><strong>Understand the Interface:</strong> ${examples.interface || 'Familiarize yourself with the main controls, buttons, and options available in the feature.'}</li>
  <li><strong>Perform Basic Actions:</strong> ${examples.basicAction || 'Start with simple operations to get comfortable with the feature.'}</li>
  <li><strong>Explore Advanced Options:</strong> ${examples.advanced || 'Once comfortable, explore advanced settings and customization options.'}</li>
</ol>

<h3>Real-World Examples</h3>
<p>Here are practical scenarios where ${topic} proves invaluable:</p>
<ul>
  <li><strong>Example 1:</strong> ${examples.example1 || 'A common use case where this feature saves time and improves efficiency.'}</li>
  <li><strong>Example 2:</strong> ${examples.example2 || 'Another scenario demonstrating the practical benefits of using this feature.'}</li>
  <li><strong>Example 3:</strong> ${examples.example3 || 'An advanced use case for power users who want to maximize productivity.'}</li>
</ul>

<h3>Best Practices and Tips</h3>
<p>To get the most out of ${topic}, follow these recommendations:</p>
<ul>
  <li>${examples.tip1 || 'Organize your content systematically to maintain clarity and efficiency.'}</li>
  <li>${examples.tip2 || 'Regularly review and update your settings to match your evolving needs.'}</li>
  <li>${examples.tip3 || 'Take advantage of keyboard shortcuts to speed up your workflow.'}</li>
  <li>${examples.tip4 || 'Backup important configurations to avoid losing customizations.'}</li>
</ul>

<h3>Common Issues and Solutions</h3>
<p>If you encounter problems, try these troubleshooting steps:</p>
<ul>
  <li><strong>Issue:</strong> Feature not responding. <strong>Solution:</strong> Refresh the page and check your internet connection.</li>
  <li><strong>Issue:</strong> Changes not saving. <strong>Solution:</strong> Ensure you have proper permissions and sufficient storage space.</li>
  <li><strong>Issue:</strong> Performance is slow. <strong>Solution:</strong> Clear your browser cache and close unnecessary tabs.</li>
</ul>

<h3>Next Steps</h3>
<p>Now that you understand ${topic}, consider exploring related features like ${this.getRelatedFeatures(category)}. Continue practicing with your own files and projects to become proficient.</p>

<h3>Conclusion</h3>
<p>You now have a solid understanding of ${topic} in File Box. This feature is designed to ${this.getTopicPurpose(topic, category)}, and with regular use, you'll discover even more ways it can enhance your file management workflow. Keep exploring and don't hesitate to refer back to this guide whenever needed.</p>`;
  }

  /**
   * Generate detailed guide content
   */
  generateGuideContent(topic, category, difficulty, isFileManagement, isSharing, isSecurity) {
    const examples = this.getTopicExamples(topic, category, isFileManagement, isSharing, isSecurity);
    
    return `<h2>${topic} Guide</h2>
<p>This comprehensive guide provides practical information about ${topic} in File Box. ${topic} is a powerful feature that ${this.getTopicPurpose(topic, category)}. This guide covers everything from basic concepts to advanced techniques.</p>

<h3>Overview and Key Concepts</h3>
<p>${topic} is designed to ${this.getTopicPurpose(topic, category)}. Understanding its core functionality will help you leverage its full potential. The feature integrates seamlessly with other File Box capabilities, creating a cohesive file management experience.</p>

<h3>Key Features and Capabilities</h3>
<p>Here are the main features that make ${topic} valuable:</p>
<ul>
  <li><strong>${examples.feature1 || 'Core Functionality'}:</strong> ${examples.feature1Desc || 'The primary capability that addresses your main needs and improves workflow efficiency.'}</li>
  <li><strong>${examples.feature2 || 'Customization Options'}:</strong> ${examples.feature2Desc || 'Flexible settings that allow you to tailor the feature to your specific requirements.'}</li>
  <li><strong>${examples.feature3 || 'Integration Capabilities'}:</strong> ${examples.feature3Desc || 'Seamless connection with other File Box features for enhanced productivity.'}</li>
</ul>

<h3>How to Use ${topic}</h3>
<p>Follow these instructions to use ${topic} effectively:</p>
<ol>
  <li>${examples.useStep1 || 'Locate the feature in the File Box interface'}</li>
  <li>${examples.useStep2 || 'Configure initial settings according to your preferences'}</li>
  <li>${examples.useStep3 || 'Begin using the feature with your files and folders'}</li>
  <li>${examples.useStep4 || 'Monitor results and adjust settings as needed'}</li>
</ol>

<h3>Practical Applications</h3>
<p>${topic} is particularly useful in these scenarios:</p>
<ul>
  <li>${examples.app1 || 'Managing large numbers of files efficiently'}</li>
  <li>${examples.app2 || 'Collaborating with team members on shared projects'}</li>
  <li>${examples.app3 || 'Organizing content for better accessibility and searchability'}</li>
</ul>

<h3>Tips and Tricks</h3>
<p>Maximize your productivity with these advanced tips:</p>
<ul>
  <li>${examples.trick1 || 'Use keyboard shortcuts for faster access to common actions'}</li>
  <li>${examples.trick2 || 'Set up automation rules to streamline repetitive tasks'}</li>
  <li>${examples.trick3 || 'Regularly review and optimize your configuration for best results'}</li>
</ul>

<h3>Conclusion</h3>
<p>${topic} is an essential tool in File Box that can significantly improve your file management experience. By following this guide and practicing regularly, you'll become proficient in using this feature to its full potential.</p>`;
  }

  /**
   * Generate detailed article content
   */
  generateArticleContent(topic, category, difficulty, isFileManagement, isSharing, isSecurity) {
    const examples = this.getTopicExamples(topic, category, isFileManagement, isSharing, isSecurity);
    
    return `<h2>${topic} Explained</h2>
<p>In this in-depth article, we'll explore ${topic} and its importance in File Box. ${topic} represents a fundamental aspect of modern file management, offering users powerful capabilities to ${this.getTopicPurpose(topic, category)}.</p>

<h3>What is ${topic}?</h3>
<p>${topic} is a comprehensive feature in File Box that ${this.getTopicPurpose(topic, category)}. It provides users with ${examples.whatIs || 'advanced tools and capabilities to manage their digital content more effectively'}. Whether you're working individually or as part of a team, ${topic} offers solutions tailored to your needs.</p>

<h3>Core Benefits and Advantages</h3>
<p>Using ${topic} provides several significant advantages:</p>
<ul>
  <li><strong>${examples.benefit1 || 'Improved Organization'}:</strong> ${examples.benefit1Desc || 'Helps you maintain a structured file system, making it easier to locate and manage your content.'}</li>
  <li><strong>${examples.benefit2 || 'Enhanced Productivity'}:</strong> ${examples.benefit2Desc || 'Streamlines workflows and reduces time spent on repetitive tasks, allowing you to focus on important work.'}</li>
  <li><strong>${examples.benefit3 || 'Better Collaboration'}:</strong> ${examples.benefit3Desc || 'Facilitates seamless teamwork by enabling efficient sharing and coordination among team members.'}</li>
  <li><strong>${examples.benefit4 || 'Increased Security'}:</strong> ${examples.benefit4Desc || 'Provides robust protection for your files with advanced security features and access controls.'}</li>
</ul>

<h3>Real-World Use Cases</h3>
<p>Here are common scenarios where ${topic} proves particularly valuable:</p>
<ul>
  <li><strong>${examples.case1 || 'Project Management'}:</strong> ${examples.case1Desc || 'Organize project files, track versions, and collaborate with team members efficiently.'}</li>
  <li><strong>${examples.case2 || 'Content Organization'}:</strong> ${examples.case2Desc || 'Categorize and structure large collections of files for easy retrieval and management.'}</li>
  <li><strong>${examples.case3 || 'Team Collaboration'}:</strong> ${examples.case3Desc || 'Share resources, coordinate work, and maintain consistency across team projects.'}</li>
</ul>

<h3>Implementation and Best Practices</h3>
<p>To effectively implement ${topic} in your workflow:</p>
<ol>
  <li>${examples.impl1 || 'Start with a clear understanding of your organizational needs'}</li>
  <li>${examples.impl2 || 'Configure settings to match your specific requirements'}</li>
  <li>${examples.impl3 || 'Establish consistent naming conventions and organizational patterns'}</li>
  <li>${examples.impl4 || 'Regularly review and optimize your setup for maximum efficiency'}</li>
</ol>

<h3>Conclusion</h3>
<p>${topic} is a valuable feature that can significantly improve your file management experience in File Box. By understanding its capabilities and implementing best practices, you can enhance productivity, improve organization, and achieve better results in your daily work. Explore the feature, experiment with different approaches, and find what works best for your specific needs.</p>`;
  }

  /**
   * Generate detailed FAQ content
   */
  generateFAQContent(topic, category, difficulty, isFileManagement, isSharing, isSecurity) {
    const examples = this.getTopicExamples(topic, category, isFileManagement, isSharing, isSecurity);
    
    return `<h2>Frequently Asked Questions About ${topic}</h2>
<p>This FAQ section addresses common questions and concerns about ${topic} in File Box. Whether you're just getting started or looking to deepen your understanding, you'll find helpful answers here.</p>

<h3>What is ${topic} and how does it work?</h3>
<p>${topic} is a feature in File Box that ${this.getTopicPurpose(topic, category)}. It works by ${examples.howWorks || 'providing intuitive tools and interfaces that allow you to manage your files efficiently'}. The feature is designed to be user-friendly while offering powerful capabilities for both beginners and advanced users.</p>

<h3>How do I get started with ${topic}?</h3>
<p>To get started, ${examples.getStarted || 'navigate to the feature in the File Box sidebar, click on it to open, and follow the on-screen instructions'}. You can also use the search bar to quickly locate the feature. Once opened, you'll see options to configure settings and begin using the feature with your files.</p>

<h3>Is ${topic} available for all File Box users?</h3>
<p>Yes, ${topic} is available to all File Box users. Some advanced features may have additional requirements or be part of premium plans, but the core functionality is accessible to everyone. Check your account settings to see which features are available to you.</p>

<h3>Can I customize ${topic} to fit my needs?</h3>
<p>Absolutely! ${topic} offers several customization options including ${examples.customizations || 'settings for display preferences, notification controls, and workflow configurations'}. You can access these options through the feature's settings menu, allowing you to tailor the experience to your specific requirements.</p>

<h3>What are the main benefits of using ${topic}?</h3>
<p>The main benefits include ${examples.mainBenefits || 'improved file organization, enhanced productivity, better collaboration capabilities, and increased security'}. These advantages help you work more efficiently and maintain better control over your digital content.</p>

<h3>Are there any limitations or restrictions?</h3>
<p>${topic} is designed to be flexible, but there may be some limitations based on your account type or storage plan. Common considerations include ${examples.limitations || 'file size limits, storage quotas, and access permissions'}. Check your account details for specific information about your plan's capabilities.</p>

<h3>How can I troubleshoot common issues?</h3>
<p>If you encounter problems, try these steps: ${examples.troubleshoot || 'Refresh the page, clear your browser cache, check your internet connection, and ensure you have the latest browser version'}. If issues persist, consult the File Box help documentation or contact support for assistance.</p>

<h3>Where can I learn more about advanced features?</h3>
<p>For more advanced information, explore other learning resources in File Box, check the documentation section, or participate in the community forums. You can also experiment with the feature's advanced settings to discover additional capabilities.</p>

<h3>Conclusion</h3>
<p>We hope this FAQ has answered your questions about ${topic}. If you have additional questions or need further assistance, don't hesitate to explore other resources or reach out to the File Box support team.</p>`;
  }

  /**
   * Get topic-specific examples and details
   */
  getTopicExamples(topic, category, isFileManagement, isSharing, isSecurity) {
    const topicLower = topic.toLowerCase();
    
    // File management examples
    if (isFileManagement || topicLower.includes('organization') || topicLower.includes('file')) {
      return {
        step1: 'Organize files into logical folder structures',
        step2: 'Use tags and categories to improve searchability',
        step3: 'Set up automated organization rules',
        gettingStarted: 'You\'ll find organization tools in the main Files section. Look for the "Smart Organize" button or folder creation options.',
        access: 'Navigate to Files in the sidebar, then use the "New Folder" button or drag and drop files to organize them.',
        interface: 'The file browser shows your folders and files. Use the toolbar buttons to create folders, upload files, or access organization features.',
        basicAction: 'Create a new folder by clicking "New Folder", name it appropriately, and start moving files into it.',
        advanced: 'Set up smart organization rules that automatically sort files based on type, name patterns, or content.',
        example1: 'Organizing project files by creating folders for each project phase (Planning, Development, Testing, Deployment)',
        example2: 'Using tags to categorize documents by department, making it easy to filter and find related files',
        example3: 'Setting up automated rules to move downloaded files into appropriate folders based on file type',
        tip1: 'Create a consistent folder naming convention (e.g., YYYY-MM-DD_ProjectName)',
        tip2: 'Use descriptive folder names that clearly indicate contents',
        tip3: 'Regularly review and clean up unused folders to maintain organization',
        tip4: 'Take advantage of the search feature to quickly locate files across folders',
        feature1: 'Folder Creation and Management',
        feature1Desc: 'Create unlimited folders and subfolders to organize your files hierarchically',
        feature2: 'Smart Organization',
        feature2Desc: 'AI-powered suggestions for organizing files based on content and patterns',
        feature3: 'Tagging System',
        feature3Desc: 'Add tags to files for flexible categorization beyond folder structure',
        useStep1: 'Open the Files section and review your current file structure',
        useStep2: 'Create folders using the "New Folder" button or right-click menu',
        useStep3: 'Drag and drop files into appropriate folders or use the move feature',
        useStep4: 'Add tags to files for additional categorization and easier searching',
        app1: 'Managing documents for multiple clients or projects',
        app2: 'Organizing personal files like photos, documents, and media',
        app3: 'Creating a structured archive for historical documents',
        trick1: 'Use keyboard shortcuts: Ctrl/Cmd+N for new folder, Ctrl/Cmd+F for search',
        trick2: 'Enable smart organization suggestions to get AI-powered folder recommendations',
        trick3: 'Use the bulk selection feature to organize multiple files at once',
        whatIs: 'tools and methods to systematically arrange, categorize, and manage your digital files',
        benefit1: 'Time Savings',
        benefit1Desc: 'Quickly locate files without searching through cluttered directories',
        benefit2: 'Better Workflow',
        benefit2Desc: 'Maintain a logical structure that matches your work processes',
        benefit3: 'Team Efficiency',
        benefit3Desc: 'Standardized organization helps team members find files quickly',
        benefit4: 'Reduced Errors',
        benefit4Desc: 'Clear organization prevents accidental deletion or misplacement',
        case1: 'Client File Management',
        case1Desc: 'Create separate folders for each client, with subfolders for different project types or time periods',
        case2: 'Academic Research',
        case2Desc: 'Organize research papers, notes, and data by topic, author, or publication date',
        case3: 'Content Creation',
        case3Desc: 'Structure content assets by type (images, videos, documents) and project',
        impl1: 'Assess your current file structure and identify organizational challenges',
        impl2: 'Design a folder hierarchy that matches your workflow and thinking patterns',
        impl3: 'Use consistent naming conventions for both folders and files',
        impl4: 'Schedule regular maintenance sessions to review and optimize your structure',
        howWorks: 'allowing you to create folders, add tags, and use smart organization features to systematically arrange your files',
        getStarted: 'click on "Files" in the sidebar, then use the "New Folder" button to create your first organizational structure',
        customizations: 'folder display options, default sorting preferences, and view settings (grid or list)',
        mainBenefits: 'faster file retrieval, reduced clutter, improved productivity, and better collaboration',
        limitations: 'storage quotas, maximum folder depth, and file naming restrictions',
        troubleshoot: 'check folder permissions, verify storage space availability, and ensure file names don\'t contain invalid characters'
      };
    }
    
    // Sharing examples
    if (isSharing || topicLower.includes('share') || topicLower.includes('collaborat')) {
      return {
        step1: 'Share files with specific users or create shareable links',
        step2: 'Set permissions (view-only or edit access) for shared content',
        step3: 'Manage shared files and track who has access',
        gettingStarted: 'Select any file or folder, then click the "Share" button to see sharing options.',
        access: 'Right-click on any file or folder and select "Share", or use the share icon in the file toolbar.',
        interface: 'The sharing dialog shows options to share with users, create links, set permissions, and manage existing shares.',
        basicAction: 'Share a file by selecting it, clicking Share, entering an email address, and choosing permission level.',
        advanced: 'Create password-protected links, set expiration dates, and configure advanced sharing settings.',
        example1: 'Sharing project documents with team members for collaborative editing',
        example2: 'Creating a public link to share a presentation with external clients',
        example3: 'Setting up a shared folder for a department with automatic access for new team members',
        tip1: 'Use view-only permissions for sensitive documents that shouldn\'t be modified',
        tip2: 'Set expiration dates on shared links for temporary access',
        tip3: 'Regularly review shared files to remove access for users who no longer need it',
        tip4: 'Use password protection for links containing sensitive information',
        feature1: 'User Sharing',
        feature1Desc: 'Share files directly with other File Box users by email address',
        feature2: 'Shareable Links',
        feature2Desc: 'Generate links that can be shared with anyone, even without a File Box account',
        feature3: 'Permission Management',
        feature3Desc: 'Control who can view, edit, or download your shared files',
        useStep1: 'Select the file or folder you want to share',
        useStep2: 'Click the Share button and choose sharing method (user or link)',
        useStep3: 'Configure permissions and access settings',
        useStep4: 'Send the share invitation or copy the link to share',
        app1: 'Collaborating on documents with remote team members',
        app2: 'Sharing files with clients or external partners',
        app3: 'Creating a shared workspace for project collaboration',
        trick1: 'Use Ctrl/Cmd+Shift+S as a shortcut to open the share dialog',
        trick2: 'Create share templates for frequently shared file types',
        trick3: 'Use the "Shared with Me" section to quickly access files others have shared',
        whatIs: 'capabilities to distribute files and folders with other users, enabling collaboration and information sharing',
        benefit1: 'Collaboration',
        benefit1Desc: 'Work together on files in real-time with team members',
        benefit2: 'Accessibility',
        benefit2Desc: 'Share files with people who don\'t have File Box accounts via links',
        benefit3: 'Control',
        benefit3Desc: 'Maintain control over who can access and modify your files',
        benefit4: 'Convenience',
        benefit4Desc: 'Easily distribute files without email attachments or external services',
        case1: 'Team Project Collaboration',
        case1Desc: 'Share project folders with team members, allowing everyone to access and edit relevant files',
        case2: 'Client Deliverables',
        case2Desc: 'Create secure links to share final deliverables with clients, with view-only access',
        case3: 'Department Resources',
        case3Desc: 'Set up shared folders for department-wide access to common resources and templates',
        impl1: 'Identify files and folders that need to be shared',
        impl2: 'Determine appropriate permission levels for each recipient',
        impl3: 'Establish sharing policies and best practices for your team',
        impl4: 'Regularly audit shared files to ensure access is current and appropriate',
        howWorks: 'providing options to share files with specific users via email or create shareable links with customizable permissions',
        getStarted: 'select a file, click the Share button, and choose whether to share with a user or create a link',
        customizations: 'default permission settings, link expiration preferences, and notification options',
        mainBenefits: 'seamless collaboration, easy file distribution, controlled access, and improved team productivity',
        limitations: 'storage quotas affecting shareable content, maximum number of simultaneous shares, and link expiration settings',
        troubleshoot: 'verify recipient email addresses, check permission settings, ensure sufficient storage space, and confirm link hasn\'t expired'
      };
    }
    
    // Security/Backup examples
    if (isSecurity || topicLower.includes('security') || topicLower.includes('backup') || topicLower.includes('recovery')) {
      return {
        step1: 'Configure security settings and enable backup features',
        step2: 'Set up automated backup schedules',
        step3: 'Learn how to recover files from backups',
        gettingStarted: 'Navigate to Security or Cloud Backup in the Tools section to access security and backup features.',
        access: 'Go to Security or Cloud Backup in the sidebar under Tools, then configure your settings.',
        interface: 'The security dashboard shows options for encryption, access controls, and backup configurations.',
        basicAction: 'Enable automatic backups by going to Cloud Backup, selecting a source folder, and setting a schedule.',
        advanced: 'Configure encryption settings, set up multiple backup locations, and customize retention policies.',
        example1: 'Setting up automatic daily backups of important project folders',
        example2: 'Recovering accidentally deleted files from the backup archive',
        example3: 'Configuring encryption for sensitive documents to protect confidential information',
        tip1: 'Enable automatic backups for critical folders to prevent data loss',
        tip2: 'Regularly test your backup recovery process to ensure it works',
        tip3: 'Use encryption for sensitive files, especially when sharing externally',
        tip4: 'Keep multiple backup copies in different locations for redundancy',
        feature1: 'Automated Backups',
        feature1Desc: 'Schedule automatic backups of selected folders at regular intervals',
        feature2: 'File Recovery',
        feature2Desc: 'Restore deleted or lost files from backup archives',
        feature3: 'Encryption',
        feature3Desc: 'Protect sensitive files with encryption both in storage and during transfer',
        useStep1: 'Access Cloud Backup from the Tools section',
        useStep2: 'Select folders or files you want to back up',
        useStep3: 'Configure backup schedule and destination settings',
        useStep4: 'Monitor backup status and test recovery procedures',
        app1: 'Protecting important business documents from data loss',
        app2: 'Maintaining backup copies of personal files and photos',
        app3: 'Ensuring compliance with data retention requirements',
        trick1: 'Set up backups to run during off-peak hours to avoid performance impact',
        trick2: 'Use the trash recovery feature as a first line of defense before accessing backups',
        trick3: 'Configure email notifications for backup completion and failures',
        whatIs: 'features and practices to protect your files from loss, unauthorized access, and corruption',
        benefit1: 'Data Protection',
        benefit1Desc: 'Safeguard your files against accidental deletion, hardware failure, or corruption',
        benefit2: 'Peace of Mind',
        benefit2Desc: 'Know that your important files are safely backed up and recoverable',
        benefit3: 'Compliance',
        benefit3Desc: 'Meet regulatory requirements for data retention and protection',
        benefit4: 'Disaster Recovery',
        benefit4Desc: 'Quickly restore operations after data loss incidents',
        case1: 'Business Continuity',
        case1Desc: 'Maintain backup copies of critical business documents to ensure operations continue after data loss',
        case2: 'Personal Data Protection',
        case2Desc: 'Backup personal files like photos and documents to prevent permanent loss',
        case3: 'Regulatory Compliance',
        case3Desc: 'Maintain backup archives to meet legal requirements for data retention',
        impl1: 'Identify critical files and folders that require backup protection',
        impl2: 'Choose appropriate backup frequency based on how often files change',
        impl3: 'Test recovery procedures regularly to ensure backups are working correctly',
        impl4: 'Document backup and recovery procedures for team reference',
        howWorks: 'creating copies of your files at scheduled intervals and storing them securely for recovery when needed',
        getStarted: 'open Cloud Backup from Tools, click "Setup Backup", select your source folder, and configure the schedule',
        customizations: 'backup frequency, retention periods, encryption settings, and notification preferences',
        mainBenefits: 'data protection, quick recovery, compliance support, and reduced risk of permanent data loss',
        limitations: 'storage space requirements, backup frequency restrictions, and recovery time windows',
        troubleshoot: 'check backup schedule settings, verify storage space availability, ensure source folders are accessible, and review backup logs for errors'
      };
    }
    
    // Default/generic examples
    return {
      step1: 'Navigate to the feature and understand its basic functionality',
      step2: 'Configure settings according to your preferences and needs',
      step3: 'Apply the feature in your daily workflow for maximum benefit',
      gettingStarted: 'Look for the feature in the appropriate section of File Box.',
      access: 'Use the sidebar navigation or search function to locate the feature.',
      interface: 'Familiarize yourself with the available options and controls.',
      basicAction: 'Start with basic operations to understand core functionality.',
      advanced: 'Explore advanced settings and features as you become more comfortable.',
      example1: 'Using the feature to improve your file management workflow',
      example2: 'Applying the feature in collaborative scenarios',
      example3: 'Leveraging advanced features for power users',
      tip1: 'Take time to understand all available options',
      tip2: 'Customize settings to match your workflow',
      tip3: 'Explore related features for enhanced functionality',
      tip4: 'Refer to documentation when needed',
      feature1: 'Core Functionality',
      feature1Desc: 'The primary capability that addresses your main needs',
      feature2: 'Customization',
      feature2Desc: 'Options to tailor the feature to your preferences',
      feature3: 'Integration',
      feature3Desc: 'Connection with other File Box features',
      useStep1: 'Access the feature through the File Box interface',
      useStep2: 'Configure initial settings',
      useStep3: 'Begin using the feature',
      useStep4: 'Optimize settings based on your experience',
      app1: 'Improving your file management efficiency',
      app2: 'Enhancing collaboration with team members',
      app3: 'Organizing content for better accessibility',
      trick1: 'Use keyboard shortcuts for faster access',
      trick2: 'Set up automation where possible',
      trick3: 'Regularly review and optimize your configuration',
      whatIs: 'a feature designed to enhance your file management capabilities',
      benefit1: 'Efficiency',
      benefit1Desc: 'Streamline your workflow and save time',
      benefit2: 'Organization',
      benefit2Desc: 'Better structure and management of your files',
      benefit3: 'Collaboration',
      benefit3Desc: 'Improved teamwork and coordination',
      benefit4: 'Productivity',
      benefit4Desc: 'Get more done with less effort',
      case1: 'Daily File Management',
      case1Desc: 'Using the feature in your regular file management tasks',
      case2: 'Project Organization',
      case2Desc: 'Applying the feature to organize project-related files',
      case3: 'Team Collaboration',
      case3Desc: 'Using the feature to work effectively with team members',
      impl1: 'Understand your specific needs and requirements',
      impl2: 'Configure the feature accordingly',
      impl3: 'Establish consistent usage patterns',
      impl4: 'Regularly review and optimize',
      howWorks: 'providing tools and features to enhance your file management experience',
      getStarted: 'locate the feature and begin exploring its options',
      customizations: 'various settings and preferences',
      mainBenefits: 'improved efficiency, better organization, and enhanced productivity',
      limitations: 'account type restrictions and storage quotas',
      troubleshoot: 'check settings, verify permissions, and consult documentation'
    };
  }

  /**
   * Get topic purpose description
   */
  getTopicPurpose(topic, category) {
    const topicLower = topic.toLowerCase();
    if (topicLower.includes('organization') || topicLower.includes('file')) {
      return 'organize and structure your files systematically';
    }
    if (topicLower.includes('share') || topicLower.includes('collaborat')) {
      return 'share files and collaborate with others effectively';
    }
    if (topicLower.includes('security') || topicLower.includes('backup') || topicLower.includes('recovery')) {
      return 'protect your files and ensure data safety';
    }
    if (topicLower.includes('search')) {
      return 'find files quickly using advanced search capabilities';
    }
    if (topicLower.includes('team')) {
      return 'manage team workflows and collaboration';
    }
    return 'enhance your file management capabilities';
  }

  /**
   * Get category location
   */
  getCategoryLocation(category) {
    const locations = {
      'getting-started': 'main Files section',
      'file-management': 'Files section',
      'sharing': 'Share dialog or Shared section',
      'collaboration': 'Team Folders or Collaboration section',
      'security': 'Security settings',
      'advanced': 'Advanced settings or Tools section',
      'api': 'API documentation or Developer section'
    };
    return locations[category] || 'appropriate section';
  }

  /**
   * Get related features
   */
  getRelatedFeatures(category) {
    const related = {
      'getting-started': 'file organization and sharing features',
      'file-management': 'sharing and collaboration tools',
      'sharing': 'team folders and collaboration features',
      'collaboration': 'file organization and security settings',
      'security': 'backup and recovery features',
      'advanced': 'all core File Box features',
      'api': 'integration and automation capabilities'
    };
    return related[category] || 'related File Box features';
  }

  /**
   * Generate a learning resource using AI (always tries AI first)
   */
  async generateResource(topic, category, type, difficulty) {
    // Add variation to ensure unique content each time
    const variationSeed = Date.now() + Math.random();
    const uniqueTopic = `${topic} (${new Date().toISOString().split('T')[0]})`;
    
    // Try AI generation with multiple attempts
    const maxAttempts = 3;
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      try {
        // Priority 1: Try OpenRouter (if API key available)
        if (process.env.OPENROUTER_API_KEY) {
          const result = await this.generateWithOpenRouter(uniqueTopic, category, type, difficulty, variationSeed);
          if (result && result.content && result.content.length > 200) {
            return result;
          }
        }
        
        // Priority 2: Try Hugging Face text generation
        try {
          const result = await this.generateWithHuggingFace(uniqueTopic, category, type, difficulty, variationSeed);
          if (result && result.content && result.content.length > 200) {
            return result;
          }
        } catch (hfError) {
          console.log(`[AI] Hugging Face attempt ${attempt} failed, trying next method...`);
        }
        
        // If we have OpenRouter but it failed, retry with different prompt
        if (process.env.OPENROUTER_API_KEY && attempt < maxAttempts) {
          await new Promise(resolve => setTimeout(resolve, 2000 * attempt)); // Exponential backoff
          continue;
        }
      } catch (error) {
        console.error(`[AI] Generation attempt ${attempt} failed:`, error.message);
        if (attempt < maxAttempts) {
          await new Promise(resolve => setTimeout(resolve, 2000 * attempt));
          continue;
        }
      }
    }
    
    // Only use template as absolute last resort, but enhance it with AI-like variations
    console.warn(`[AI] All AI generation attempts failed for ${topic}, using enhanced template`);
    return this.generateEnhancedTemplateResource(topic, category, type, difficulty, variationSeed);
  }

  async generateWithOpenRouter(topic, category, type, difficulty, variationSeed = null) {
    // Add unique elements to prompt to ensure different content each time
    const dateContext = new Date().toLocaleDateString('en-US', { month: 'long', year: 'numeric' });
    const uniqueAngle = this.getUniqueAngle(variationSeed);
    
    const prompt = `Create a unique, comprehensive ${difficulty}-level ${type} about "${topic}" for a cloud storage application called File Box. 
Category: ${category}
Date Context: ${dateContext}
Unique Angle: ${uniqueAngle}

Requirements:
- Title: A clear, engaging, unique title (max 60 characters) - make it different from generic titles
- Description: A detailed, informative 2-3 sentence description (150-250 characters) that is specific and compelling. Include concrete benefits.
- Content: Write ORIGINAL, detailed HTML content (1000-1500 words) with:
  * Multiple unique sections with h2 and h3 headings
  * Detailed explanations with SPECIFIC, REAL examples (not generic)
  * Step-by-step instructions with actual steps
  * Real-world use cases with concrete scenarios
  * Practical tips with actionable advice
  * NO placeholder text, NO generic phrases like "Benefit 1" or "Feature 1"
  * Use proper HTML: <h2>, <h3>, <p>, <ul>, <ol>, <li>, <strong>, <em>, <code>
  * Make content UNIQUE - avoid generic templates
- Tags: 3-5 relevant, specific tags
- Duration: Estimated reading time (10-30 minutes)

CRITICAL REQUIREMENTS:
- Content must be UNIQUE and ORIGINAL - generate fresh content, not templates
- Include SPECIFIC examples: real file names, folder structures, actual scenarios
- Write detailed explanations: explain WHY, not just WHAT
- Use concrete numbers, specific features, actual use cases
- Make it practical and actionable
- Ensure content is comprehensive and educational

Format your response as JSON only:
{
  "title": "Unique, engaging title",
  "description": "Specific, detailed description with concrete benefits",
  "content": "<h2>Unique Section Title</h2><p>Detailed, original content...</p>",
  "tags": ["specific-tag1", "specific-tag2", "specific-tag3"],
  "duration": 15
}`;

    const messages = [
      {
        role: 'system',
        content: 'You are an expert technical writer creating unique, original educational content for a cloud storage application. Always respond with valid JSON only, no additional text. Generate fresh, original content - never use templates or generic placeholders. Make each piece of content unique and different from previous generations.'
      },
      {
        role: 'user',
        content: prompt
      }
    ];

    // Use higher temperature and more tokens for more variation and creativity
    const maxTokens = parseInt(process.env.AI_LEARNING_RESOURCES_MAX_TOKENS) || 3000;
    const temperature = parseFloat(process.env.AI_LEARNING_RESOURCES_TEMPERATURE) || 0.9;
    const response = await callOpenRouter(messages, maxTokens, temperature);
    
    // Try to parse JSON from response
    let jsonData;
    try {
      // Extract JSON from response (might have markdown code blocks)
      const jsonMatch = response.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        jsonData = JSON.parse(jsonMatch[0]);
      } else {
        jsonData = JSON.parse(response);
      }
    } catch (parseError) {
      console.error('Failed to parse AI response as JSON:', parseError);
      return this.generateEnhancedTemplateResource(topic, category, type, difficulty, variationSeed);
    }

    // Ensure description is meaningful
    let description = jsonData.description;
    if (!description || description.trim().length < 50) {
      // Generate a better fallback description
      const typeDescriptions = {
        tutorial: `Step-by-step guide to ${topic.toLowerCase()}. Learn practical techniques and best practices to master this feature in File Box.`,
        guide: `Comprehensive guide covering ${topic.toLowerCase()}. Discover how to effectively use this feature to improve your file management workflow.`,
        article: `In-depth exploration of ${topic.toLowerCase()}. Understand the concepts, benefits, and real-world applications in File Box.`,
        faq: `Common questions and answers about ${topic.toLowerCase()}. Find solutions to frequently asked questions and learn best practices.`,
        documentation: `Technical documentation for ${topic.toLowerCase()}. Reference guide with detailed specifications and implementation details.`,
        video: `Video tutorial on ${topic.toLowerCase()}. Watch and learn how to use this feature effectively in File Box.`
      };
      description = typeDescriptions[type] || `Learn how to use ${topic.toLowerCase()} in File Box. This ${difficulty}-level resource provides practical guidance and examples.`;
    }

    return {
      title: jsonData.title || topic,
      description: description.trim(),
      content: jsonData.content || `<h2>${topic}</h2><p>Content about ${topic}.</p>`,
      tags: jsonData.tags || [topic.toLowerCase().replace(/\s+/g, '-'), category, type],
      duration: jsonData.duration || 10
    };
  }

  async generateWithHuggingFace(topic, category, type, difficulty, variationSeed = null) {
    // Try to use Hugging Face for actual text generation
    try {
      const prompt = `Write a comprehensive ${difficulty}-level ${type} about ${topic} for File Box cloud storage. Include detailed explanations, examples, and practical tips.`;
      const generated = await callHuggingFace(prompt, 1000);
      
      if (generated && generated.length > 200) {
        // Parse and structure the generated content
        return {
          title: `${topic}: Complete Guide`,
          description: `Learn ${topic.toLowerCase()} in File Box. This ${difficulty}-level resource provides detailed guidance and practical examples.`,
          content: `<h2>${topic}</h2><p>${generated}</p>`,
          tags: [topic.toLowerCase().replace(/\s+/g, '-'), category, type],
          duration: difficulty === 'beginner' ? config.learningResources.minDuration : 
                   difficulty === 'intermediate' ? Math.floor((config.learningResources.minDuration + config.learningResources.maxDuration) / 2) :
                   config.learningResources.maxDuration
        };
      }
    } catch (error) {
      console.log('[AI] Hugging Face generation failed:', error.message);
    }
    
    // Fallback to enhanced template
    return this.generateEnhancedTemplateResource(topic, category, type, difficulty, variationSeed);
  }

  /**
   * Get unique angle for content variation
   */
  getUniqueAngle(seed = null) {
    const angles = [
      'Focus on practical, real-world applications',
      'Emphasize time-saving techniques and efficiency',
      'Highlight advanced features and power-user tips',
      'Cover common mistakes and how to avoid them',
      'Include step-by-step workflows for specific scenarios',
      'Focus on integration with other File Box features',
      'Emphasize best practices and industry standards',
      'Cover troubleshooting and problem-solving approaches'
    ];
    
    if (seed) {
      const index = Math.floor((seed % angles.length));
      return angles[index];
    }
    return angles[Math.floor(Math.random() * angles.length)];
  }

  generateEnhancedTemplateResource(topic, category, type, difficulty, variationSeed = null) {
    // Template-based generation with variations
    // Get duration range from config
    const minDuration = config.learningResources.minDuration;
    const maxDuration = config.learningResources.maxDuration;
    const duration = difficulty === 'beginner' 
      ? minDuration 
      : difficulty === 'intermediate' 
        ? Math.floor((minDuration + maxDuration) / 2)
        : maxDuration;

    // Generate detailed content based on topic and type
    const topicLower = topic.toLowerCase();
    const isFileManagement = category === 'file-management' || topicLower.includes('file') || topicLower.includes('organization');
    const isSharing = category === 'sharing' || topicLower.includes('share') || topicLower.includes('collaborat');
    const isSecurity = category === 'security' || topicLower.includes('security') || topicLower.includes('backup') || topicLower.includes('recovery');
    
    const templates = {
      tutorial: {
        title: `Complete Guide to ${topic}`,
        content: this.generateTutorialContent(topic, category, difficulty, isFileManagement, isSharing, isSecurity)
      },
      guide: {
        title: `${topic}: A Practical Guide`,
        content: this.generateGuideContent(topic, category, difficulty, isFileManagement, isSharing, isSecurity)
      },
      article: {
        title: `Understanding ${topic}`,
        content: this.generateArticleContent(topic, category, difficulty, isFileManagement, isSharing, isSecurity)
      },
      faq: {
        title: `Frequently Asked Questions: ${topic}`,
        content: this.generateFAQContent(topic, category, difficulty, isFileManagement, isSharing, isSecurity)
      }
    };

    const template = templates[type] || templates.guide;
    const baseTags = [topic.toLowerCase().replace(/\s+/g, '-'), category, type];
    
    // Add difficulty-based tags
    if (difficulty === 'beginner') {
      baseTags.push('getting-started', 'basics');
    } else if (difficulty === 'intermediate') {
      baseTags.push('advanced', 'tips');
    } else {
      baseTags.push('expert', 'advanced');
    }

    // Generate meaningful descriptions based on type and topic
    const typeDescriptions = {
      tutorial: `Step-by-step tutorial on ${topic.toLowerCase()}. Follow along to learn practical techniques and master this ${difficulty}-level skill in File Box.`,
      guide: `Comprehensive guide to ${topic.toLowerCase()}. Discover strategies, tips, and best practices for effectively using this feature in your workflow.`,
      article: `In-depth article exploring ${topic.toLowerCase()}. Learn about the concepts, benefits, and real-world applications that can improve your file management.`,
      faq: `Frequently asked questions about ${topic.toLowerCase()}. Find answers to common questions and learn how to troubleshoot issues effectively.`,
      documentation: `Technical documentation for ${topic.toLowerCase()}. Reference guide with detailed specifications, API information, and implementation examples.`,
      video: `Video tutorial covering ${topic.toLowerCase()}. Watch demonstrations and learn through visual examples how to use this feature in File Box.`
    };

    const description = typeDescriptions[type] || `Learn how to use ${topic.toLowerCase()} in File Box. This ${difficulty}-level ${type} provides practical guidance and examples.`;

    return {
      title: template.title,
      description: description,
      content: template.content,
      tags: baseTags.slice(0, 5),
      duration: duration
    };
  }

  /**
   * Generate multiple diverse learning resources
   */
  async generateMultipleResources(count = null) {
    // Use configured count or default
    const resourceCount = count || config.learningResources.count;
    const topics = config.learningResources.topics;
    const categories = config.learningResources.categories;
    const types = config.learningResources.types;
    const difficulties = config.learningResources.difficulties;

    const resources = [];
    const usedTopics = new Set();

    for (let i = 0; i < resourceCount; i++) {
      // Select random topic (avoid duplicates)
      let topic;
      let attempts = 0;
      do {
        topic = topics[Math.floor(Math.random() * topics.length)];
        attempts++;
      } while (usedTopics.has(topic) && attempts < 20);
      
      usedTopics.add(topic);

      const category = categories[Math.floor(Math.random() * categories.length)];
      const type = types[Math.floor(Math.random() * types.length)];
      const difficulty = difficulties[Math.floor(Math.random() * difficulties.length)];

      try {
        const resource = await this.generateResource(topic, category, type, difficulty);
        resources.push({
          ...resource,
          type,
          category,
          difficulty,
          isPublished: true
        });
        
        // Add configurable delay to avoid rate limiting
        const delayMs = parseInt(process.env.AI_LEARNING_RESOURCES_DELAY_MS) || 1000;
        await new Promise(resolve => setTimeout(resolve, delayMs));
      } catch (error) {
        console.error(`Error generating resource ${i + 1}:`, error);
        // Continue with next resource
      }
    }

    return resources;
  }
}

module.exports = new AIResourceGenerator();
