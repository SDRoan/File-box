let cron;
try {
  cron = require('node-cron');
} catch (error) {
  console.warn('[Scheduler] node-cron not installed. Install it with: npm install node-cron');
  // Create a mock cron object for graceful degradation
  cron = {
    schedule: () => ({})
  };
}

const mongoose = require('mongoose');
const LearningResource = require('../models/LearningResource');
const articleFetcher = require('./articleFetcher');
require('dotenv').config();

class LearningResourceScheduler {
  constructor() {
    this.isRunning = false;
  }

  /**
   * Generate and update learning resources (runs every 24 hours)
   */
  async updateResources() {
    if (this.isRunning) {
      console.log('[Scheduler] Update already in progress, skipping...');
      return;
    }

    this.isRunning = true;
    const startTime = Date.now();
    console.log(`[Scheduler] Starting article fetch from internet at ${new Date().toISOString()}...`);

    try {
      // Generate new AI resources using configured count
      const config = require('../config/aiConfig');
      const resourceCount = config.learningResources.count;
      
      if (!config.learningResources.enabled) {
        console.log('[Scheduler] Article fetching is disabled in config');
        return;
      }

      console.log(`[Scheduler] Fetching ${resourceCount} random articles from internet...`);
      const newResources = await articleFetcher.generateMultipleArticles(resourceCount);
      
      if (!newResources || newResources.length === 0) {
        console.error('[Scheduler] ⚠️  No articles fetched!');
        return;
      }

      console.log(`[Scheduler] Fetched ${newResources.length} random articles from internet`);

      // Connect to MongoDB
      const mongoUri = process.env.MONGODB_URI || 'mongodb://localhost:27017/dropbox-clone';
      
      // Check if already connected
      if (mongoose.connection.readyState === 0) {
        await mongoose.connect(mongoUri);
        console.log('[Scheduler] Connected to MongoDB');
      }

      // Delete old resources to ensure fresh content every 24 hours
      const deleteResult = await LearningResource.deleteMany({});
      console.log(`[Scheduler] Cleared ${deleteResult.deletedCount} old resources`);

      // Insert new articles
      const inserted = await LearningResource.insertMany(newResources);
      const duration = ((Date.now() - startTime) / 1000).toFixed(2);
      
      console.log(`[Scheduler] ✅ Successfully updated ${inserted.length} random articles from internet in ${duration}s!`);

      // Display what was created
      console.log('[Scheduler] New articles:');
      inserted.forEach((resource, index) => {
        console.log(`  ${index + 1}. ${resource.title} (${resource.type}, ${resource.difficulty}) - ${resource.externalUrl ? 'External' : 'Local'}`);
      });

      console.log(`[Scheduler] Next update scheduled for 24 hours from now`);

    } catch (error) {
      console.error('[Scheduler] Error updating resources:', error);
      console.error('[Scheduler] Stack:', error.stack);
    } finally {
      this.isRunning = false;
    }
  }

  /**
   * Start the scheduler
   */
  start() {
    // Check if node-cron is available
    if (!cron || typeof cron.schedule !== 'function') {
      console.warn('[Scheduler] ⚠️  node-cron not available. Install it with: npm install node-cron');
      console.log('[Scheduler] Running one-time resource update instead...');
      this.updateResources();
      return;
    }

    // Use configured schedule interval
    const config = require('../config/aiConfig');
    const scheduleInterval = config.learningResources.updateInterval;
    
    // Run on configured schedule (default: every 24 hours at midnight)
    // Format: minute hour day month day-of-week
    cron.schedule(scheduleInterval, async () => {
      console.log('[Scheduler] Scheduled task triggered at', new Date().toISOString());
      await this.updateResources();
    });

    // Also run immediately on startup (optional - comment out if you don't want this)
    console.log('[Scheduler] Running initial resource update...');
    this.updateResources();

    console.log(`[Scheduler] ✅ Scheduler started. Resources will update on schedule: ${scheduleInterval}`);
  }

  /**
   * Stop the scheduler
   */
  stop() {
    // This would stop all cron jobs, but node-cron doesn't have a built-in stop method
    // The scheduler will stop when the process exits
    console.log('[Scheduler] Scheduler stopped');
  }
}

module.exports = new LearningResourceScheduler();
