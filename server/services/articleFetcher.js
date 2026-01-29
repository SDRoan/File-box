const axios = require('axios');
const { parseString } = require('xml2js');

/**
 * Service to fetch random articles from the internet via RSS feeds
 */
class ArticleFetcher {
  constructor() {
    // RSS feed URLs from various news sources
    this.rssFeeds = [
      'https://feeds.bbci.co.uk/news/rss.xml',
      'https://rss.cnn.com/rss/edition.rss',
      'https://feeds.reuters.com/reuters/topNews',
      'https://www.theguardian.com/world/rss',
      'https://feeds.npr.org/1001/rss.xml',
      'https://rss.nytimes.com/services/xml/rss/nyt/Technology.xml',
      'https://feeds.wired.com/wired/index',
      'https://techcrunch.com/feed/',
      'https://www.wired.com/feed/rss',
      'https://www.theverge.com/rss/index.xml',
    ];

    // Categories for categorization
    this.categories = [
      'getting-started',
      'file-management',
      'sharing',
      'collaboration',
      'security',
      'advanced',
      'api'
    ];

    // Difficulty levels
    this.difficulties = ['beginner', 'intermediate', 'advanced'];
  }

  /**
   * Parse RSS feed XML
   */
  async parseRSSFeed(feedUrl) {
    try {
      const response = await axios.get(feedUrl, {
        timeout: 10000,
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
      });

      return new Promise((resolve, reject) => {
        parseString(response.data, (err, result) => {
          if (err) {
            reject(err);
          } else {
            resolve(result);
          }
        });
      });
    } catch (error) {
      console.error(`[ArticleFetcher] Error fetching RSS feed ${feedUrl}:`, error.message);
      throw error;
    }
  }

  /**
   * Extract articles from RSS feed
   */
  extractArticlesFromRSS(rssData) {
    const articles = [];
    
    try {
      const items = rssData?.rss?.channel?.[0]?.item || 
                   rssData?.feed?.entry || 
                   [];

      items.forEach((item, index) => {
        try {
          let title = item.title?.[0] || item.title?.['#text'] || 'Untitled Article';
          let description = item.description?.[0] || 
                            item.summary?.[0] || 
                            item.content?.[0]?.['_'] ||
                            item['content:encoded']?.[0] ||
                            'No description available';
          
          // Ensure title is a string
          if (typeof title !== 'string') {
            title = String(title || 'Untitled Article');
          }
          
          // Ensure description is a string
          if (typeof description !== 'string') {
            description = String(description || 'No description available');
          }
          
          // Clean HTML tags from description
          const cleanDescription = description
            .replace(/<[^>]*>/g, '')
            .replace(/&nbsp;/g, ' ')
            .replace(/&amp;/g, '&')
            .replace(/&lt;/g, '<')
            .replace(/&gt;/g, '>')
            .replace(/&quot;/g, '"')
            .trim()
            .substring(0, 500); // Limit description length

          const link = item.link?.[0] || 
                      item.link?.['@']?.href || 
                      item.id?.[0] ||
                      '#';

          const pubDate = item.pubDate?.[0] || 
                         item.published?.[0] ||
                         new Date().toISOString();

          // Extract tags/categories
          const tags = [];
          if (item.category) {
            const categories = Array.isArray(item.category) ? item.category : [item.category];
            categories.forEach(cat => {
              const tag = (cat._ || cat['#text'] || cat).toString().toLowerCase().replace(/\s+/g, '-');
              if (tag && tag.length > 2 && tag.length < 30) {
                tags.push(tag);
              }
            });
          }

          // Generate tags from title if none found
          if (tags.length === 0) {
            const words = title.toLowerCase().split(/\s+/);
            words.forEach(word => {
              const cleanWord = word.replace(/[^a-z0-9]/g, '');
              if (cleanWord.length > 3 && cleanWord.length < 20) {
                tags.push(cleanWord);
              }
            });
            tags.splice(5); // Limit to 5 tags
          }

          articles.push({
            title: title.substring(0, 200), // Limit title length
            description: cleanDescription || 'Read more about this article.',
            externalUrl: link,
            type: 'article',
            category: this.categories[Math.floor(Math.random() * this.categories.length)],
            difficulty: this.difficulties[Math.floor(Math.random() * this.difficulties.length)],
            tags: tags.slice(0, 5), // Limit to 5 tags
            duration: Math.floor(Math.random() * 20) + 5, // Random duration 5-25 minutes
            content: '', // External articles don't have local content
            isPublished: true,
            createdAt: new Date(pubDate),
            updatedAt: new Date()
          });
        } catch (itemError) {
          console.error(`[ArticleFetcher] Error processing article ${index}:`, itemError.message);
        }
      });
    } catch (error) {
      console.error('[ArticleFetcher] Error extracting articles:', error.message);
    }

    return articles;
  }

  /**
   * Fetch articles from a single RSS feed
   */
  async fetchArticlesFromFeed(feedUrl) {
    try {
      const rssData = await this.parseRSSFeed(feedUrl);
      const articles = this.extractArticlesFromRSS(rssData);
      console.log(`[ArticleFetcher] Fetched ${articles.length} articles from ${feedUrl}`);
      return articles;
    } catch (error) {
      console.error(`[ArticleFetcher] Failed to fetch from ${feedUrl}:`, error.message);
      return [];
    }
  }

  /**
   * Fetch random articles from multiple RSS feeds
   */
  async fetchRandomArticles(count = 20) {
    console.log(`[ArticleFetcher] Fetching ${count} random articles from internet...`);
    
    const allArticles = [];
    const shuffledFeeds = [...this.rssFeeds].sort(() => Math.random() - 0.5);

    // Fetch from multiple feeds in parallel (limit to 5 at a time to avoid overwhelming)
    const batchSize = 5;
    for (let i = 0; i < Math.min(shuffledFeeds.length, 10); i += batchSize) {
      const batch = shuffledFeeds.slice(i, i + batchSize);
      const promises = batch.map(feed => this.fetchArticlesFromFeed(feed));
      
      try {
        const results = await Promise.allSettled(promises);
        results.forEach((result, index) => {
          if (result.status === 'fulfilled') {
            allArticles.push(...result.value);
          } else {
            console.error(`[ArticleFetcher] Feed ${batch[index]} failed:`, result.reason?.message);
          }
        });

        // Add delay between batches to be respectful
        if (i + batchSize < shuffledFeeds.length) {
          await new Promise(resolve => setTimeout(resolve, 1000));
        }
      } catch (error) {
        console.error(`[ArticleFetcher] Error in batch ${i}:`, error.message);
      }
    }

    // Shuffle and select random articles
    const shuffled = allArticles.sort(() => Math.random() - 0.5);
    const selectedArticles = shuffled.slice(0, count);

    console.log(`[ArticleFetcher] Successfully fetched ${selectedArticles.length} random articles`);
    
    return selectedArticles;
  }

  /**
   * Generate multiple random articles
   */
  async generateMultipleArticles(count = 20) {
    try {
      const articles = await this.fetchRandomArticles(count);
      
      if (articles.length === 0) {
        console.warn('[ArticleFetcher] No articles fetched, generating fallback articles');
        return this.generateFallbackArticles(count);
      }

      return articles;
    } catch (error) {
      console.error('[ArticleFetcher] Error generating articles:', error);
      return this.generateFallbackArticles(count);
    }
  }

  /**
   * Generate fallback articles if RSS feeds fail
   */
  generateFallbackArticles(count) {
    const fallbackArticles = [];
    const topics = [
      'Technology Trends',
      'Software Development',
      'Cloud Computing',
      'Data Security',
      'Artificial Intelligence',
      'Web Development',
      'Mobile Apps',
      'Cybersecurity',
      'Programming Languages',
      'Tech News'
    ];

    for (let i = 0; i < count; i++) {
      const topic = topics[Math.floor(Math.random() * topics.length)];
      fallbackArticles.push({
        title: `Latest News: ${topic}`,
        description: `Stay updated with the latest developments in ${topic.toLowerCase()}. Read more to learn about current trends and insights.`,
        externalUrl: `https://news.google.com/search?q=${encodeURIComponent(topic)}`,
        type: 'article',
        category: this.categories[Math.floor(Math.random() * this.categories.length)],
        difficulty: this.difficulties[Math.floor(Math.random() * this.difficulties.length)],
        tags: [topic.toLowerCase().replace(/\s+/g, '-'), 'news', 'technology'],
        duration: Math.floor(Math.random() * 20) + 5,
        content: '',
        isPublished: true,
        createdAt: new Date(),
        updatedAt: new Date()
      });
    }

    return fallbackArticles;
  }
}

module.exports = new ArticleFetcher();
