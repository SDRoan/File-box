const express = require('express');
const router = express.Router();
const auth = require('../middleware/auth');
const Integration = require('../models/Integration');
const axios = require('axios');
const appConfig = require('../config/appConfig');
const crypto = require('crypto');

// Get all integrations for user
router.get('/', auth, async (req, res) => {
  try {
    const integrations = await Integration.find({ user: req.user._id });
    // Don't send access tokens in response
    const safeIntegrations = integrations.map(integration => ({
      _id: integration._id,
      provider: integration.provider,
      providerEmail: integration.providerEmail,
      enabled: integration.enabled,
      settings: integration.settings,
      createdAt: integration.createdAt,
      updatedAt: integration.updatedAt
    }));
    res.json(safeIntegrations);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Temporary storage for OAuth state (in production, use Redis or database)
const oauthStates = new Map();

// Initiate OAuth flow - Microsoft Teams
router.get('/microsoft-teams/auth', auth, async (req, res) => {
  try {
    const state = crypto.randomBytes(32).toString('hex');
    // Store state with user ID
    oauthStates.set(state, {
      userId: req.user._id.toString(),
      provider: 'microsoft_teams',
      timestamp: Date.now()
    });
    
    // Clean up old states (older than 10 minutes)
    setTimeout(() => {
      oauthStates.delete(state);
    }, 10 * 60 * 1000);

    const clientId = process.env.MICROSOFT_TEAMS_CLIENT_ID || 'your-client-id';
    // Use backend server URL for OAuth callback (not frontend)
    const backendUrl = process.env.BACKEND_URL || `http://localhost:${appConfig.server.port}`;
    const redirectUri = `${backendUrl}/api/integrations/callback/microsoft-teams`;
    // Use user-consent permissions (Files.ReadWrite instead of Files.ReadWrite.All)
    // This allows users to consent without admin approval
    const scope = 'Files.ReadWrite offline_access User.Read';
    
    const authUrl = `https://login.microsoftonline.com/common/oauth2/v2.0/authorize?` +
      `client_id=${clientId}&` +
      `response_type=code&` +
      `redirect_uri=${encodeURIComponent(redirectUri)}&` +
      `response_mode=query&` +
      `scope=${encodeURIComponent(scope)}&` +
      `state=${state}`;

    res.json({ authUrl });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// OAuth callback - Microsoft Teams
router.get('/callback/microsoft-teams', async (req, res) => {
  try {
    const { code, state, error } = req.query;

    console.log('Microsoft Teams callback received:', { code: code ? 'present' : 'missing', state: state ? 'present' : 'missing', error });

    if (error) {
      console.error('OAuth error from Microsoft:', error);
      return res.redirect(`${appConfig.server.clientUrl}/integrations?error=${encodeURIComponent(error)}`);
    }

    if (!code) {
      console.error('No authorization code received');
      return res.redirect(`${appConfig.server.clientUrl}/integrations?error=no_code`);
    }

    const clientId = process.env.MICROSOFT_TEAMS_CLIENT_ID || 'your-client-id';
    const clientSecret = process.env.MICROSOFT_TEAMS_CLIENT_SECRET || 'your-client-secret';
    // Use backend server URL for OAuth callback (not frontend)
    const backendUrl = process.env.BACKEND_URL || `http://localhost:${appConfig.server.port}`;
    const redirectUri = `${backendUrl}/api/integrations/callback/microsoft-teams`;

    if (clientId === 'your-client-id' || clientSecret === 'your-client-secret') {
      console.error('Microsoft Teams credentials not configured');
      return res.redirect(`${appConfig.server.clientUrl}/integrations?error=credentials_not_configured`);
    }

    console.log('Exchanging code for tokens...');
    // Exchange code for tokens
    const tokenResponse = await axios.post('https://login.microsoftonline.com/common/oauth2/v2.0/token', 
      new URLSearchParams({
        client_id: clientId,
        client_secret: clientSecret,
        code: code,
        redirect_uri: redirectUri,
        grant_type: 'authorization_code'
      }),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    );

    const { access_token, refresh_token, expires_in } = tokenResponse.data;
    console.log('Tokens received successfully');

    // Get user info
    console.log('Fetching user info...');
    const userResponse = await axios.get('https://graph.microsoft.com/v1.0/me', {
      headers: { Authorization: `Bearer ${access_token}` }
    });

    const email = userResponse.data.mail || userResponse.data.userPrincipalName;
    const userId = userResponse.data.id;
    console.log('User info retrieved:', { email, userId });

    // Get userId from stored state
    const stateData = oauthStates.get(state);
    if (!stateData) {
      console.error('Invalid or expired state parameter');
      return res.redirect(`${appConfig.server.clientUrl}/integrations?error=invalid_state`);
    }
    oauthStates.delete(state); // Clean up
    
    const tempUserId = stateData.userId;
    console.log('Saving integration for user:', tempUserId);

    const expiresAt = expires_in ? new Date(Date.now() + expires_in * 1000) : null;

    const integration = await Integration.findOneAndUpdate(
      { user: tempUserId, provider: 'microsoft_teams' },
      {
        user: tempUserId,
        provider: 'microsoft_teams',
        accessToken: access_token,
        refreshToken: refresh_token,
        tokenExpiresAt: expiresAt,
        providerUserId: userId,
        providerEmail: email,
        enabled: true,
        updatedAt: new Date()
      },
      { upsert: true, new: true }
    );

    console.log('Integration saved successfully, redirecting...');
    res.redirect(`${appConfig.server.clientUrl}/integrations?success=microsoft_teams`);
  } catch (error) {
    console.error('Microsoft Teams OAuth error:', error);
    const errorMessage = error.response?.data?.error_description || error.response?.data?.error || error.message || 'Unknown error';
    console.error('Error details:', errorMessage);
    res.redirect(`${appConfig.server.clientUrl}/integrations?error=${encodeURIComponent(errorMessage)}`);
  }
});

// Connect Microsoft Teams (legacy endpoint for direct token submission)
router.post('/microsoft-teams/connect', auth, async (req, res) => {
  try {
    const { accessToken, refreshToken, expiresIn, userId, email } = req.body;

    if (!accessToken) {
      return res.status(400).json({ message: 'Access token is required' });
    }

    const expiresAt = expiresIn ? new Date(Date.now() + expiresIn * 1000) : null;

    const integration = await Integration.findOneAndUpdate(
      { user: req.user._id, provider: 'microsoft_teams' },
      {
        user: req.user._id,
        provider: 'microsoft_teams',
        accessToken,
        refreshToken,
        tokenExpiresAt: expiresAt,
        providerUserId: userId,
        providerEmail: email,
        enabled: true,
        updatedAt: new Date()
      },
      { upsert: true, new: true }
    );

    res.json({ message: 'Microsoft Teams connected successfully', integrationId: integration._id });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Initiate OAuth flow - Zoom
router.get('/zoom/auth', auth, async (req, res) => {
  try {
    const state = crypto.randomBytes(32).toString('hex');
    oauthStates.set(state, {
      userId: req.user._id.toString(),
      provider: 'zoom',
      timestamp: Date.now()
    });
    
    setTimeout(() => {
      oauthStates.delete(state);
    }, 10 * 60 * 1000);

    const clientId = process.env.ZOOM_CLIENT_ID || 'your-client-id';
    const redirectUri = `${appConfig.server.clientUrl}/integrations/callback/zoom`;
    
    const authUrl = `https://zoom.us/oauth/authorize?` +
      `response_type=code&` +
      `client_id=${clientId}&` +
      `redirect_uri=${encodeURIComponent(redirectUri)}&` +
      `state=${state}`;

    res.json({ authUrl });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// OAuth callback - Zoom
router.get('/callback/zoom', async (req, res) => {
  try {
    const { code, state, error } = req.query;

    if (error) {
      return res.redirect(`${appConfig.server.clientUrl}/integrations?error=${encodeURIComponent(error)}`);
    }

    if (!code) {
      return res.redirect(`${appConfig.server.clientUrl}/integrations?error=no_code`);
    }

    const clientId = process.env.ZOOM_CLIENT_ID || 'your-client-id';
    const clientSecret = process.env.ZOOM_CLIENT_SECRET || 'your-client-secret';
    const redirectUri = `${appConfig.server.clientUrl}/integrations/callback/zoom`;

    // Exchange code for tokens
    const tokenResponse = await axios.post('https://zoom.us/oauth/token',
      new URLSearchParams({
        grant_type: 'authorization_code',
        code: code,
        redirect_uri: redirectUri
      }),
      {
        headers: {
          'Authorization': `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString('base64')}`,
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      }
    );

    const { access_token, refresh_token, expires_in } = tokenResponse.data;

    // Get user info
    const userResponse = await axios.get('https://api.zoom.us/v2/users/me', {
      headers: { Authorization: `Bearer ${access_token}` }
    });

    const email = userResponse.data.email;
    const userId = userResponse.data.id;

    const stateData = oauthStates.get(state);
    if (!stateData) {
      return res.redirect(`${appConfig.server.clientUrl}/integrations?error=invalid_state`);
    }
    oauthStates.delete(state);
    
    const tempUserId = stateData.userId;

    const expiresAt = expires_in ? new Date(Date.now() + expires_in * 1000) : null;

    const integration = await Integration.findOneAndUpdate(
      { user: tempUserId, provider: 'zoom' },
      {
        user: tempUserId,
        provider: 'zoom',
        accessToken: access_token,
        refreshToken: refresh_token,
        tokenExpiresAt: expiresAt,
        providerUserId: userId,
        providerEmail: email,
        enabled: true,
        updatedAt: new Date()
      },
      { upsert: true, new: true }
    );

    res.redirect(`${appConfig.server.clientUrl}/integrations?success=zoom`);
  } catch (error) {
    console.error('Zoom OAuth error:', error);
    res.redirect(`${appConfig.server.clientUrl}/integrations?error=${encodeURIComponent(error.message)}`);
  }
});

// Connect Zoom (legacy endpoint)
router.post('/zoom/connect', auth, async (req, res) => {
  try {
    const { accessToken, refreshToken, expiresIn, userId, email } = req.body;

    if (!accessToken) {
      return res.status(400).json({ message: 'Access token is required' });
    }

    const expiresAt = expiresIn ? new Date(Date.now() + expiresIn * 1000) : null;

    const integration = await Integration.findOneAndUpdate(
      { user: req.user._id, provider: 'zoom' },
      {
        user: req.user._id,
        provider: 'zoom',
        accessToken,
        refreshToken,
        tokenExpiresAt: expiresAt,
        providerUserId: userId,
        providerEmail: email,
        enabled: true,
        updatedAt: new Date()
      },
      { upsert: true, new: true }
    );

    res.json({ message: 'Zoom connected successfully', integrationId: integration._id });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Initiate OAuth flow - Slack
router.get('/slack/auth', auth, async (req, res) => {
  try {
    const state = crypto.randomBytes(32).toString('hex');
    oauthStates.set(state, {
      userId: req.user._id.toString(),
      provider: 'slack',
      timestamp: Date.now()
    });
    
    setTimeout(() => {
      oauthStates.delete(state);
    }, 10 * 60 * 1000);

    const clientId = process.env.SLACK_CLIENT_ID || 'your-client-id';
    const redirectUri = `${appConfig.server.clientUrl}/integrations/callback/slack`;
    const scope = 'files:write files:read channels:write channels:read chat:write';
    
    const authUrl = `https://slack.com/oauth/v2/authorize?` +
      `client_id=${clientId}&` +
      `scope=${encodeURIComponent(scope)}&` +
      `redirect_uri=${encodeURIComponent(redirectUri)}&` +
      `state=${state}`;

    res.json({ authUrl });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// OAuth callback - Slack
router.get('/callback/slack', async (req, res) => {
  try {
    const { code, state, error } = req.query;

    if (error) {
      return res.redirect(`${appConfig.server.clientUrl}/integrations?error=${encodeURIComponent(error)}`);
    }

    if (!code) {
      return res.redirect(`${appConfig.server.clientUrl}/integrations?error=no_code`);
    }

    const clientId = process.env.SLACK_CLIENT_ID || 'your-client-id';
    const clientSecret = process.env.SLACK_CLIENT_SECRET || 'your-client-secret';
    const redirectUri = `${appConfig.server.clientUrl}/integrations/callback/slack`;

    // Exchange code for tokens
    const tokenResponse = await axios.post('https://slack.com/api/oauth.v2.access',
      new URLSearchParams({
        client_id: clientId,
        client_secret: clientSecret,
        code: code,
        redirect_uri: redirectUri
      }),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    );

    if (!tokenResponse.data.ok) {
      throw new Error(tokenResponse.data.error || 'Slack OAuth failed');
    }

    const { access_token, refresh_token, expires_in, authed_user, team } = tokenResponse.data;
    const email = authed_user?.email || '';
    const userId = authed_user?.id || '';
    const teamId = team?.id || '';

    const stateData = oauthStates.get(state);
    if (!stateData) {
      return res.redirect(`${appConfig.server.clientUrl}/integrations?error=invalid_state`);
    }
    oauthStates.delete(state);
    
    const tempUserId = stateData.userId;

    const expiresAt = expires_in ? new Date(Date.now() + expires_in * 1000) : null;

    const integration = await Integration.findOneAndUpdate(
      { user: tempUserId, provider: 'slack' },
      {
        user: tempUserId,
        provider: 'slack',
        accessToken: access_token,
        refreshToken: refresh_token,
        tokenExpiresAt: expiresAt,
        providerUserId: userId,
        providerEmail: email,
        enabled: true,
        settings: { teamId },
        updatedAt: new Date()
      },
      { upsert: true, new: true }
    );

    res.redirect(`${appConfig.server.clientUrl}/integrations?success=slack`);
  } catch (error) {
    console.error('Slack OAuth error:', error);
    res.redirect(`${appConfig.server.clientUrl}/integrations?error=${encodeURIComponent(error.message)}`);
  }
});

// Connect Slack (legacy endpoint)
router.post('/slack/connect', auth, async (req, res) => {
  try {
    const { accessToken, refreshToken, expiresIn, userId, email, teamId } = req.body;

    if (!accessToken) {
      return res.status(400).json({ message: 'Access token is required' });
    }

    const expiresAt = expiresIn ? new Date(Date.now() + expiresIn * 1000) : null;

    const integration = await Integration.findOneAndUpdate(
      { user: req.user._id, provider: 'slack' },
      {
        user: req.user._id,
        provider: 'slack',
        accessToken,
        refreshToken,
        tokenExpiresAt: expiresAt,
        providerUserId: userId,
        providerEmail: email,
        enabled: true,
        settings: { teamId },
        updatedAt: new Date()
      },
      { upsert: true, new: true }
    );

    res.json({ message: 'Slack connected successfully', integrationId: integration._id });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Share file via integration
router.post('/:integrationId/share', auth, async (req, res) => {
  try {
    const { fileId, channel, message } = req.body;
    const integration = await Integration.findOne({
      _id: req.params.integrationId,
      user: req.user._id,
      enabled: true
    });

    if (!integration) {
      return res.status(404).json({ message: 'Integration not found or disabled' });
    }

    // Get file info
    const File = require('../models/File');
    const file = await File.findById(fileId);
    if (!file || file.owner.toString() !== req.user._id.toString()) {
      return res.status(404).json({ message: 'File not found' });
    }

    // Share based on provider
    let result;
    switch (integration.provider) {
      case 'slack':
        result = await shareToSlack(integration, file, channel, message);
        break;
      case 'microsoft_teams':
        result = await shareToTeams(integration, file, channel, message);
        break;
      case 'zoom':
        result = await shareToZoom(integration, file, message);
        break;
      default:
        return res.status(400).json({ message: 'Unsupported provider' });
    }

    res.json({ message: 'File shared successfully', result });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Disconnect integration
router.delete('/:integrationId', auth, async (req, res) => {
  try {
    const integration = await Integration.findOne({
      _id: req.params.integrationId,
      user: req.user._id
    });

    if (!integration) {
      return res.status(404).json({ message: 'Integration not found' });
    }

    await integration.deleteOne();
    res.json({ message: 'Integration disconnected' });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Helper function to refresh Microsoft Teams access token
async function refreshMicrosoftTeamsToken(integration) {
  try {
    const clientId = process.env.MICROSOFT_TEAMS_CLIENT_ID;
    const clientSecret = process.env.MICROSOFT_TEAMS_CLIENT_SECRET;
    
    if (!integration.refreshToken) {
      throw new Error('No refresh token available. Please reconnect Microsoft Teams.');
    }

    const tokenResponse = await axios.post('https://login.microsoftonline.com/common/oauth2/v2.0/token',
      new URLSearchParams({
        client_id: clientId,
        client_secret: clientSecret,
        refresh_token: integration.refreshToken,
        grant_type: 'refresh_token'
      }),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    );

    const { access_token, refresh_token, expires_in } = tokenResponse.data;
    
    // Update integration with new tokens
    integration.accessToken = access_token;
    if (refresh_token) {
      integration.refreshToken = refresh_token;
    }
    if (expires_in) {
      integration.tokenExpiresAt = new Date(Date.now() + expires_in * 1000);
    }
    await integration.save();

    return access_token;
  } catch (error) {
    console.error('Error refreshing Microsoft Teams token:', error.message);
    throw new Error('Failed to refresh access token. Please reconnect Microsoft Teams.');
  }
}

// Helper function to make Microsoft Graph API call with automatic token refresh
async function makeGraphApiCall(integration, method, url, data = null, headers = {}) {
  try {
    const config = {
      method,
      url,
      headers: {
        'Authorization': `Bearer ${integration.accessToken}`,
        ...headers
      }
    };
    
    if (data) {
      config.data = data;
    }

    const response = await axios(config);
    return response;
  } catch (error) {
    // If 401, try refreshing token and retry once
    if (error.response && error.response.status === 401) {
      console.log('Token expired, refreshing...');
      await refreshMicrosoftTeamsToken(integration);
      
      // Retry the request with new token
      const retryConfig = {
        method,
        url,
        headers: {
          'Authorization': `Bearer ${integration.accessToken}`,
          ...headers
        }
      };
      
      if (data) {
        retryConfig.data = data;
      }
      
      return await axios(retryConfig);
    }
    throw error;
  }
}

// Helper functions for sharing
async function shareToSlack(integration, file, channel, message) {
  try {
    const fs = require('fs-extra');
    const path = require('path');
    
    // Get file path - use the path field from the file object
    let filePath = file.path;
    
    // Ensure absolute path if relative
    if (filePath && !path.isAbsolute(filePath)) {
      filePath = path.join(__dirname, '..', filePath);
    }
    
    // Fallback: construct path if path field doesn't exist
    if (!filePath) {
      filePath = path.join(__dirname, '..', 'uploads', file.owner.toString(), file.name);
    }
    
    if (!await fs.pathExists(filePath)) {
      throw new Error(`File not found on server: ${filePath}`);
    }

    // Upload file to Slack
    const FormData = require('form-data');
    const form = new FormData();
    form.append('file', fs.createReadStream(filePath));
    form.append('channels', channel || 'general');
    if (message) {
      form.append('initial_comment', message);
    }
    form.append('filename', file.originalName);

    const uploadResponse = await axios.post('https://slack.com/api/files.upload', form, {
      headers: {
        ...form.getHeaders(),
        'Authorization': `Bearer ${integration.accessToken}`
      }
    });

    if (!uploadResponse.data.ok) {
      throw new Error(uploadResponse.data.error || 'Failed to upload to Slack');
    }

    return { 
      success: true, 
      channel: channel || 'general', 
      fileId: uploadResponse.data.file.id,
      message: 'File shared to Slack successfully' 
    };
  } catch (error) {
    console.error('Slack share error:', error);
    throw new Error(`Failed to share to Slack: ${error.message}`);
  }
}

async function shareToTeams(integration, file, channel, message) {
  try {
    const fs = require('fs-extra');
    const path = require('path');
    
    // Debug: log file object to see what we have
    console.log('File object:', {
      id: file._id,
      name: file.name,
      originalName: file.originalName,
      path: file.path,
      owner: file.owner
    });
    
    // Get file path - use the path field from the file object
    let filePath = file.path;
    
    // Validate filePath is a string
    if (!filePath || typeof filePath !== 'string') {
      // Fallback: construct path if path field doesn't exist or is invalid
      if (!file.owner || !file.name) {
        throw new Error(`Invalid file object: missing owner or name. File: ${JSON.stringify({ owner: file.owner, name: file.name, path: file.path })}`);
      }
      filePath = path.join(__dirname, '..', 'uploads', file.owner.toString(), file.name);
      console.log('Constructed file path:', filePath);
    } else {
      // Ensure absolute path if relative
      if (!path.isAbsolute(filePath)) {
        filePath = path.join(__dirname, '..', filePath);
      }
      console.log('Using file.path:', filePath);
    }
    
    // Validate filePath is still a string before using it
    if (!filePath || typeof filePath !== 'string') {
      throw new Error(`Invalid file path: ${filePath}`);
    }
    
    if (!await fs.pathExists(filePath)) {
      throw new Error(`File not found on server: ${filePath}`);
    }

    // Upload file to OneDrive/SharePoint first, then share to Teams
    const fileContent = await fs.readFile(filePath);
    const fileBuffer = Buffer.from(fileContent);

    // Use originalName or name for the file name
    const fileName = file.originalName || file.name || 'file';
    
    // Upload to OneDrive - encode the file name in the URL path
    const encodedFileName = encodeURIComponent(fileName);
    console.log('Uploading file to OneDrive:', fileName);
    console.log('File size:', fileBuffer.length, 'bytes');
    
    const uploadResponse = await makeGraphApiCall(
      integration,
      'put',
      `https://graph.microsoft.com/v1.0/me/drive/root:/${encodedFileName}:/content`,
      fileBuffer,
      { 'Content-Type': file.mimeType || 'application/octet-stream' }
    );

    console.log('Upload response:', {
      id: uploadResponse.data.id,
      name: uploadResponse.data.name,
      webUrl: uploadResponse.data.webUrl,
      parentReference: uploadResponse.data.parentReference
    });

    const driveItemId = uploadResponse.data.id;
    const webUrl = uploadResponse.data.webUrl;

    // Create a sharing link (using 'anonymous' scope for user-consent compatibility)
    const shareResponse = await makeGraphApiCall(
      integration,
      'post',
      `https://graph.microsoft.com/v1.0/me/drive/items/${driveItemId}/createLink`,
      {
        type: 'view',
        scope: 'anonymous' // Changed from 'organization' to work with user-consent permissions
      },
      { 'Content-Type': 'application/json' }
    );

    // Post to Teams channel (if channel ID provided)
    if (channel) {
      const teamsMessage = {
        body: {
          contentType: 'html',
          content: message ? `<p>${message}</p><p><a href="${shareResponse.data.link.webUrl}">${file.originalName}</a></p>` : `<p><a href="${shareResponse.data.link.webUrl}">${file.originalName}</a></p>`
        }
      };

      await makeGraphApiCall(
        integration,
        'post',
        `https://graph.microsoft.com/v1.0/teams/${channel}/channels/${channel}/messages`,
        teamsMessage,
        { 'Content-Type': 'application/json' }
      );
    }

    return { 
      success: true, 
      channel: channel || 'OneDrive',
      shareLink: shareResponse.data.link.webUrl,
      message: 'File shared to Microsoft Teams successfully' 
    };
  } catch (error) {
    console.error('Teams share error:', error);
    console.error('Error details:', {
      message: error.message,
      response: error.response?.data,
      status: error.response?.status,
      statusText: error.response?.statusText
    });
    
    // Provide more detailed error message
    let errorMessage = `Failed to share to Teams: ${error.message}`;
    if (error.response?.data) {
      errorMessage += ` - ${JSON.stringify(error.response.data)}`;
    }
    throw new Error(errorMessage);
  }
}

async function shareToZoom(integration, file, message) {
  try {
    const fs = require('fs-extra');
    const path = require('path');
    
    // Get file path - use the path field from the file object
    let filePath = file.path;
    
    // Ensure absolute path if relative
    if (filePath && !path.isAbsolute(filePath)) {
      filePath = path.join(__dirname, '..', filePath);
    }
    
    // Fallback: construct path if path field doesn't exist
    if (!filePath) {
      filePath = path.join(__dirname, '..', 'uploads', file.owner.toString(), file.name);
    }
    
    if (!await fs.pathExists(filePath)) {
      throw new Error(`File not found on server: ${filePath}`);
    }

    // Zoom doesn't have a direct file sharing API, but we can upload to Zoom's file storage
    // For now, we'll create a shareable link and notify via chat
    const fileContent = await fs.readFile(filePath);
    const fileBuffer = Buffer.from(fileContent);

    // Upload file to Zoom
    const FormData = require('form-data');
    const form = new FormData();
    form.append('file', fileBuffer, file.originalName);
    form.append('file_name', file.originalName);

    const uploadResponse = await axios.post(
      'https://api.zoom.us/v2/files',
      form,
      {
        headers: {
          ...form.getHeaders(),
          'Authorization': `Bearer ${integration.accessToken}`
        }
      }
    );

    return { 
      success: true, 
      fileId: uploadResponse.data.id,
      message: 'File uploaded to Zoom successfully' 
    };
  } catch (error) {
    console.error('Zoom share error:', error);
    throw new Error(`Failed to share to Zoom: ${error.message}`);
  }
}

module.exports = router;

