# Integrations Setup Guide

Follow these steps to set up real-time OAuth integrations for Microsoft Teams, Zoom, and Slack.

## Step 1: Install Required Package ✅

The `form-data` package has been installed. This is needed for file uploads to integrations.

## Step 2: Set Up OAuth Apps

### Microsoft Teams Setup

1. Go to [Azure Portal](https://portal.azure.com)
2. Navigate to **Azure Active Directory** → **App registrations**
3. Click **New registration**
4. Fill in:
   - **Name**: File Box Integration
   - **Supported account types**: Accounts in any organizational directory and personal Microsoft accounts
   - **Redirect URI**: 
     - Type: Web
     - URI: `http://localhost:3000/integrations/callback/microsoft-teams`
5. Click **Register**
6. Go to **Certificates & secrets** → **New client secret**
7. Copy the **Client ID** and **Client secret value**
8. Go to **API permissions** → **Add a permission** → **Microsoft Graph** → **Delegated permissions**
9. Add these permissions:
   - `Files.ReadWrite.All`
   - `User.Read`
   - `offline_access`
10. Click **Grant admin consent**

### Zoom Setup

1. Go to [Zoom Marketplace](https://marketplace.zoom.us)
2. Click **Develop** → **Build App**
3. Choose **OAuth** app type
4. Fill in:
   - **App Name**: File Box Integration
   - **Company Name**: Your Company
   - **Developer Email**: Your Email
5. In **Redirect URL for OAuth**, add:
   - `http://localhost:3000/integrations/callback/zoom`
6. Add these scopes:
   - `files:write:admin`
   - `files:read:admin`
   - `user:read`
7. Click **Create**
8. Copy the **Client ID** and **Client Secret**

### Slack Setup

1. Go to [Slack API](https://api.slack.com/apps)
2. Click **Create New App** → **From scratch**
3. Fill in:
   - **App Name**: File Box Integration
   - **Workspace**: Select your workspace
4. Go to **OAuth & Permissions** in the sidebar
5. Under **Redirect URLs**, click **Add New Redirect URL**
6. Add: `http://localhost:3000/integrations/callback/slack`
7. Under **Scopes** → **Bot Token Scopes**, add:
   - `files:write`
   - `files:read`
   - `channels:write`
   - `channels:read`
   - `chat:write`
8. Under **User Token Scopes**, add:
   - `files:write`
   - `files:read`
9. Click **Save Changes**
10. Go to **Basic Information** → **App Credentials**
11. Copy the **Client ID** and **Client Secret**

## Step 3: Add Credentials to .env File

1. Navigate to the `server` folder
2. Create or edit `.env` file (copy from `env.example` if needed)
3. Add these lines with your actual credentials:

```env
# Integration OAuth Credentials
MICROSOFT_TEAMS_CLIENT_ID=your-microsoft-teams-client-id-here
MICROSOFT_TEAMS_CLIENT_SECRET=your-microsoft-teams-client-secret-here
ZOOM_CLIENT_ID=your-zoom-client-id-here
ZOOM_CLIENT_SECRET=your-zoom-client-secret-here
SLACK_CLIENT_ID=your-slack-client-id-here
SLACK_CLIENT_SECRET=your-slack-client-secret-here
```

**Important**: Replace the placeholder values with your actual OAuth credentials from Step 2.

## Step 4: Restart Your Server

After adding the credentials, restart your backend server:

```bash
cd server
npm start
# or if using nodemon
npm run dev
```

## Step 5: Test the Integration

1. Start your frontend (`npm start` in the `client` folder)
2. Navigate to the **Integrations** page
3. Click **Connect** on any integration (Microsoft Teams, Zoom, or Slack)
4. You'll be redirected to the provider's OAuth page
5. Sign in and authorize the app
6. You'll be redirected back to your app
7. The integration should show as "Connected"

## Troubleshooting

### "Failed to get OAuth URL"
- Check that your server is running
- Verify your `.env` file has the correct credentials
- Make sure the server restarted after adding credentials

### "Invalid redirect URI"
- Double-check that the redirect URI in your OAuth app matches exactly:
  - `http://localhost:3000/integrations/callback/microsoft-teams`
  - `http://localhost:3000/integrations/callback/zoom`
  - `http://localhost:3000/integrations/callback/slack`

### "Invalid client credentials"
- Verify your Client ID and Client Secret are correct
- Make sure there are no extra spaces in your `.env` file
- Restart the server after making changes

### File sharing not working
- Check that you've granted all required permissions/scopes
- Verify the integration shows as "Connected"
- Check server logs for error messages

## Notes

- For production, update the redirect URIs to your production domain
- Keep your Client Secrets secure and never commit them to version control
- The `.env` file should be in `.gitignore` (it already is)
