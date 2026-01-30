# 🚀 Quick Deployment Guide

## Deploy to Vercel in 5 Minutes

### Step 1: Push to GitHub ✅
Your code is already on GitHub at: `https://github.com/SDRoan/File-box.git`

### Step 2: Deploy Frontend to Vercel

1. **Go to [vercel.com](https://vercel.com)** and sign in with GitHub

2. **Click "Add New Project"**

3. **Import your repository:**
   - Find and select: `SDRoan/File-box`
   - Click "Import"

4. **Configure Project:**
   - **Framework Preset:** Create React App
   - **Root Directory:** `client` ⚠️ (IMPORTANT!)
   - **Build Command:** `npm run build` (auto-detected)
   - **Output Directory:** `build` (auto-detected)

5. **Add Environment Variable:**
   - Key: `REACT_APP_API_URL`
   - Value: `http://localhost:5001/api` (we'll update this after backend deployment)
   - Click "Add"

6. **Click "Deploy"**

7. **Wait 2-3 minutes** - Your site will be live! 🎉

   You'll get a URL like: `https://file-box-xyz.vercel.app`

### Step 3: Deploy Backend (Choose One)

#### Option A: Railway (Easiest - Free Tier)

1. Go to [railway.app](https://railway.app) → Sign in with GitHub
2. **New Project** → **Deploy from GitHub repo**
3. Select `SDRoan/File-box`
4. **Settings:**
   - Root Directory: `server`
   - Build Command: `npm install`
   - Start Command: `npm start`
5. **Variables Tab** → Add:
   ```
   PORT=5000
   MONGODB_URI=mongodb+srv://your-mongodb-connection-string
   JWT_SECRET=your-random-secret-key-here
   CLIENT_URL=https://your-vercel-app.vercel.app
   ALLOWED_ORIGINS=http://localhost:3000,https://your-vercel-app.vercel.app
   ```
6. Copy your Railway URL (e.g., `https://file-box-production.up.railway.app`)

#### Option B: Render

1. Go to [render.com](https://render.com) → Sign in
2. **New** → **Web Service** → Connect GitHub → Select repo
3. Configure:
   - Name: `file-box-backend`
   - Root Directory: `server`
   - Build Command: `npm install`
   - Start Command: `npm start`
4. Add same environment variables as Railway

### Step 4: Set Up MongoDB Atlas (Free)

1. Go to [mongodb.com/cloud/atlas](https://www.mongodb.com/cloud/atlas)
2. **Create Free Cluster**
3. **Database Access** → Create user (save password!)
4. **Network Access** → Add IP: `0.0.0.0/0` (allow all)
5. **Connect** → **Connect your application** → Copy connection string
6. Replace `<password>` in connection string
7. Add to backend environment variables as `MONGODB_URI`

### Step 5: Update Frontend API URL

1. Go back to **Vercel Dashboard** → Your project
2. **Settings** → **Environment Variables**
3. Update `REACT_APP_API_URL` to your backend URL:
   ```
   https://your-backend-url.railway.app/api
   ```
   or
   ```
   https://your-backend-url.onrender.com/api
   ```
4. **Redeploy** (happens automatically, or click "Redeploy")

### Step 6: Test Your Site! 🎉

Visit your Vercel URL and test:
- ✅ Registration with email verification
- ✅ Login
- ✅ File upload
- ✅ File preview

---

## Troubleshooting

**Frontend shows "Cannot connect to server":**
- Check `REACT_APP_API_URL` in Vercel environment variables
- Make sure backend is deployed and running
- Check backend logs in Railway/Render dashboard

**CORS errors:**
- Add your Vercel URL to `ALLOWED_ORIGINS` in backend environment variables
- Format: `http://localhost:3000,https://your-app.vercel.app`

**Build fails:**
- Check build logs in Vercel dashboard
- Make sure `Root Directory` is set to `client`

---

## Your URLs After Deployment

- **Frontend:** `https://your-app.vercel.app`
- **Backend:** `https://your-backend.railway.app` (or Render URL)
- **Database:** MongoDB Atlas (connection string in backend env vars)

---

## Need Help?

- 📖 Full guide: See `DEPLOYMENT.md`
- 🔗 Vercel Docs: https://vercel.com/docs
- 🔗 Railway Docs: https://docs.railway.app
