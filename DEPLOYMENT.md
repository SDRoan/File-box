# Deployment Guide for File Box

This guide will help you deploy your File Box application to Vercel (frontend) and a backend hosting service.

## Prerequisites

1. GitHub account with your code pushed to repository
2. Vercel account (free tier available)
3. Backend hosting service (Railway, Render, or Vercel Serverless Functions)

---

## Part 1: Deploy Frontend to Vercel

### Step 1: Push Code to GitHub

Make sure all your code is committed and pushed:

```bash
git add .
git commit -m "Prepare for deployment"
git push origin main
```

### Step 2: Deploy to Vercel

#### Option A: Using Vercel Dashboard (Recommended)

1. **Go to [vercel.com](https://vercel.com)** and sign in (use GitHub to sign in)

2. **Click "Add New Project"**

3. **Import your GitHub repository:**
   - Select your repository: `SDRoan/File-box`
   - Vercel will auto-detect it's a React app

4. **Configure Project Settings:**
   - **Framework Preset:** Create React App
   - **Root Directory:** `client` (IMPORTANT!)
   - **Build Command:** `npm run build`
   - **Output Directory:** `build`
   - **Install Command:** `npm install`

5. **Environment Variables:**
   Add these in the Vercel dashboard:
   ```
   REACT_APP_API_URL=https://your-backend-url.com/api
   ```
   (Replace with your actual backend URL - you'll get this after deploying backend)

6. **Click "Deploy"**

7. **Wait for deployment** (usually 2-3 minutes)

8. **Your site will be live!** You'll get a URL like: `https://file-box-xyz.vercel.app`

#### Option B: Using Vercel CLI

```bash
# Install Vercel CLI
npm i -g vercel

# Login to Vercel
vercel login

# Deploy
cd client
vercel

# Follow the prompts:
# - Set up and deploy? Yes
# - Which scope? Your account
# - Link to existing project? No
# - Project name? file-box (or your choice)
# - Directory? ./
# - Override settings? No
```

---

## Part 2: Deploy Backend

**Important:** Vercel is primarily for frontend. For your Node.js/Express backend, you have several options:

### Option 1: Railway (Recommended - Easy & Free)

1. **Go to [railway.app](https://railway.app)** and sign in with GitHub

2. **Create New Project** → **Deploy from GitHub repo**

3. **Select your repository** and configure:
   - **Root Directory:** `server`
   - **Build Command:** `npm install`
   - **Start Command:** `npm start`

4. **Add Environment Variables** in Railway dashboard:
   ```
   PORT=5000
   MONGODB_URI=your-mongodb-connection-string
   JWT_SECRET=your-secret-key
   CLIENT_URL=https://your-vercel-app.vercel.app
   SMTP_HOST=smtp.gmail.com
   SMTP_PORT=587
   SMTP_SECURE=false
   SMTP_USER=your-email@gmail.com
   SMTP_PASSWORD=your-app-password
   ```

5. **Get your backend URL** (e.g., `https://file-box-backend.railway.app`)

6. **Update frontend environment variable** in Vercel:
   - Go to Vercel dashboard → Your project → Settings → Environment Variables
   - Update `REACT_APP_API_URL` to: `https://file-box-backend.railway.app/api`

### Option 2: Render

1. **Go to [render.com](https://render.com)** and sign in

2. **New** → **Web Service** → **Connect GitHub**

3. **Configure:**
   - **Name:** file-box-backend
   - **Root Directory:** `server`
   - **Environment:** Node
   - **Build Command:** `npm install`
   - **Start Command:** `npm start`

4. **Add Environment Variables** (same as Railway)

5. **Deploy**

### Option 3: Vercel Serverless Functions (Advanced)

You can convert your Express backend to Vercel serverless functions, but this requires code restructuring.

---

## Part 3: Database Setup

### MongoDB Atlas (Free Tier Available)

1. **Go to [mongodb.com/cloud/atlas](https://www.mongodb.com/cloud/atlas)**

2. **Create a free cluster**

3. **Create a database user** (username/password)

4. **Whitelist IP addresses:**
   - For development: `0.0.0.0/0` (all IPs)
   - For production: Add your backend hosting IPs

5. **Get connection string:**
   - Click "Connect" → "Connect your application"
   - Copy the connection string
   - Replace `<password>` with your database password
   - Example: `mongodb+srv://username:password@cluster.mongodb.net/dbname`

6. **Add to backend environment variables:**
   ```
   MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/filebox
   ```

---

## Part 4: Update Frontend API URL

After deploying backend:

1. **Go to Vercel Dashboard** → Your project → Settings → Environment Variables

2. **Update `REACT_APP_API_URL`:**
   ```
   REACT_APP_API_URL=https://your-backend-url.com/api
   ```

3. **Redeploy** (Vercel will auto-redeploy, or click "Redeploy")

---

## Part 5: Custom Domain (Optional)

1. **In Vercel Dashboard** → Your project → Settings → Domains

2. **Add your domain** (e.g., `filebox.com`)

3. **Update DNS records** as instructed by Vercel

4. **SSL is automatically configured** by Vercel

---

## Troubleshooting

### Frontend Issues

- **Build fails:** Check build logs in Vercel dashboard
- **API calls fail:** Verify `REACT_APP_API_URL` is set correctly
- **404 on refresh:** Ensure `vercel.json` rewrite rules are correct

### Backend Issues

- **Connection refused:** Check backend URL and CORS settings
- **Database connection fails:** Verify MongoDB URI and IP whitelist
- **Environment variables not working:** Ensure they're set in hosting dashboard

### CORS Issues

Make sure your backend has CORS configured to allow your Vercel domain:

```javascript
// In server/index.js
app.use(cors({
  origin: [
    'http://localhost:3000',
    'https://your-vercel-app.vercel.app',
    'https://your-custom-domain.com'
  ],
  credentials: true
}));
```

---

## Quick Checklist

- [ ] Code pushed to GitHub
- [ ] Frontend deployed to Vercel
- [ ] Backend deployed (Railway/Render)
- [ ] MongoDB Atlas cluster created
- [ ] Environment variables set in both frontend and backend
- [ ] `REACT_APP_API_URL` points to backend
- [ ] CORS configured on backend
- [ ] Test registration/login flow
- [ ] Test file upload/download

---

## Support

- Vercel Docs: https://vercel.com/docs
- Railway Docs: https://docs.railway.app
- Render Docs: https://render.com/docs
