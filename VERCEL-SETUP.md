# 🚀 Deploy File Box to Vercel - Step by Step

## Quick Start (5 Minutes)

### ✅ Step 1: Push Your Code to GitHub

```bash
cd "/Users/saibyasachiruhan/Desktop/File Box"
git add .
git commit -m "Add Vercel deployment configuration"
git push origin main
```

### ✅ Step 2: Deploy Frontend to Vercel

1. **Go to [vercel.com](https://vercel.com)**
   - Click "Sign Up" or "Log In"
   - Choose "Continue with GitHub"

2. **Import Your Project**
   - Click "Add New..." → "Project"
   - Find your repository: `SDRoan/File-box`
   - Click "Import"

3. **Configure Project Settings**
   
   **IMPORTANT:** Set these values:
   
   - **Framework Preset:** `Create React App` (auto-detected)
   - **Root Directory:** `client` ⚠️ **Change this!**
   - **Build Command:** `npm run build` (auto-detected)
   - **Output Directory:** `build` (auto-detected)
   - **Install Command:** `npm install` (auto-detected)

4. **Add Environment Variable**
   
   Click "Environment Variables" and add:
   
   ```
   Name: REACT_APP_API_URL
   Value: http://localhost:5001/api
   ```
   
   ⚠️ We'll update this after deploying the backend!

5. **Click "Deploy"**
   
   Wait 2-3 minutes for deployment to complete.

6. **🎉 Your Site is Live!**
   
   You'll get a URL like: `https://file-box-abc123.vercel.app`
   
   **Save this URL** - you'll need it for backend configuration!

---

## 🔧 Step 3: Deploy Backend (Choose One)

### Option A: Railway (Recommended - Easiest)

1. **Go to [railway.app](https://railway.app)**
   - Sign in with GitHub

2. **Create New Project**
   - Click "New Project"
   - Select "Deploy from GitHub repo"
   - Choose `SDRoan/File-box`

3. **Configure Service**
   - Click on the new service
   - Go to **Settings** tab
   - Set **Root Directory:** `server`
   - Set **Start Command:** `npm start`

4. **Add Environment Variables**
   
   Go to **Variables** tab and add:
   
   ```
   PORT=5000
   MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/filebox
   JWT_SECRET=your-super-secret-random-key-here-min-32-chars
   CLIENT_URL=https://your-vercel-app.vercel.app
   ALLOWED_ORIGINS=http://localhost:3000,https://your-vercel-app.vercel.app
   SMTP_HOST=smtp.gmail.com
   SMTP_PORT=587
   SMTP_SECURE=false
   SMTP_USER=your-email@gmail.com
   SMTP_PASSWORD=your-gmail-app-password
   ```
   
   ⚠️ Replace:
   - `your-vercel-app.vercel.app` with your actual Vercel URL
   - MongoDB connection string (see Step 4)
   - Gmail credentials (see Step 5)

5. **Get Your Backend URL**
   - Railway will give you a URL like: `https://file-box-production.up.railway.app`
   - **Copy this URL!**

### Option B: Render

1. Go to [render.com](https://render.com) → Sign in
2. **New** → **Web Service**
3. Connect GitHub → Select `SDRoan/File-box`
4. Configure:
   - **Name:** `file-box-backend`
   - **Root Directory:** `server`
   - **Build Command:** `npm install`
   - **Start Command:** `npm start`
5. Add same environment variables as Railway
6. Copy your Render URL

---

## 🗄️ Step 4: Set Up MongoDB Atlas (Free)

1. **Go to [mongodb.com/cloud/atlas](https://www.mongodb.com/cloud/atlas)**
   - Sign up for free account

2. **Create Cluster**
   - Click "Build a Database"
   - Choose **FREE** tier (M0)
   - Select a cloud provider/region
   - Click "Create"

3. **Create Database User**
   - Go to **Database Access** → **Add New Database User**
   - Choose **Password** authentication
   - Username: `filebox-admin` (or your choice)
   - Password: Generate secure password (SAVE IT!)
   - Click "Add User"

4. **Configure Network Access**
   - Go to **Network Access** → **Add IP Address**
   - Click "Allow Access from Anywhere" (adds `0.0.0.0/0`)
   - Click "Confirm"

5. **Get Connection String**
   - Go to **Database** → Click "Connect"
   - Choose "Connect your application"
   - Copy the connection string
   - It looks like: `mongodb+srv://username:<password>@cluster0.xxxxx.mongodb.net/?retryWrites=true&w=majority`
   - Replace `<password>` with your actual password
   - Add database name: `mongodb+srv://username:password@cluster0.xxxxx.mongodb.net/filebox?retryWrites=true&w=majority`

6. **Add to Backend Environment Variables**
   - In Railway/Render, update `MONGODB_URI` with your connection string

---

## 📧 Step 5: Configure Email (Gmail)

For email verification to work:

1. **Enable 2-Factor Authentication** on your Gmail account

2. **Generate App Password**
   - Go to [myaccount.google.com/apppasswords](https://myaccount.google.com/apppasswords)
   - Select "Mail" and "Other (Custom name)"
   - Name it: "File Box"
   - Copy the 16-character password

3. **Add to Backend Environment Variables**
   ```
   SMTP_USER=your-email@gmail.com
   SMTP_PASSWORD=your-16-char-app-password
   ```

---

## 🔄 Step 6: Update Frontend API URL

1. **Go to Vercel Dashboard** → Your project

2. **Settings** → **Environment Variables**

3. **Edit `REACT_APP_API_URL`:**
   ```
   https://your-backend-url.railway.app/api
   ```
   or
   ```
   https://your-backend-url.onrender.com/api
   ```

4. **Redeploy**
   - Vercel will auto-redeploy, or click "Redeploy" button

---

## ✅ Step 7: Test Your Deployment

Visit your Vercel URL and test:

- ✅ Registration (should send email verification code)
- ✅ Email verification
- ✅ Login
- ✅ File upload
- ✅ File preview

---

## 🐛 Troubleshooting

### Frontend Issues

**"Cannot connect to server"**
- ✅ Check `REACT_APP_API_URL` in Vercel environment variables
- ✅ Make sure backend is deployed and running
- ✅ Check backend logs in Railway/Render

**404 on page refresh**
- ✅ `vercel.json` rewrite rules should handle this (already configured)

**Build fails**
- ✅ Check build logs in Vercel dashboard
- ✅ Make sure `Root Directory` is set to `client`

### Backend Issues

**CORS errors**
- ✅ Add your Vercel URL to `ALLOWED_ORIGINS` in backend env vars
- ✅ Format: `http://localhost:3000,https://your-app.vercel.app`

**Database connection fails**
- ✅ Check MongoDB connection string format
- ✅ Verify IP whitelist includes `0.0.0.0/0`
- ✅ Check username/password are correct

**Email not sending**
- ✅ Verify Gmail app password is correct
- ✅ Check SMTP environment variables
- ✅ If email service not configured, registration will work without verification (fallback mode)

---

## 📋 Checklist

- [ ] Code pushed to GitHub
- [ ] Frontend deployed to Vercel
- [ ] Backend deployed (Railway/Render)
- [ ] MongoDB Atlas cluster created
- [ ] Database user created
- [ ] Network access configured
- [ ] Environment variables set in backend
- [ ] `REACT_APP_API_URL` updated in Vercel
- [ ] Gmail app password configured (optional)
- [ ] Tested registration
- [ ] Tested login
- [ ] Tested file upload

---

## 🎉 You're Done!

Your File Box is now live at:
- **Frontend:** `https://your-app.vercel.app`
- **Backend:** `https://your-backend.railway.app`

---

## 📚 Additional Resources

- [Vercel Documentation](https://vercel.com/docs)
- [Railway Documentation](https://docs.railway.app)
- [MongoDB Atlas Guide](https://docs.atlas.mongodb.com/getting-started/)
