# Quick Setup Guide

## Prerequisites

1. **Node.js** (v14 or higher) - [Download](https://nodejs.org/)
2. **MongoDB** - [Download](https://www.mongodb.com/try/download/community) or use [MongoDB Atlas](https://www.mongodb.com/cloud/atlas) (free tier available)

## Installation Steps

### 1. Install Dependencies

```bash
npm run install-all
```

This will install dependencies for:
- Root project
- Server (backend)
- Client (frontend)

### 2. Configure Environment Variables

Copy the example environment file and update it:

```bash
cd server
cp env.example .env
```

Edit `server/.env` with your configuration:

```env
PORT=5000
MONGODB_URI=mongodb://localhost:27017/dropbox-clone
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production
CLIENT_URL=http://localhost:3000
```

**For MongoDB Atlas users:**
Replace `MONGODB_URI` with your Atlas connection string:
```
MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/dropbox-clone
```

### 3. Start MongoDB

**Local MongoDB:**
```bash
# macOS (using Homebrew)
brew services start mongodb-community

# Linux
sudo systemctl start mongod

# Windows
net start MongoDB
```

**MongoDB Atlas:**
No local installation needed! Just use your connection string in `.env`.

### 4. Run the Application

**Option 1: Run both server and client together (Recommended)**
```bash
npm run dev
```

**Option 2: Run separately**

Terminal 1 - Backend:
```bash
cd server
npm run dev
```

Terminal 2 - Frontend:
```bash
cd client
npm start
```

### 5. Access the Application

- **Frontend:** http://localhost:3000
- **Backend API:** http://localhost:5000

## First Time Setup

1. Open http://localhost:3000
2. Click "Sign up" to create a new account
3. Enter your name, email, and password
4. Start uploading files!

## Troubleshooting

### MongoDB Connection Error
- Make sure MongoDB is running (if using local MongoDB)
- Check your `MONGODB_URI` in `.env` file
- For Atlas, ensure your IP is whitelisted

### Port Already in Use
- Change `PORT` in `server/.env` if 5000 is taken
- Change port in `client/package.json` scripts if 3000 is taken

### Module Not Found Errors
- Run `npm run install-all` again
- Delete `node_modules` folders and reinstall

## Production Deployment

1. Set `NODE_ENV=production` in `.env`
2. Use a strong `JWT_SECRET`
3. Update `CLIENT_URL` to your production domain
4. Build the client: `cd client && npm run build`
5. Serve the built files with a production server (nginx, etc.)










