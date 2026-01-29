# File Box

A full-featured cloud storage application built with React and Node.js, featuring AI-powered smart organization, file analytics, and advanced file management capabilities.

## Features

- 🔐 User Authentication (Register/Login)
- 📁 File Upload & Download
- 📂 Folder Management (Create, Navigate, Delete)
- ⭐ Star Files and Folders
- 🗑️ Trash System (Soft Delete & Permanent Delete)
- 👥 File Sharing (Share links & User sharing)
- 💾 Storage Management (Track usage and limits)
- 🔄 Real-time Updates (WebSocket integration)
- 📱 Responsive UI

## Tech Stack

### Backend
- Node.js & Express
- MongoDB (Mongoose)
- JWT Authentication
- Socket.io for real-time updates
- Multer for file uploads

### Frontend
- React with TypeScript
- React Router
- Axios for API calls
- Socket.io Client

## Installation

### Prerequisites
- Node.js (v14 or higher)
- MongoDB (local or MongoDB Atlas)

### Setup

1. **Clone and install dependencies:**
```bash
npm run install-all
```

2. **Set up environment variables:**

Create a `.env` file in the `server` directory:
```env
PORT=5000
MONGODB_URI=mongodb://localhost:27017/dropbox-clone
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production
CLIENT_URL=http://localhost:3000
```

3. **Start MongoDB:**
Make sure MongoDB is running on your system. If using MongoDB Atlas, update the `MONGODB_URI` in `.env`.

4. **Run the application:**

Development mode (runs both server and client):
```bash
npm run dev
```

Or run separately:
```bash
# Terminal 1 - Backend
cd server
npm run dev

# Terminal 2 - Frontend
cd client
npm start
```

5. **Access the application:**
- Frontend: http://localhost:3000
- Backend API: http://localhost:5000

## Usage

1. **Register/Login:** Create an account or sign in
2. **Upload Files:** Click the "Upload" button to add files
3. **Create Folders:** Click "New Folder" to organize your files
4. **Navigate:** Click on folders to browse
5. **Manage Files:** Use the action buttons to download, star, or delete files
6. **Share Files:** Share files with other users or create shareable links
7. **View Storage:** Check your storage usage in the sidebar

## Project Structure

```
dropbox-clone/
├── server/
│   ├── models/          # MongoDB models
│   ├── routes/          # API routes
│   ├── middleware/      # Auth middleware
│   ├── uploads/         # Uploaded files storage
│   └── index.js         # Server entry point
├── client/
│   ├── src/
│   │   ├── components/  # React components
│   │   ├── context/     # React context
│   │   ├── services/    # API services
│   │   └── types/       # TypeScript types
│   └── public/
└── package.json         # Root package.json
```

## API Endpoints

### Authentication
- `POST /api/auth/register` - Register new user
- `POST /api/auth/login` - Login user
- `GET /api/auth/me` - Get current user

### Files
- `GET /api/files` - Get files and folders
- `POST /api/files/upload` - Upload file
- `POST /api/files/folder` - Create folder
- `GET /api/files/download/:id` - Download file
- `DELETE /api/files/:id` - Delete file/folder
- `POST /api/files/restore/:id` - Restore from trash
- `POST /api/files/star/:id` - Star/unstar item

### Sharing
- `POST /api/share/create` - Create share link
- `GET /api/share/:shareId` - Get share info
- `POST /api/share/user` - Share with user
- `GET /api/share/shared/with-me` - Get shared files

## Notes

- Files are stored locally in `server/uploads/` directory
- Default storage limit is 10GB per user
- JWT tokens expire after 7 days
- Make sure to change `JWT_SECRET` in production

## License

MIT

