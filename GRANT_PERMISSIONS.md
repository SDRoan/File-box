# How to Grant Network Permissions on macOS

## Step-by-Step Instructions

### Method 1: Full Disk Access (Recommended)

1. **Open System Settings**
   - Click the Apple menu (🍎) → System Settings
   - Or System Preferences on older macOS versions

2. **Navigate to Privacy & Security**
   - Click "Privacy & Security" in the sidebar
   - Scroll down to find "Full Disk Access"

3. **Add Terminal/VS Code**
   - Click the lock icon 🔒 (enter your password)
   - Click the "+" button
   - Navigate to and select:
     - **Terminal**: `/Applications/Utilities/Terminal.app`
     - **VS Code**: `/Applications/Visual Studio Code.app`
     - Or wherever your terminal/editor is installed

4. **Enable the Permission**
   - Make sure the checkbox next to the app is ✅ checked
   - Close System Settings

5. **Restart Your Terminal/VS Code**
   - Quit and reopen your terminal or VS Code
   - Try running `npm start` again

### Method 2: Firewall Settings

1. **Open System Settings** → **Network** → **Firewall**
2. Click **Options** or **Firewall Options**
3. Look for Node.js in the list
4. If Node.js is blocked, change it to "Allow incoming connections"
5. If you don't see Node.js, you may need to run a Node app first to trigger the prompt

### Method 3: Terminal-Specific Fix

If you're using VS Code's integrated terminal:

1. **Grant VS Code Full Disk Access** (see Method 1)
2. **Restart VS Code completely**
3. Try running the servers again

### Alternative: Use System Terminal

If VS Code terminal still has issues:

1. Open **Terminal.app** (the system terminal)
2. Navigate to your project:
   ```bash
   cd "/Users/saibyasachiruhan/Desktop/File Box/server"
   npm start
   ```
3. Open a new terminal window for the client:
   ```bash
   cd "/Users/saibyasachiruhan/Desktop/File Box/client"
   npm start
   ```

## Verify Permissions

After granting permissions, test with:

```bash
# Test if Node.js can bind to ports
node -e "require('http').createServer().listen(3000, () => console.log('Port 3000 works!'))"
```

If you see "Port 3000 works!" then permissions are correct.

## Troubleshooting

- **Still getting EPERM errors?** Try restarting your Mac
- **Permission prompt appears?** Always click "Allow" when macOS asks
- **Port already in use?** Kill the process: `lsof -ti:3000 | xargs kill -9`

## Note

The folder name change from "Store Box" to "File Box" is NOT the issue. This is purely a macOS security/permission restriction.
