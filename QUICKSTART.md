# 🚀 Quick Start Guide - Taara

Get Taara running in 5 minutes!

---

## Step 1: Setup (One-time)

### Windows
```bash
# Create virtual environment
python -m venv venv

# Install dependencies
venv\Scripts\pip.exe install -r requirements.txt
```

### Linux/Mac
```bash
# Create virtual environment
python3 -m venv venv

# Install dependencies
./venv/bin/pip install -r requirements.txt

# Make run script executable
chmod +x run.sh
```

---

## Step 2: Get API Key

1. Go to [Google AI Studio](https://makersuite.google.com/app/apikey)
2. Click "Create API Key"
3. Copy your API key
4. Open `.env` file and paste:
   ```
   GEMINI_API_KEY=your_key_here
   ```

---

## Step 3: Run Taara

### Windows
Double-click `run.bat` or run:
```bash
venv\Scripts\streamlit.exe run main.py
```

### Linux/Mac
```bash
./run.sh
```

---

## Step 4: Access Web Interface

Open your browser to:
```
http://localhost:8501
```

---

## Step 5: Connect to Your Server

In the web interface:

1. **Reasoning Engine API Key**: Paste your Gemini API key
2. **VPS IP Address**: e.g., `192.168.1.100`
3. **SSH Username**: e.g., `root` or `ubuntu`
4. **SSH Password**: Your server password
5. Click **"🚀 Connect & Initialize"**

Wait for baseline DNA collection (10-20 seconds).

---

## Step 6: Try It Out!

### Test DevOps Action
1. Click **DevOps Actions** in sidebar
2. Select "Deploy"
3. Enter service name: `nginx`
4. Click "Propose Deploy with AI"
5. Review proposed commands
6. Click "✅ Approve"

### Test Security Scan
1. Click **Security Actions** in sidebar
2. Select "Scan for Malware"
3. Click "Run ClamAV Scan"
4. Approve the command
5. Check CLI output

---

## Troubleshooting

### "Connection failed"
- Check VPS IP address is correct
- Verify SSH credentials
- Ensure server is accessible (try `ping <ip>`)

### "API key invalid"
- Double-check your Gemini API key in `.env`
- Ensure no extra spaces
- Verify key is active in Google AI Studio

### "Module not found"
- Make sure virtual environment is activated
- Run: `pip install -r requirements.txt` again

### "Permission denied"
- SSH user needs sudo access for some operations
- Try with `root` user or add user to sudoers

---

## Next Steps

- Read [README.md](README.md) for full documentation
- Explore Dashboard to see system metrics
- Test rollback functionality in Actions Log
- Set up ClamAV and CrowdSec on your server for full features

---

**Need help?** Check code comments or reach out!

---

Happy automating! 🎉
