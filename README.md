# DMARC Analyzer

A comprehensive web application for analyzing DMARC (Domain-based Message Authentication, Reporting, and Conformance) XML reports. Upload your DMARC reports and get instant insights into your email security posture with beautiful, interactive visualizations.

![DMARC Analyzer Dashboard](https://img.shields.io/badge/Status-Production%20Ready-success)
![Python](https://img.shields.io/badge/Python-3.8+-blue)
![React](https://img.shields.io/badge/React-18.2-61dafb)
![License](https://img.shields.io/badge/License-MIT-green)

## 🚀 Features

### Backend (Python/Flask)
- ✅ **Multi-file Upload**: Upload up to 10 files at once
- ✅ **Format Support**: XML, ZIP, GZ, and TAR files
- ✅ **Intelligent Extraction**: Automatically extracts nested archives and folders
- ✅ **Comprehensive Logging**: Rotating file logs for error tracking and debugging
- ✅ **RESTful API**: Clean API endpoints for data processing
- ✅ **Error Handling**: Robust error handling with detailed messages

### Frontend (React/Vite)
- ✅ **Modern UI**: Sleek dark theme matching the reference design
- ✅ **Drag & Drop**: Easy file upload with drag-and-drop support
- ✅ **Interactive Charts**: Beautiful visualizations using Recharts
- ✅ **Real-time Analytics**: Instant processing feedback with loading states
- ✅ **Responsive Design**: Works perfectly on desktop and mobile
- ✅ **Threat Detection**: Automatic identification of security issues

### Analytics Features
- 📊 **Authentication Analysis**: DKIM, SPF, and DMARC compliance rates
- 🌍 **Source Tracking**: Identify all email sources and their compliance
- 📈 **Timeline View**: Track trends over time with daily breakdowns
- 🚨 **Threat Detection**: Automatic identification of suspicious IPs
- 📝 **Report Summary**: Comprehensive overview of all processed reports
- 🎯 **Compliance Scoring**: Visual compliance rate indicators

## 📋 Prerequisites

### Backend Requirements
- Python 3.8 or higher
- pip (Python package manager)

### Frontend Requirements
- Node.js 16+ and npm
- Modern web browser

## 🛠️ Installation

### 1. Clone the Repository
```bash
git clone <repository-url>
cd dmarc-analyzer
```

### 2. Backend Setup

#### Navigate to backend directory
```bash
cd backend
```

#### Create virtual environment (recommended)
```bash
python -m venv venv

# On Windows
venv\Scripts\activate

# On macOS/Linux
source venv/bin/activate
```

#### Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Frontend Setup

#### Navigate to frontend directory
```bash
cd ../frontend
```

#### Install dependencies
```bash
npm install
```

## 🚀 Running the Application

You need to run both backend and frontend servers simultaneously.

### Terminal 1: Start Backend Server
```bash
cd backend
python app.py
```

The backend will start on `http://localhost:5000`

### Terminal 2: Start Frontend Server
```bash
cd frontend
npm run dev
```

The frontend will start on `http://localhost:3000`

### Access the Application
Open your browser and navigate to `http://localhost:3000`

## 📖 Usage Guide

### Step 1: Upload Files
1. Click on the upload area or drag files directly into it
2. Select one or more DMARC report files (XML, ZIP, GZ, or TAR)
3. Maximum 10 files per upload
4. Click "Analyze" button

### Step 2: Wait for Processing
- The system will extract and parse all files
- Loading indicators show progress
- Processing time depends on file size and count

### Step 3: View Dashboard
Once processing completes, you'll see:

#### Summary Cards
- **Total Messages**: Total number of email messages analyzed
- **DMARC Compliance**: Overall compliance percentage
- **Reports Processed**: Number of files analyzed
- **Threat Level**: Security risk assessment

#### Authentication Overview
- DKIM pass/fail rates with progress bars
- SPF pass/fail rates with progress bars
- Overall DMARC compliance metrics
- Distribution pie chart

#### Timeline Analysis
- Daily message volume trends
- Compliance rates over time
- Interactive area chart

#### Top Email Sources
- List of top sending IPs
- Hostname resolution
- Individual compliance rates
- Color-coded risk indicators

#### Security Insights
- Identified threats and warnings
- Recommendations for improvement
- Risk level classifications

#### Report Sources
- Organizations that sent reports
- Number of reports per source

## 📁 Project Structure

```
dmarc-analyzer/
├── backend/
│   ├── app.py                  # Flask application & API endpoints
│   ├── dmarc_processor.py      # DMARC parsing & analytics logic
│   ├── requirements.txt        # Python dependencies
│   └── logs/                   # Application logs (auto-created)
│
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   ├── Dashboard.jsx   # Main dashboard component
│   │   │   ├── FileUpload.jsx  # File upload component
│   │   │   └── Loader.jsx      # Loading component
│   │   ├── App.jsx             # Main application component
│   │   ├── main.jsx            # Application entry point
│   │   └── index.css           # Global styles
│   ├── index.html              # HTML template
│   ├── package.json            # Node dependencies
│   ├── vite.config.js          # Vite configuration
│   ├── tailwind.config.js      # Tailwind CSS configuration
│   └── postcss.config.js       # PostCSS configuration
│
└── README.md                   # This file
```

## 🔧 Configuration

### Backend Configuration
Edit `backend/app.py` to modify:
- `MAX_CONTENT_LENGTH`: Maximum upload size (default: 50MB)
- `MAX_FILES`: Maximum files per upload (default: 10)
- `ALLOWED_EXTENSIONS`: Supported file types

### Frontend Configuration
Edit `frontend/vite.config.js` to modify:
- Server port (default: 3000)
- API proxy settings

## 📊 Supported File Formats

### Direct XML Files
- `.xml` - DMARC report XML files

### Compressed Files
- `.zip` - ZIP archives
- `.gz` - Gzip compressed files
- `.tar` - TAR archives
- `.tar.gz` - Compressed TAR archives

### Nested Archives
The system automatically handles:
- XML files inside folders
- Archives within archives
- Multiple levels of nesting

## 🔍 Understanding DMARC Reports

### Key Metrics

**DKIM (DomainKeys Identified Mail)**
- Validates that email content hasn't been tampered with
- Uses cryptographic signatures

**SPF (Sender Policy Framework)**
- Validates that emails come from authorized servers
- Checks IP addresses against DNS records

**DMARC Compliance**
- Requires BOTH DKIM and SPF to pass
- Indicates fully authenticated email

### Threat Levels
- **Low**: 90%+ compliance - Good security posture
- **Medium**: 70-89% compliance - Some improvements needed
- **High**: <70% compliance - Significant security concerns

## 🐛 Troubleshooting

### Backend Issues

**Problem**: Module not found errors
```bash
# Solution: Ensure virtual environment is activated and dependencies installed
pip install -r requirements.txt
```

**Problem**: Port 5000 already in use
```bash
# Solution: Kill the process or change port in app.py
# On Windows
netstat -ano | findstr :5000
taskkill /PID <process_id> /F

# On macOS/Linux
lsof -ti:5000 | xargs kill -9
```

**Problem**: File upload fails
- Check file size (must be under 50MB)
- Verify file format is supported
- Check logs in `backend/logs/` directory

### Frontend Issues

**Problem**: npm install fails
```bash
# Solution: Clear cache and reinstall
npm cache clean --force
npm install
```

**Problem**: Cannot connect to backend
- Ensure backend is running on port 5000
- Check CORS configuration in app.py
- Verify proxy settings in vite.config.js

**Problem**: Charts not displaying
- Check browser console for errors
- Ensure data format is correct
- Verify recharts library is installed

## 📝 Logging

### Backend Logs
Location: `backend/logs/dmarc_analyzer.log`

Log Levels:
- **INFO**: Normal operations
- **WARNING**: Potential issues
- **ERROR**: Failed operations

Features:
- Rotating file logs (10MB max, 10 backups)
- Timestamps on all entries
- File and line number tracking

### Viewing Logs
```bash
# View latest logs
tail -f backend/logs/dmarc_analyzer.log

# Search for errors
grep ERROR backend/logs/dmarc_analyzer.log
```

## 🔒 Security Considerations

1. **File Upload Security**
   - File type validation
   - Size limits enforced
   - Temporary file cleanup

2. **Data Privacy**
   - Files processed in temporary directories
   - Automatic cleanup after processing
   - No data persistence

3. **CORS Configuration**
   - Restricted to localhost by default
   - Configure for production deployment

## 🚀 Production Deployment

### Backend
1. Use production WSGI server (e.g., Gunicorn)
```bash
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

2. Set up reverse proxy (Nginx/Apache)
3. Configure SSL/TLS certificates
4. Update CORS settings for production domain

### Frontend
1. Build production bundle
```bash
npm run build
```

2. Serve static files with web server
3. Configure environment variables
4. Set up CDN for assets (optional)

## 🤝 Contributing

Contributions are welcome! Please feel free to submit pull requests.

## 📄 License

This project is licensed under the MIT License.

## 🙏 Acknowledgments

- Flask framework for backend API
- React for frontend framework
- Recharts for beautiful visualizations
- Tailwind CSS for styling
- Lucide React for icons

## 📞 Support

For issues and questions:
1. Check the troubleshooting section
2. Review backend logs
3. Check browser console for frontend errors
4. Open an issue on GitHub

---

**Built with ❤️ for better email security**
