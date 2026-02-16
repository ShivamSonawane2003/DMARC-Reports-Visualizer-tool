from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import logging
from logging.handlers import RotatingFileHandler
import tempfile
import shutil
from datetime import datetime
from werkzeug.utils import secure_filename
from werkzeug.exceptions import HTTPException
from dmarc_processor import DMARCProcessor
import traceback

# Initialize Flask app
app = Flask(__name__)
CORS(app, origins=['http://localhost:3000', 'http://localhost:5173'])

# Configuration
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = tempfile.mkdtemp()
MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50MB
ALLOWED_EXTENSIONS = {'xml', 'zip', 'gz', 'tar'}
MAX_FILES = 10

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

# Setup logging
LOG_DIR = os.path.join(BASE_DIR, 'logs')
os.makedirs(LOG_DIR, exist_ok=True)

file_handler = RotatingFileHandler(
    os.path.join(LOG_DIR, 'dmarc_analyzer.log'),
    maxBytes=10485760,  # 10MB
    backupCount=10
)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))
file_handler.setLevel(logging.INFO)

root_logger = logging.getLogger()
root_logger.setLevel(logging.INFO)
root_logger.addHandler(file_handler)

app.logger.handlers = []
app.logger.propagate = True
app.logger.info('DMARC Analyzer startup')

# Initialize processor
processor = DMARCProcessor(app.logger)


def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    app.logger.info('Health check called')
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat()
    })


@app.route('/', methods=['GET'])
def index():
    """Basic index route for backend sanity checks"""
    return jsonify({
        'message': 'DMARC Analyzer backend is running',
        'health': '/api/health'
    })


@app.route('/api/upload', methods=['POST'])
def upload_files():
    """
    Upload and process DMARC report files
    Supports: XML, ZIP, GZ, TAR files
    Max files: 10 per request
    """
    try:
        app.logger.info('Upload request received')
        
        # Check if files are present
        if 'files' not in request.files:
            app.logger.warning('No files in request')
            return jsonify({'error': 'No files provided'}), 400
        
        files = request.files.getlist('files')
        app.logger.info(f'Received {len(files)} file(s)')
        
        # Validate file count
        if len(files) > MAX_FILES:
            app.logger.warning(f'Too many files: {len(files)}')
            return jsonify({
                'error': f'Too many files. Maximum {MAX_FILES} files allowed'
            }), 400
        
        # Validate files
        if not files or all(f.filename == '' for f in files):
            app.logger.warning('No files selected')
            return jsonify({'error': 'No files selected'}), 400
        
        # Create temporary directory for this upload session
        session_dir = tempfile.mkdtemp(dir=app.config['UPLOAD_FOLDER'])
        app.logger.info(f'Created session directory: {session_dir}')
        
        uploaded_files = []
        errors = []
        
        # Save uploaded files
        for file in files:
            if file and file.filename:
                filename = secure_filename(file.filename)
                
                if not allowed_file(filename):
                    error_msg = f'File type not allowed: {filename}'
                    app.logger.warning(error_msg)
                    errors.append(error_msg)
                    continue
                
                filepath = os.path.join(session_dir, filename)
                file.save(filepath)
                uploaded_files.append(filepath)
                app.logger.info(f'Saved file: {filename}')
        
        if not uploaded_files:
            app.logger.error('No valid files uploaded')
            shutil.rmtree(session_dir, ignore_errors=True)
            return jsonify({
                'error': 'No valid files uploaded',
                'details': errors
            }), 400
        
        # Process files
        app.logger.info(f'Processing {len(uploaded_files)} file(s)')
        result = processor.process_files(uploaded_files, session_dir)
        
        # Cleanup
        app.logger.info('Cleaning up temporary files')
        shutil.rmtree(session_dir, ignore_errors=True)
        
        if result.get('error'):
            app.logger.error(f'Processing error: {result["error"]}')
            return jsonify(result), 400
        
        app.logger.info(f'Successfully processed {result.get("files_processed", 0)} file(s)')
        return jsonify(result), 200
        
    except Exception as e:
        app.logger.error(f'Unexpected error in upload: {str(e)}')
        app.logger.error(traceback.format_exc())
        return jsonify({
            'error': 'Internal server error',
            'message': str(e)
        }), 500


@app.errorhandler(413)
def too_large(e):
    """Handle file too large error"""
    app.logger.warning('File size exceeded limit')
    return jsonify({
        'error': 'File too large',
        'message': 'Maximum file size is 50MB'
    }), 413


@app.errorhandler(Exception)
def handle_exception(e):
    """Handle unexpected errors with consistent logging"""
    if isinstance(e, HTTPException):
        return e

    app.logger.error('Unhandled exception', exc_info=True)
    return jsonify({
        'error': 'Internal server error',
        'message': 'An unexpected error occurred'
    }), 500


if __name__ == '__main__':
    app.logger.info('Starting Flask server on port 5000')
    app.run(debug=True, host='0.0.0.0', port=5000)
