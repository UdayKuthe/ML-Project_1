"""
File processing utilities for resume upload and text extraction
"""

import os
import shutil
from pathlib import Path
from typing import Dict, Any, Optional, Union
import logging
from fastapi import UploadFile, HTTPException
import magic
import PyPDF2
import docx
from io import BytesIO
from config import Config

logger = logging.getLogger(__name__)

class FileProcessor:
    """File processing and text extraction utilities"""
    
    def __init__(self):
        self.upload_folder = Path(Config.UPLOAD_FOLDER)
        self.upload_folder.mkdir(parents=True, exist_ok=True)
        self.max_file_size = Config.MAX_CONTENT_LENGTH
        self.allowed_extensions = Config.ALLOWED_EXTENSIONS
    
    def validate_file(self, file: UploadFile) -> Dict[str, Any]:
        """
        Validate uploaded file
        
        Returns:
            Dict with validation result and details
        """
        # Check file extension
        file_extension = self.get_file_extension(file.filename)
        if file_extension not in self.allowed_extensions:
            return {
                "valid": False,
                "error": f"File type not allowed. Allowed types: {', '.join(self.allowed_extensions)}"
            }
        
        # Check file size (if available)
        if hasattr(file, 'size') and file.size:
            if file.size > self.max_file_size:
                return {
                    "valid": False,
                    "error": f"File too large. Maximum size: {self.max_file_size / (1024*1024):.1f}MB"
                }
        
        return {"valid": True, "error": None}
    
    def get_file_extension(self, filename: str) -> str:
        """Get file extension from filename"""
        return Path(filename).suffix.lower().lstrip('.')
    
    def get_mime_type(self, file_content: bytes, filename: str) -> str:
        """Get MIME type of file"""
        try:
            # Try to detect MIME type using python-magic
            mime = magic.from_buffer(file_content, mime=True)
            return mime
        except:
            # Fallback to extension-based detection
            extension = self.get_file_extension(filename)
            mime_mapping = {
                'pdf': 'application/pdf',
                'doc': 'application/msword',
                'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                'txt': 'text/plain'
            }
            return mime_mapping.get(extension, 'application/octet-stream')
    
    def save_uploaded_file(self, file: UploadFile, user_id: str) -> Dict[str, Any]:
        """
        Save uploaded file to disk
        
        Returns:
            Dict with file information
        """
        try:
            # Read file content
            file_content = file.file.read()
            file.file.seek(0)  # Reset file pointer
            
            # Validate file
            validation = self.validate_file(file)
            if not validation["valid"]:
                raise HTTPException(status_code=400, detail=validation["error"])
            
            # Generate unique filename
            import uuid
            file_id = str(uuid.uuid4())
            file_extension = self.get_file_extension(file.filename)
            safe_filename = f"{file_id}.{file_extension}"
            
            # Create user-specific directory
            user_folder = self.upload_folder / user_id
            user_folder.mkdir(parents=True, exist_ok=True)
            
            # Save file
            file_path = user_folder / safe_filename
            with open(file_path, "wb") as buffer:
                buffer.write(file_content)
            
            # Get file info
            file_info = {
                "original_filename": file.filename,
                "saved_filename": safe_filename,
                "file_path": str(file_path),
                "file_size": len(file_content),
                "mime_type": self.get_mime_type(file_content, file.filename),
                "file_extension": file_extension
            }
            
            logger.info(f"File saved: {file.filename} -> {file_path}")
            return file_info
            
        except Exception as e:
            logger.error(f"Error saving file: {e}")
            raise HTTPException(status_code=500, detail="Error saving file")
    
    def extract_text_from_file(self, file_path: str, mime_type: str) -> str:
        """
        Extract text from uploaded file based on its type
        
        Args:
            file_path: Path to the file
            mime_type: MIME type of the file
            
        Returns:
            Extracted text content
        """
        try:
            if mime_type == 'application/pdf':
                return self.extract_text_from_pdf(file_path)
            elif mime_type in ['application/msword', 
                              'application/vnd.openxmlformats-officedocument.wordprocessingml.document']:
                return self.extract_text_from_word(file_path)
            elif mime_type == 'text/plain':
                return self.extract_text_from_txt(file_path)
            else:
                logger.warning(f"Unsupported file type for text extraction: {mime_type}")
                return ""
                
        except Exception as e:
            logger.error(f"Error extracting text from {file_path}: {e}")
            return ""
    
    def extract_text_from_pdf(self, file_path: str) -> str:
        """Extract text from PDF file"""
        try:
            text = ""
            with open(file_path, 'rb') as file:
                pdf_reader = PyPDF2.PdfReader(file)
                for page_num in range(len(pdf_reader.pages)):
                    page = pdf_reader.pages[page_num]
                    text += page.extract_text() + "\n"
            
            return self.clean_extracted_text(text)
            
        except Exception as e:
            logger.error(f"Error extracting text from PDF {file_path}: {e}")
            return ""
    
    def extract_text_from_word(self, file_path: str) -> str:
        """Extract text from Word document (.doc or .docx)"""
        try:
            if file_path.endswith('.docx'):
                doc = docx.Document(file_path)
                text = ""
                for paragraph in doc.paragraphs:
                    text += paragraph.text + "\n"
                return self.clean_extracted_text(text)
            else:
                # For .doc files, you might need to use python-docx2txt or other libraries
                # For now, return empty string
                logger.warning(f"Legacy .doc format not fully supported: {file_path}")
                return ""
                
        except Exception as e:
            logger.error(f"Error extracting text from Word document {file_path}: {e}")
            return ""
    
    def extract_text_from_txt(self, file_path: str) -> str:
        """Extract text from plain text file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                text = file.read()
            
            return self.clean_extracted_text(text)
            
        except Exception as e:
            logger.error(f"Error extracting text from TXT {file_path}: {e}")
            return ""
    
    def clean_extracted_text(self, text: str) -> str:
        """Clean and normalize extracted text"""
        if not text:
            return ""
        
        # Remove excessive whitespace
        import re
        text = re.sub(r'\n+', '\n', text)
        text = re.sub(r' +', ' ', text)
        text = text.strip()
        
        # Remove special characters that might interfere with NLP
        text = re.sub(r'[^\w\s\.\-\+\#\(\)\[\]@]', ' ', text)
        
        return text
    
    def delete_file(self, file_path: str) -> bool:
        """Delete a file from disk"""
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
                logger.info(f"File deleted: {file_path}")
                return True
            return False
        except Exception as e:
            logger.error(f"Error deleting file {file_path}: {e}")
            return False
    
    def get_file_info(self, file_path: str) -> Optional[Dict[str, Any]]:
        """Get information about a file"""
        try:
            if not os.path.exists(file_path):
                return None
            
            file_stat = os.stat(file_path)
            file_path_obj = Path(file_path)
            
            return {
                "filename": file_path_obj.name,
                "size": file_stat.st_size,
                "created": file_stat.st_ctime,
                "modified": file_stat.st_mtime,
                "extension": file_path_obj.suffix.lower().lstrip('.')
            }
            
        except Exception as e:
            logger.error(f"Error getting file info for {file_path}: {e}")
            return None
    
    def cleanup_user_files(self, user_id: str, older_than_days: int = 30) -> int:
        """
        Clean up old files for a user
        
        Args:
            user_id: User ID
            older_than_days: Delete files older than this many days
            
        Returns:
            Number of files deleted
        """
        try:
            user_folder = self.upload_folder / user_id
            if not user_folder.exists():
                return 0
            
            import time
            from datetime import datetime, timedelta
            
            cutoff_time = time.time() - (older_than_days * 24 * 60 * 60)
            deleted_count = 0
            
            for file_path in user_folder.iterdir():
                if file_path.is_file():
                    file_stat = file_path.stat()
                    if file_stat.st_mtime < cutoff_time:
                        file_path.unlink()
                        deleted_count += 1
                        logger.info(f"Deleted old file: {file_path}")
            
            return deleted_count
            
        except Exception as e:
            logger.error(f"Error cleaning up files for user {user_id}: {e}")
            return 0

# Global file processor instance
file_processor = FileProcessor()

# Utility functions
def save_resume_file(file: UploadFile, user_id: str) -> Dict[str, Any]:
    """Save resume file and return file info"""
    return file_processor.save_uploaded_file(file, user_id)

def extract_resume_text(file_path: str, mime_type: str) -> str:
    """Extract text from resume file"""
    return file_processor.extract_text_from_file(file_path, mime_type)
