"""
OTP Service for email verification and password reset
"""

import random
import smtplib
import ssl
import re
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from typing import Optional
import json
from pathlib import Path

# OTP storage
OTP_DATA_DIR = Path(__file__).parent.parent / "data"
OTP_DATA_FILE = OTP_DATA_DIR / "otp_codes.json"
OTP_DATA_DIR.mkdir(parents=True, exist_ok=True)

# Email configuration
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USERNAME = "cybernovatechguard@gmail.com"
SMTP_PASSWORD = "qcadyrjbohrqqjex"  # Your app password without spaces


class OTPService:
    """Service for generating and verifying OTP codes"""
    
    def __init__(self):
        self._load_otps()
    
    def _load_otps(self):
        """Load OTP codes from file"""
        if OTP_DATA_FILE.exists():
            with open(OTP_DATA_FILE, 'r') as f:
                self.otps = json.load(f)
        else:
            self.otps = {}
    
    def _save_otps(self):
        """Save OTP codes to file"""
        with open(OTP_DATA_FILE, 'w') as f:
            json.dump(self.otps, f, indent=2)
    
    def generate_otp(self, email: str, purpose: str = "verification") -> str:
        """Generate a 6-digit OTP"""
        otp = str(random.randint(100000, 999999))
        expiry = (datetime.now() + timedelta(minutes=10)).isoformat()
        
        self.otps[email] = {
            "otp": otp,
            "purpose": purpose,
            "expiry": expiry,
            "created_at": datetime.now().isoformat()
        }
        self._save_otps()
        return otp
    
    def verify_otp(self, email: str, otp: str, purpose: str = "verification") -> bool:
        """Verify OTP code"""
        stored = self.otps.get(email)
        
        if not stored:
            return False
        
        # Check if expired
        expiry = datetime.fromisoformat(stored["expiry"])
        if datetime.now() > expiry:
            del self.otps[email]
            self._save_otps()
            return False
        
        # Check OTP and purpose
        if stored["otp"] == otp and stored["purpose"] == purpose:
            # Clear OTP after successful verification
            del self.otps[email]
            self._save_otps()
            return True
        
        return False
    
    def clear_otp(self, email: str):
        """Clear OTP for an email"""
        if email in self.otps:
            del self.otps[email]
            self._save_otps()
    
    def send_email(self, to_email: str, subject: str, body: str) -> bool:
        """Send email using SMTP"""
        # Extract OTP from body for console display
        otp_match = re.search(r'<code[^>]*>(\d+)</code>', body)
        if otp_match:
            print(f"\n{'='*60}")
            print(f"📧 OTP for {to_email}: {otp_match.group(1)}")
            print(f"📝 Subject: {subject}")
            print(f"{'='*60}\n")
        
        if not SMTP_USERNAME or not SMTP_PASSWORD:
            print(f"⚠️ Email not configured. Would send to {to_email}: {subject}")
            return False
        
        try:
            msg = MIMEMultipart()
            msg["From"] = SMTP_USERNAME
            msg["To"] = to_email
            msg["Subject"] = subject
            
            msg.attach(MIMEText(body, "html"))
            
            context = ssl.create_default_context()
            with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
                server.starttls(context=context)
                server.login(SMTP_USERNAME, SMTP_PASSWORD)
                server.send_message(msg)
            
            print(f"✅ Email sent to {to_email}")
            return True
        except Exception as e:
            print(f"❌ Failed to send email: {e}")
            return False
    
    def send_verification_email(self, to_email: str, otp: str) -> bool:
        """Send verification email with OTP"""
        subject = "Verify Your Email - NepalThreat Intel"
        body = f"""
        <html>
        <body style="font-family: Arial, sans-serif; background-color: #f4f4f4; padding: 20px;">
            <div style="max-width: 500px; margin: 0 auto; background-color: #111827; border-radius: 10px; padding: 30px; color: #f9fafb; border: 1px solid #374151;">
                <h1 style="color: #06b6d4; text-align: center;">NepalThreat Intel</h1>
                <h2 style="color: #f9fafb; text-align: center;">Verify Your Email Address</h2>
                <p style="color: #9ca3af; text-align: center;">Please use the following OTP code to verify your email address:</p>
                <div style="background-color: #1f2937; padding: 15px; border-radius: 8px; text-align: center; margin: 20px 0;">
                    <code style="font-size: 32px; font-weight: bold; color: #06b6d4; letter-spacing: 5px;">{otp}</code>
                </div>
                <p style="color: #9ca3af; font-size: 12px; text-align: center;">This code will expire in 10 minutes.</p>
                <hr style="border-color: #374151;">
                <p style="color: #6b7280; font-size: 10px; text-align: center;">If you didn't request this, please ignore this email.</p>
            </div>
        </body>
        </html>
        """
        return self.send_email(to_email, subject, body)
    
    def send_password_reset_email(self, to_email: str, otp: str) -> bool:
        """Send password reset email with OTP"""
        subject = "Reset Your Password - NepalThreat Intel"
        body = f"""
        <html>
        <body style="font-family: Arial, sans-serif; background-color: #f4f4f4; padding: 20px;">
            <div style="max-width: 500px; margin: 0 auto; background-color: #111827; border-radius: 10px; padding: 30px; color: #f9fafb; border: 1px solid #374151;">
                <h1 style="color: #06b6d4; text-align: center;">NepalThreat Intel</h1>
                <h2 style="color: #f9fafb; text-align: center;">Reset Your Password</h2>
                <p style="color: #9ca3af; text-align: center;">Use the following OTP code to reset your password:</p>
                <div style="background-color: #1f2937; padding: 15px; border-radius: 8px; text-align: center; margin: 20px 0;">
                    <code style="font-size: 32px; font-weight: bold; color: #06b6d4; letter-spacing: 5px;">{otp}</code>
                </div>
                <p style="color: #9ca3af; font-size: 12px; text-align: center;">This code will expire in 10 minutes.</p>
                <hr style="border-color: #374151;">
                <p style="color: #6b7280; font-size: 10px; text-align: center;">If you didn't request this, please ignore this email.</p>
            </div>
        </body>
        </html>
        """
        return self.send_email(to_email, subject, body)


# Singleton instance
otp_service = OTPService()