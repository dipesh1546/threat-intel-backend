"""
Authentication service for user management and JWT tokens
"""

from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
import bcrypt
from models.user import user_db
from services.otp_service import otp_service

# JWT configuration
SECRET_KEY = "your-secret-key-change-this-in-production-please-use-environment-variable"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days


class AuthService:
    """Authentication service"""
    
    def get_password_hash(self, password: str) -> str:
        """Hash password using bcrypt"""
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed.decode('utf-8')
    
    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify password against hash"""
        try:
            return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))
        except Exception as e:
            print(f"Password verification error: {e}")
            return False
    
    def create_access_token(self, data: dict, expires_delta: Optional[timedelta] = None) -> str:
        """Create JWT access token"""
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        return encoded_jwt
    
    def decode_token(self, token: str) -> Optional[dict]:
        """Decode JWT token"""
        print(f"🔍 decode_token called with token length: {len(token)}")
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            print(f"🔍 decode_token success: {payload}")
            return payload
        except JWTError as e:
            print(f"❌ decode_token failed: {e}")
            return None
    
    def get_user_by_email(self, email: str) -> Optional[dict]:
        """Get user by email"""
        user = user_db.get_user_by_email(email)
        if not user:
            return None
        return {
            "email": user.email,
            "username": user.username,
            "is_verified": user.is_verified
        }
    
    def register_user(self, email: str, username: str, password: str) -> dict:
        """Register a new user"""
        # Check if user exists
        if user_db.user_exists(email):
            raise ValueError("User already exists")
        
        # Hash password
        password_hash = self.get_password_hash(password)
        
        # Create user (unverified)
        user = user_db.create_user(email, username, password_hash)
        
        # Generate and send OTP
        otp = otp_service.generate_otp(email, "verification")
        otp_service.send_verification_email(email, otp)
        
        return {
            "email": user.email,
            "username": user.username,
            "message": "User created. Please verify your email with the OTP sent."
        }
    
    def verify_email(self, email: str, otp: str) -> dict:
        """Verify user email with OTP"""
        if not otp_service.verify_otp(email, otp, "verification"):
            raise ValueError("Invalid or expired OTP")
        
        user_db.verify_user(email)
        
        # Create access token
        access_token = self.create_access_token(data={"sub": email})
        
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "user": {
                "email": email,
                "username": user_db.get_user_by_email(email).username,
                "is_verified": True
            }
        }
    
    def login(self, email: str, password: str, remember_me: bool = False) -> dict:
        """Login user"""
        user = user_db.get_user_by_email(email)
        
        if not user:
            raise ValueError("Invalid credentials")
        
        if not self.verify_password(password, user.password_hash):
            raise ValueError("Invalid credentials")
        
        if not user.is_verified:
            # Resend OTP
            otp = otp_service.generate_otp(email, "verification")
            otp_service.send_verification_email(email, otp)
            raise ValueError("Email not verified. A new OTP has been sent.")
        
        # Create access token with custom expiry for remember me
        if remember_me:
            # 30 days for remember me
            expires_delta = timedelta(days=30)
        else:
            # 7 days default
            expires_delta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        
        access_token = self.create_access_token(data={"sub": email}, expires_delta=expires_delta)
        
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "user": {
                "email": user.email,
                "username": user.username,
                "is_verified": user.is_verified
            }
        }
    
    def request_password_reset(self, email: str) -> dict:
        """Request password reset OTP"""
        user = user_db.get_user_by_email(email)
        
        if not user:
            raise ValueError("User not found")
        
        # Generate and send OTP
        otp = otp_service.generate_otp(email, "password_reset")
        otp_service.send_password_reset_email(email, otp)
        
        return {
            "message": "Password reset OTP sent to your email"
        }
    
    def reset_password(self, email: str, otp: str, new_password: str) -> dict:
        """Reset password with OTP"""
        if not otp_service.verify_otp(email, otp, "password_reset"):
            raise ValueError("Invalid or expired OTP")
        
        # Hash new password
        password_hash = self.get_password_hash(new_password)
        
        # Update user password
        user_db.update_user(email, password_hash=password_hash)
        
        return {
            "message": "Password reset successfully"
        }
    
    def update_profile(self, email: str, new_username: str) -> dict:
        """Update user profile"""
        user = user_db.get_user_by_email(email)
        
        if not user:
            raise ValueError("User not found")
        
        # Update username
        user_db.update_user(email, username=new_username)
        
        return {
            "message": "Profile updated successfully",
            "username": new_username
        }
    
    def change_password(self, email: str, current_password: str, new_password: str) -> dict:
        """Change user password"""
        user = user_db.get_user_by_email(email)
        
        if not user:
            raise ValueError("User not found")
        
        # Verify current password
        if not self.verify_password(current_password, user.password_hash):
            raise ValueError("Current password is incorrect")
        
        # Hash new password
        password_hash = self.get_password_hash(new_password)
        
        # Update password
        user_db.update_user(email, password_hash=password_hash)
        
        return {
            "message": "Password changed successfully"
        }
    
    def get_current_user(self, token: str) -> Optional[dict]:
        """Get current user from token"""
        print("🔍 === get_current_user called ===")
        print(f"🔍 Token: {token[:50]}...")
        
        payload = self.decode_token(token)
        print(f"🔍 Decoded payload: {payload}")
        
        if not payload:
            print("❌ Failed to decode token")
            return None
        
        email = payload.get("sub")
        print(f"🔍 Email from payload: {email}")
        
        if not email:
            print("❌ No email in payload")
            return None
        
        user = user_db.get_user_by_email(email)
        print(f"🔍 User from database: {user}")
        
        if not user:
            print(f"❌ User not found for email: {email}")
            return None
        
        result = {
            "email": user.email,
            "username": user.username,
            "is_verified": user.is_verified
        }
        print(f"✅ Returning user: {result}")
        return result


# Singleton instance
auth_service = AuthService()