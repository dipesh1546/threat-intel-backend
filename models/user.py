"""
User model for authentication
"""

from datetime import datetime, timedelta
from typing import Optional
import json
from pathlib import Path

# User data file
USER_DATA_DIR = Path(__file__).parent.parent / "data"
USER_DATA_FILE = USER_DATA_DIR / "users.json"
USER_DATA_DIR.mkdir(parents=True, exist_ok=True)


class User:
    """User model"""
    
    def __init__(self, email: str, username: str, password_hash: str, 
                 is_verified: bool = False, created_at: Optional[str] = None):
        self.email = email
        self.username = username
        self.password_hash = password_hash
        self.is_verified = is_verified
        self.created_at = created_at or datetime.now().isoformat()
    
    def to_dict(self):
        return {
            "email": self.email,
            "username": self.username,
            "password_hash": self.password_hash,
            "is_verified": self.is_verified,
            "created_at": self.created_at
        }
    
    @classmethod
    def from_dict(cls, data):
        return cls(
            email=data["email"],
            username=data["username"],
            password_hash=data["password_hash"],
            is_verified=data.get("is_verified", False),
            created_at=data.get("created_at")
        )


class UserDB:
    """Simple file-based user database"""
    
    def __init__(self):
        self._load_users()
    
    def _load_users(self):
        """Load users from JSON file"""
        if USER_DATA_FILE.exists():
            with open(USER_DATA_FILE, 'r') as f:
                data = json.load(f)
                self.users = {email: User.from_dict(user_data) 
                             for email, user_data in data.items()}
        else:
            self.users = {}
    
    def _save_users(self):
        """Save users to JSON file"""
        data = {email: user.to_dict() for email, user in self.users.items()}
        with open(USER_DATA_FILE, 'w') as f:
            json.dump(data, f, indent=2)
    
    def create_user(self, email: str, username: str, password_hash: str) -> User:
        """Create a new user"""
        if email in self.users:
            raise ValueError("User already exists")
        
        user = User(email, username, password_hash)
        self.users[email] = user
        self._save_users()
        return user
    
    def get_user_by_email(self, email: str) -> Optional[User]:
        """Get user by email"""
        return self.users.get(email)
    
    def update_user(self, email: str, **kwargs):
        """Update user fields"""
        user = self.users.get(email)
        if user:
            for key, value in kwargs.items():
                if hasattr(user, key):
                    setattr(user, key, value)
            self._save_users()
            return user
        return None
    
    def verify_user(self, email: str) -> bool:
        """Mark user as verified"""
        user = self.users.get(email)
        if user:
            user.is_verified = True
            self._save_users()
            return True
        return False
    
    def user_exists(self, email: str) -> bool:
        """Check if user exists"""
        return email in self.users


# Singleton instance
user_db = UserDB()
