"""
MongoDB Atlas Database Connection
"""

from motor.motor_asyncio import AsyncIOMotorClient
import os
from typing import Optional
import logging

logger = logging.getLogger(__name__)

class Database:
    client: Optional[AsyncIOMotorClient] = None
    db = None
    
    @classmethod
    async def connect(cls):
        """Connect to MongoDB Atlas"""
        mongodb_uri = os.getenv("MONGODB_URI", "mongodb+srv://dipeskush15_db_user:Kushwaha@7890@cluster0.vhoiek3.mongodb.net/?appName=Cluster0")
        database_name = os.getenv("MONGODB_DATABASE", "threat_intel")
        
        try:
            cls.client = AsyncIOMotorClient(mongodb_uri)
            cls.db = cls.client[database_name]
            
            # Test connection
            await cls.client.admin.command('ping')
            logger.info(f"✅ Connected to MongoDB Atlas: {database_name}")
            
            # Create indexes for better performance
            await cls._create_indexes()
            
            return cls.db
        except Exception as e:
            logger.error(f"❌ Failed to connect to MongoDB: {e}")
            raise
    
    @classmethod
    async def _create_indexes(cls):
        """Create indexes for collections"""
        try:
            # Users collection
            await cls.db.users.create_index("email", unique=True)
            
            # IOCs collection
            await cls.db.iocs.create_index("value")
            await cls.db.iocs.create_index("type")
            await cls.db.iocs.create_index("severity")
            await cls.db.iocs.create_index("last_seen")
            
            # Alerts collection
            await cls.db.alerts.create_index("user_email")
            await cls.db.alerts.create_index("cve_id")
            
            # File scans collection
            await cls.db.file_scans.create_index("user_email")
            await cls.db.file_scans.create_index("timestamp")
            
            logger.info("✅ Database indexes created")
        except Exception as e:
            logger.warning(f"Index creation warning: {e}")
    
    @classmethod
    async def disconnect(cls):
        """Disconnect from MongoDB"""
        if cls.client:
            cls.client.close()
            logger.info("✅ Disconnected from MongoDB")
    
    @classmethod
    def get_db(cls):
        """Get database instance"""
        return cls.db

# Helper functions to get collections
async def get_users_collection():
    return Database.db.users

async def get_iocs_collection():
    return Database.db.iocs

async def get_alerts_collection():
    return Database.db.alerts

async def get_reports_collection():
    return Database.db.reports

async def get_settings_collection():
    return Database.db.settings

async def get_file_scans_collection():
    return Database.db.file_scans