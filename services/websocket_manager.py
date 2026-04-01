"""
WebSocket Manager for real-time threat updates
"""

from typing import Set
import json
from datetime import datetime


class WebSocketManager:
    """Manages WebSocket connections and broadcasts updates"""
    
    def __init__(self):
        self.active_connections: Set = set()
    
    async def connect(self, websocket):
        """Add a new WebSocket connection"""
        await websocket.accept()
        self.active_connections.add(websocket)
        print(f"✅ New WebSocket connection. Total: {len(self.active_connections)}")
    
    def disconnect(self, websocket):
        """Remove a WebSocket connection"""
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        print(f"❌ WebSocket disconnected. Total: {len(self.active_connections)}")
    
    async def broadcast(self, message: dict):
        """Broadcast message to all connected clients"""
        if not self.active_connections:
            return
        
        data = json.dumps(message)
        disconnected = []
        
        for connection in self.active_connections:
            try:
                await connection.send_text(data)
            except Exception:
                disconnected.append(connection)
        
        # Clean up disconnected clients
        for connection in disconnected:
            self.disconnect(connection)
    
    async def send_threat_update(self, threat: dict):
        """Send a new threat alert to all clients"""
        message = {
            "type": "new_threat",
            "data": threat,
            "timestamp": datetime.now().isoformat()
        }
        await self.broadcast(message)
    
    async def send_stats_update(self, stats: dict):
        """Send updated dashboard stats to all clients"""
        message = {
            "type": "stats_update",
            "data": stats,
            "timestamp": datetime.now().isoformat()
        }
        await self.broadcast(message)


# Singleton instance
websocket_manager = WebSocketManager()