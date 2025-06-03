"""
WebSocket Client Example for Monitor Legislativo v4
Demonstrates real-time features usage

Developed by: Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães
Organization: MackIntegridade
Financing: MackPesquisa
"""

import asyncio
import json
import websockets
import sys
from datetime import datetime

class LegislativeMonitorClient:
    """WebSocket client for legislative monitoring"""
    
    def __init__(self, url="ws://localhost:8000/api/v1/ws", token=None):
        self.url = url
        self.token = token
        self.running = False
        
    async def connect(self):
        """Connect to WebSocket server"""
        uri = self.url
        if self.token:
            uri += f"?token={self.token}"
            
        async with websockets.connect(uri) as websocket:
            self.websocket = websocket
            self.running = True
            
            print(f"🔌 Connected to {self.url}")
            print("=" * 50)
            
            # Start receiving messages
            await asyncio.gather(
                self.receive_messages(),
                self.interactive_loop()
            )
    
    async def receive_messages(self):
        """Receive and display messages from server"""
        try:
            while self.running:
                message = await self.websocket.recv()
                data = json.loads(message)
                self.display_message(data)
        except websockets.exceptions.ConnectionClosed:
            print("\n❌ Connection closed")
            self.running = False
    
    async def interactive_loop(self):
        """Interactive command loop"""
        await asyncio.sleep(1)  # Wait for connection message
        
        print("\n📋 Available commands:")
        print("  1. Subscribe to topic")
        print("  2. Unsubscribe from topic")
        print("  3. Configure search alert")
        print("  4. Send ping")
        print("  5. Exit")
        print("-" * 50)
        
        while self.running:
            try:
                # Get user input (non-blocking)
                command = await asyncio.get_event_loop().run_in_executor(
                    None, input, "\nEnter command (1-5): "
                )
                
                if command == "1":
                    await self.subscribe_to_topic()
                elif command == "2":
                    await self.unsubscribe_from_topic()
                elif command == "3":
                    await self.configure_alert()
                elif command == "4":
                    await self.send_ping()
                elif command == "5":
                    print("👋 Goodbye!")
                    self.running = False
                    await self.websocket.close()
                else:
                    print("❓ Invalid command")
                    
            except EOFError:
                break
    
    async def subscribe_to_topic(self):
        """Subscribe to a topic"""
        print("\n📌 Available topics:")
        print("  - all_propositions")
        print("  - new_propositions")
        print("  - source:camara")
        print("  - source:senado")
        print("  - source:planalto")
        print("  - keyword:<word>")
        
        topic = input("Enter topic: ").strip()
        if topic:
            await self.send_message({
                "type": "subscribe",
                "topic": topic
            })
    
    async def unsubscribe_from_topic(self):
        """Unsubscribe from a topic"""
        topic = input("Enter topic to unsubscribe: ").strip()
        if topic:
            await self.send_message({
                "type": "unsubscribe",
                "topic": topic
            })
    
    async def configure_alert(self):
        """Configure a search alert"""
        query = input("Enter search query: ").strip()
        sources_input = input("Enter sources (comma-separated, or press Enter for all): ").strip()
        
        sources = []
        if sources_input:
            sources = [s.strip() for s in sources_input.split(",")]
        
        await self.send_message({
            "type": "configure_alert",
            "query": query,
            "sources": sources
        })
    
    async def send_ping(self):
        """Send ping message"""
        await self.send_message({
            "type": "ping"
        })
    
    async def send_message(self, message):
        """Send a message to the server"""
        await self.websocket.send(json.dumps(message))
        print(f"📤 Sent: {message['type']}")
    
    def display_message(self, data):
        """Display received message"""
        msg_type = data.get("type", "unknown")
        timestamp = data.get("timestamp", "")
        
        print(f"\n📨 [{timestamp}] {msg_type.upper()}")
        
        if msg_type == "connection":
            print(f"   ✅ {data.get('message')}")
        
        elif msg_type == "subscription":
            status = data.get("status")
            topic = data.get("topic")
            print(f"   📌 Topic '{topic}' - {status}")
        
        elif msg_type == "new_proposition":
            prop = data.get("data", {})
            print(f"   🆕 New Proposition: {prop.get('title')}")
            print(f"      Source: {prop.get('source')}")
            print(f"      Type: {prop.get('type')} {prop.get('number')}/{prop.get('year')}")
        
        elif msg_type == "proposition_update":
            prop = data.get("data", {})
            print(f"   🔄 Proposition Updated: {prop.get('title')}")
            print(f"      Status: {prop.get('status')}")
        
        elif msg_type == "system_status":
            print(f"   🔧 System Status: {data.get('status')}")
            if data.get("details"):
                print(f"      Details: {data.get('details')}")
        
        elif msg_type == "alert_configured":
            print(f"   🔔 Alert configured for query: '{data.get('query')}'")
            print(f"      Sources: {data.get('sources', 'all')}")
        
        elif msg_type == "pong":
            print("   🏓 Pong received")
        
        elif msg_type == "error":
            print(f"   ❌ Error: {data.get('message')}")
        
        else:
            print(f"   📄 Data: {json.dumps(data, indent=2)}")

async def main():
    """Main function"""
    print("🏛️ Monitor Legislativo WebSocket Client")
    print("Developed by: Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães")
    print("Organization: MackIntegridade")
    print("=" * 50)
    
    # Optional: Get authentication token
    token = None
    use_auth = input("Use authentication? (y/n): ").strip().lower()
    if use_auth == "y":
        token = input("Enter JWT token: ").strip()
    
    # Create and run client
    client = LegislativeMonitorClient(token=token)
    
    try:
        await client.connect()
    except KeyboardInterrupt:
        print("\n👋 Interrupted by user")
    except Exception as e:
        print(f"\n❌ Error: {e}")

if __name__ == "__main__":
    # Run the client
    asyncio.run(main())