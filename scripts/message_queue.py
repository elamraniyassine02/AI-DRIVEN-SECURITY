
import argparse
import json
import logging
import os
import sys
import time
import uuid
from concurrent import futures

import grpc
import zmq

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("logs/message_queue.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class MessageQueue:
    def __init__(self, host="0.0.0.0", port=5555):
        self.host = host
        self.port = port
        self.context = zmq.Context()
        self.socket = None
        self.workers = {}
        
    def start_server(self):
        os.makedirs("logs", exist_ok=True)
        logger.info(f"Starting message queue server on {self.host}:{self.port}")
        
        try:
            self.socket = self.context.socket(zmq.REP)
            self.socket.bind(f"tcp://{self.host}:{self.port}")
            logger.info("Message queue server started successfully")
            
            while True:
                # Wait for next request from client
                message = self.socket.recv_json()
                
                if "type" not in message:
                    response = {"status": "error", "message": "Invalid message format"}
                else:
                    message_type = message["type"]
                    
                    if message_type == "register":
                        response = self.handle_register(message)
                    elif message_type == "heartbeat":
                        response = self.handle_heartbeat(message)
                    elif message_type == "send_data":
                        response = self.handle_send_data(message)
                    elif message_type == "get_status":
                        response = self.handle_get_status(message)
                    else:
                        response = {"status": "error", "message": f"Unknown message type: {message_type}"}
                        
                # Send reply back to client
                self.socket.send_json(response)
                
        except Exception as e:
            logger.error(f"Error in message queue server: {e}")
            if self.socket:
                self.socket.close()
            self.context.term()
            
    def handle_register(self, message):
        if "worker_id" not in message or "worker_type" not in message:
            return {"status": "error", "message": "Missing worker_id or worker_type"}
            
        worker_id = message["worker_id"]
        worker_type = message["worker_type"]
        worker_host = message.get("host", "unknown")
        
        self.workers[worker_id] = {
            "id": worker_id,
            "type": worker_type,
            "host": worker_host,
            "last_heartbeat": time.time(),
            "status": "online"
        }
        
        logger.info(f"Worker registered: {worker_id} ({worker_type}) at {worker_host}")
        return {"status": "success", "message": f"Worker {worker_id} registered successfully"}
        
    def handle_heartbeat(self, message):
        if "worker_id" not in message:
            return {"status": "error", "message": "Missing worker_id"}
            
        worker_id = message["worker_id"]
        
        if worker_id not in self.workers:
            return {"status": "error", "message": f"Worker {worker_id} not registered"}
            
        self.workers[worker_id]["last_heartbeat"] = time.time()
        self.workers[worker_id]["status"] = "online"
        
        return {"status": "success", "message": f"Heartbeat received from {worker_id}"}
        
    def handle_send_data(self, message):
        if "worker_id" not in message or "data" not in message:
            return {"status": "error", "message": "Missing worker_id or data"}
            
        worker_id = message["worker_id"]
        data = message["data"]
        
        if worker_id not in self.workers:
            return {"status": "error", "message": f"Worker {worker_id} not registered"}
            
        # Process the data (in a real implementation, this would store the data or forward it)
        logger.info(f"Received data from {worker_id}: {json.dumps(data)[:100]}...")
        
        return {"status": "success", "message": f"Data received from {worker_id}"}
        
    def handle_get_status(self, message):
        # Check for workers that haven't sent a heartbeat in the last 60 seconds
        current_time = time.time()
        for worker_id, worker in list(self.workers.items()):
            if current_time - worker["last_heartbeat"] > 60:
                worker["status"] = "offline"
                
        return {
            "status": "success",
            "workers": self.workers
        }
        
    def stop(self):
        if self.socket:
            self.socket.close()
        self.context.term()
        logger.info("Message queue server stopped")

class MessageClient:
    def __init__(self, server_host, server_port=5555, worker_id=None, worker_type=None):
        self.server_host = server_host
        self.server_port = server_port
        self.worker_id = worker_id or str(uuid.uuid4())
        self.worker_type = worker_type or "generic"
        self.context = zmq.Context()
        self.socket = None
        
    def connect(self):
        logger.info(f"Connecting to message queue server at {self.server_host}:{self.server_port}")
        
        try:
            self.socket = self.context.socket(zmq.REQ)
            self.socket.connect(f"tcp://{self.server_host}:{self.server_port}")
            
            # Register with the server
            response = self.send_message({
                "type": "register",
                "worker_id": self.worker_id,
                "worker_type": self.worker_type,
                "host": os.uname().nodename
            })
            
            if response.get("status") == "success":
                logger.info("Connected to message queue server successfully")
                return True
            else:
                logger.error(f"Failed to register with message queue server: {response.get('message')}")
                return False
                
        except Exception as e:
            logger.error(f"Error connecting to message queue server: {e}")
            if self.socket:
                self.socket.close()
            return False
            
    def send_message(self, message):
        if not self.socket:
            logger.error("Not connected to message queue server")
            return {"status": "error", "message": "Not connected to server"}
            
        try:
            self.socket.send_json(message)
            response = self.socket.recv_json()
            return response
        except Exception as e:
            logger.error(f"Error sending message: {e}")
            return {"status": "error", "message": str(e)}
            
    def send_heartbeat(self):
        return self.send_message({
            "type": "heartbeat",
            "worker_id": self.worker_id
        })
        
    def send_data(self, data):
        return self.send_message({
            "type": "send_data",
            "worker_id": self.worker_id,
            "data": data
        })
        
    def get_status(self):
        return self.send_message({
            "type": "get_status"
        })
        
    def start_heartbeat_thread(self):
        def heartbeat_loop():
            while True:
                try:
                    response = self.send_heartbeat()
                    if response.get("status") != "success":
                        logger.warning(f"Heartbeat failed: {response.get('message')}")
                except Exception as e:
                    logger.error(f"Heartbeat error: {e}")
                time.sleep(30)
                
        executor = futures.ThreadPoolExecutor(max_workers=1)
        executor.submit(heartbeat_loop)
        
    def disconnect(self):
        if self.socket:
            self.socket.close()
        self.context.term()
        logger.info("Disconnected from message queue server")

def run_server_mode(host, port):
    os.makedirs("logs", exist_ok=True)
    server = MessageQueue(host, port)
    try:
        server.start_server()
    except KeyboardInterrupt:
        logger.info("Server shutting down...")
        server.stop()

def run_worker_mode(server_host, server_port, worker_id, worker_type):
    os.makedirs("logs", exist_ok=True)
    client = MessageClient(server_host, server_port, worker_id, worker_type)
    if client.connect():
        client.start_heartbeat_thread()
        
        # In a real implementation, the worker would do its work here
        # For demonstration purposes, we'll just sleep
        try:
            while True:
                time.sleep(60)
        except KeyboardInterrupt:
            logger.info("Worker shutting down...")
            client.disconnect()

def run_admin_mode(server_host, server_port):
    os.makedirs("logs", exist_ok=True)
    client = MessageClient(server_host, server_port, "admin", "admin")
    if client.connect():
        try:
            while True:
                command = input("Enter command (status/exit): ")
                if command == "status":
                    response = client.get_status()
                    if response.get("status") == "success":
                        workers = response.get("workers", {})
                        print(f"Connected workers: {len(workers)}")
                        for worker_id, worker in workers.items():
                            print(f"  {worker_id} ({worker['type']}): {worker['status']}")
                    else:
                        print(f"Error getting status: {response.get('message')}")
                elif command == "exit":
                    break
                else:
                    print("Unknown command")
        except KeyboardInterrupt:
            pass
        finally:
            client.disconnect()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Message Queue Service")
    parser.add_argument("--server", action="store_true", help="Run in server mode")
    parser.add_argument("--worker", action="store_true", help="Run in worker mode")
    parser.add_argument("--admin", action="store_true", help="Run in admin mode")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="Host to bind/connect to")
    parser.add_argument("--port", type=int, default=5555, help="Port to bind/connect to")
    parser.add_argument("--worker-id", type=str, help="Worker ID")
    parser.add_argument("--worker-type", type=str, help="Worker type")
    
    args = parser.parse_args()
    
    if args.server:
        run_server_mode(args.host, args.port)
    elif args.worker:
        if not args.worker_id or not args.worker_type:
            print("Worker ID and worker type must be specified in worker mode")
            sys.exit(1)
        run_worker_mode(args.host, args.port, args.worker_id, args.worker_type)
    elif args.admin:
        run_admin_mode(args.host, args.port)
    else:
        parser.print_help()