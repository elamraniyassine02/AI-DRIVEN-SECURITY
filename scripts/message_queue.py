import argparse
import logging

import grpc
import message_queue_pb2
import message_queue_pb2_grpc

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def run_server(host, port):
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    message_queue_pb2_grpc.add_MessageQueueServicer_to_server(MessageQueueServicer(), server)
    server.add_insecure_port(f"{host}:{port}")
    server.start()
    logger.info(f"Server started. Listening on {host}:{port}")
    server.wait_for_termination()

def run_worker(host, port, worker_id, worker_type):
    channel = grpc.insecure_channel(f"{host}:{port}")
    stub = message_queue_pb2_grpc.MessageQueueStub(channel)
    logger.info(f"Worker {worker_id} ({worker_type}) connected to server at {host}:{port}")
    
    while True:
        messages = stub.GetMessages(message_queue_pb2.WorkerInfo(worker_id=worker_id, worker_type=worker_type))
        for message in messages.messages:
            logger.info(f"Worker {worker_id} ({worker_type}) received message: {message.data}")
            # Process the message based on worker type
            # ...
            
def run_admin(host, port):
    channel = grpc.insecure_channel(f"{host}:{port}")
    stub = message_queue_pb2_grpc.MessageQueueStub(channel)
    
    while True:
        command = input("Enter command (status/exit): ")
        if command == 'status':
            request = message_queue_pb2.EmptyRequest()
            response = stub.GetStatus(request)
            print(f"Server status: {response.status}")
            print(f"Connected workers: {response.workers}")
        elif command == 'exit':
            break
        else:
            print("Invalid command")
            
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', action='store_true', help='Run as server')
    parser.add_argument('--worker', action='store_true', help='Run as worker')
    parser.add_argument('--admin', action='store_true', help='Run as admin')
    parser.add_argument('--worker-id', type=str, help='Worker ID')
    parser.add_argument('--worker-type', type=str, help='Worker type')
    parser.add_argument('--host', type=str, default='192.168.100.55', help='Server host')  
    parser.add_argument('--port', type=int, default=5555, help='Server port')
    args = parser.parse_args()

    if args.server:
        run_server(args.host, args.port)
    elif args.worker:
        run_worker(args.host, args.port, args.worker_id, args.worker_type)
    elif args.admin:
        run_admin(args.host, args.port)
    else:
        parser.print_help()