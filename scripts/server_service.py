import argparse
import json
import logging
import os
import sys
from concurrent import futures

import grpc
import message_queue_pb2
import message_queue_pb2_grpc

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ServerService(message_queue_pb2_grpc.MessageQueueServicer):
    def __init__(self, config):
        self.config = config
        self.message_queue = []
        
    def SendMessage(self, request, context):
        self.message_queue.append(request)
        return message_queue_pb2.MessageResponse(status="SUCCESS")

    def GetMessages(self, request, context):
        messages = self.message_queue
        self.message_queue = []
        return message_queue_pb2.MessageList(messages=messages)

def serve(config):
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    message_queue_pb2_grpc.add_MessageQueueServicer_to_server(ServerService(config), server)
    server.add_insecure_port(f"{config['server']['host']}:{config['server']['port']}")
    server.start()
    logger.info("Server started. Listening on %s:%s", config['server']['host'], config['server']['port'])
    server.wait_for_termination()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', type=str, default='config/server_config.json', help='Path to the configuration file')
    args = parser.parse_args()

    with open(args.config) as f:
        config = json.load(f)

    serve(config)