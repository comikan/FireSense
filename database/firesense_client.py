#!/usr/bin/env python3
"""
FireSense gRPC Client (Compact)
"""

import os
import logging
from typing import Optional, Generator
import grpc
import firesense_pb2
import firesense_pb2_grpc

class FireSenseClient:
    def __init__(self, server_addr: str = "localhost:50051"):
        self.channel = grpc.insecure_channel(server_addr)
        self.stub = firesense_pb2_grpc.FireSenseStub(self.channel)

    def upload_file(self, file_path: str, chunk_size: int = 1024*1024) -> str:
        def chunk_generator():
            file_id = os.path.basename(file_path)
            with open(file_path, 'rb') as f:
                while chunk := f.read(chunk_size):
                    yield firesense_pb2.FileChunk(
                        file_id=file_id,
                        content=chunk,
                        offset=f.tell() - len(chunk)
            yield firesense_pb2.FileChunk(file_id=file_id, is_last=True)
        
        response = self.stub.UploadFile(chunk_generator())
        return response.file_id

    def download_file(self, file_id: str, output_path: str):
        request = firesense_pb2.DownloadRequest(file_id=file_id)
        with open(output_path, 'wb') as f:
            for chunk in self.stub.DownloadFile(request):
                f.write(chunk.content)

    def list_files(self, prefix: str = "") -> list:
        response = self.stub.ListFiles(firesense_pb2.ListRequest(prefix=prefix))
        return [{"name": f.name, "size": f.size} for f in response.files]

if __name__ == "__main__":
    client = FireSenseClient()
    
    # Example usage
    file_id = client.upload_file("example.txt")
    print(f"Uploaded file ID: {file_id}")
    
    client.download_file(file_id, "downloaded.txt")
    print("Download complete")
    
    files = client.list_files()
    print("Files:", files)
