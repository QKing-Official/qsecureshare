import http.server
import os
import socketserver
import threading

class SecureShare:
    def __init__(self):
        self.server = None
        self.received_data_dir = "received_data"
        os.makedirs(self.received_data_dir, exist_ok=True)

    def xor_encrypt(self, data, key):
        """Simple XOR encryption (not secure for real-world use)"""
        return bytes([b ^ key for b in data])

    def xor_decrypt(self, encrypted_data, key):
        """Decrypt using XOR (same operation as encryption)"""
        return self.xor_encrypt(encrypted_data, key)

    def share_text(self, address, port, text_data, key):
        """Send text data to another device securely over HTTP"""
        self._send_data(address, port, text_data.encode('utf-8'), key, "message.txt")

    def share_file(self, address, port, file_path, key):
        """Send a file to another device securely over HTTP"""
        with open(file_path, "rb") as file:
            file_data = file.read()
        self._send_data(address, port, file_data, key, file_path)

    def _send_data(self, address, port, data, key, filename):
        """Send data to a specified server and port"""
        encrypted_data = self.xor_encrypt(data, key)
        headers = {
            'Content-Type': 'application/octet-stream',
            'Content-Length': str(len(encrypted_data)),
            'Filename': filename
        }
        
        import http.client
        conn = http.client.HTTPConnection(address, port)
        conn.request("POST", "/", encrypted_data, headers)
        response = conn.getresponse()
        print("Response from server:", response.status, response.reason)
        conn.close()

    def http_start(self, port=8080):
        """Start the HTTP server"""
        handler = self._create_handler()
        self.server = socketserver.TCPServer(("", port), handler)
        self.server.share = self  # Assign the share instance to the server
        print(f"HTTP server running on http://localhost:{port}")
        try:
            self.server.serve_forever()
        except Exception as e:
            print(f"Error occurred while running server: {e}")

    def stop_server(self):
        """Stop the server"""
        if self.server:
            print("Stopping the server...")
            self.server.shutdown()
            self.server.server_close()

    def _create_handler(self):
        """Create the request handler for the HTTP server"""
        class SecureHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
            def do_POST(self):
                filename = self.headers['Filename']
                content_length = int(self.headers['Content-Length'])
                encrypted_data = self.rfile.read(content_length)

                # Access the shared 'share' instance from the server
                key = 123  # You should pass or define a more secure key in production

                # Decrypt the data
                decrypted_data = self.server.share.xor_decrypt(encrypted_data, key)

                # Save the decrypted data to a file
                filepath = os.path.join(self.server.share.received_data_dir, filename)
                with open(filepath, 'wb') as file:
                    file.write(decrypted_data)

                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(b"Data received and saved.")

        return SecureHTTPRequestHandler
