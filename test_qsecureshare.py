from qsecureshare import SecureShare
import time
import threading

def main():
    # Initialize SecureShare instance
    share = SecureShare()

    # Start the server in a separate thread
    print("Starting server...")
    server_thread = threading.Thread(target=share.http_start, args=(8080,))
    server_thread.daemon = True  # Allow program to exit even if the server is running
    server_thread.start()

    # Test sending a secure text message
    print("Sending a secure text message...")
    share.share_text("localhost", 8080, "Hello, secure world!", key=123)

    # Test sending a secure file
    print("Sending a secure file...")
    with open("test_file.txt", "w") as f:
        f.write("This is a test file for QSecureShare!")
    share.share_file("localhost", 8080, "test_file.txt", key=123)

    # Allow time for server to process requests
    time.sleep(2)

    # Verify received data
    print("Received files are saved in the 'received_data' directory.")

    # Stop the server
    share.stop_server()

if __name__ == "__main__":
    main()
