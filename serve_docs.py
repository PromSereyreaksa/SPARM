#!/usr/bin/env python3
"""
Simple HTTP server to serve SPARM documentation locally
You can then use localxpose to expose it externally
"""

import http.server
import socketserver
import os
import sys
import webbrowser
from pathlib import Path

class DocumentationHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(Path(__file__).parent / "docs"), **kwargs)
    
    def end_headers(self):
        self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
        self.send_header('Pragma', 'no-cache')
        self.send_header('Expires', '0')
        super().end_headers()

def main():
    PORT = 8080
    
    print("🚀 SPARM Documentation Server")
    print("=" * 50)
    
    # Check if docs directory exists
    docs_dir = Path(__file__).parent / "docs"
    if not docs_dir.exists():
        print("❌ Documentation directory not found!")
        print("Please ensure 'docs' folder exists with sparm_documentation.html")
        sys.exit(1)
    
    # Check if documentation file exists
    doc_file = docs_dir / "sparm_documentation.html"
    if not doc_file.exists():
        print("❌ Documentation file not found!")
        print("Please ensure 'sparm_documentation.html' exists in docs folder")
        sys.exit(1)
    
    try:
        with socketserver.TCPServer(("", PORT), DocumentationHandler) as httpd:
            print(f"✅ Server started successfully!")
            print(f"📍 Local URL: http://localhost:{PORT}/sparm_documentation.html")
            print(f"🌐 Network URL: http://0.0.0.0:{PORT}/sparm_documentation.html")
            print("\n" + "=" * 50)
            print("🔗 To expose externally using localxpose:")
            print(f"   loclx tunnel http --to localhost:{PORT}")
            print("=" * 50)
            print("\n⚡ Server is running... Press Ctrl+C to stop")
            
            # Try to open browser automatically
            try:
                webbrowser.open(f'http://localhost:{PORT}/sparm_documentation.html')
                print("🌐 Documentation opened in browser")
            except:
                pass
                
            httpd.serve_forever()
            
    except KeyboardInterrupt:
        print("\n\n👋 Server stopped by user")
    except OSError as e:
        if "Address already in use" in str(e):
            print(f"❌ Port {PORT} is already in use!")
            print("Try a different port or stop the existing service")
        else:
            print(f"❌ Error starting server: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

if __name__ == "__main__":
    main()