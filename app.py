import os
import sys

# Add garudaa directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'garudaa'))

# Import the actual backend app
from garuda_backend import app

if __name__ == '__main__':
    # Get port from environment variable (Railway provides this)
    port = int(os.environ.get('PORT', 5000))
    print(f"🚀 Starting GARUDA Backend on port {port}")
    print(f"🌐 CORS enabled for all origins")
    # Bind to 0.0.0.0 to accept connections from outside
    app.run(host='0.0.0.0', port=port, debug=False)
