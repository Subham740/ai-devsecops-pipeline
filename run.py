from app import create_app
import os

app = create_app()

if __name__ == "__main__":
    # Use the standard app port by default; override with PORT when needed.
    port = int(os.getenv("PORT", 5000))
    host = os.getenv("HOST", "0.0.0.0")
    debug = os.getenv("FLASK_DEBUG", "True").lower() in ("true", "1", "t")

    print(f"Starting Flask app on {host}:{port} (debug={debug})")
    app.run(host=host, port=port, debug=debug)
