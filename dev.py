"""Start the local dev server (reads APP_PORT from .env)."""

import os

from dotenv import load_dotenv

load_dotenv()

if __name__ == "__main__":
    import uvicorn

    port = int(os.getenv("APP_PORT", "8001"))
    host = os.getenv("APP_HOST", "127.0.0.1")
    uvicorn.run("main:app", host=host, port=port, reload=True)
