"""Local Windows/Linux entry point. Docker uses api.app directly."""
import os
from common import config  # load .env before reading runtime options
import uvicorn

if __name__ == '__main__':
    uvicorn.run('api.app:app', host=os.getenv('SOC_BIND_HOST', '127.0.0.1'), port=int(os.getenv('SOC_PORT', '8100')), workers=1)
