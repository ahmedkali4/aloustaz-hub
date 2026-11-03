import sys
import os

# Ensure parent directory is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from werkzeug.middleware.proxy_fix import ProxyFix
from app import app

# 1. Enforce HTTPS and trust Vercel Reverse Proxy (Stops ERR_TOO_MANY_REDIRECTS)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
app.config['PREFERRED_URL_SCHEME'] = 'https'

# 2. Normalize Vercel rewrite paths
class VercelRouteMiddleware:
    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app

    def __call__(self, environ, start_response):
        # Force HTTPS scheme in WSGI environ
        environ['wsgi.url_scheme'] = 'https'
        
        # Check actual requested path from Vercel headers
        invoke = environ.get('HTTP_X_INVOKE_PATH') or environ.get('HTTP_X_MATCHED_PATH')
        if invoke and not invoke.startswith('/api/index'):
            environ['PATH_INFO'] = invoke.split('?')[0]
        elif environ.get('PATH_INFO') in ('/api/index', '/api/index/', ''):
            environ['PATH_INFO'] = '/'

        return self.wsgi_app(environ, start_response)

app.wsgi_app = VercelRouteMiddleware(app.wsgi_app)
