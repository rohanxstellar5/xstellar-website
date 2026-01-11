# oauth_google.py
"""
Google OAuth Flow for User Authentication
Allows users to sign up/login with Google account (reduces friction)
"""

from dotenv import load_dotenv
load_dotenv()

from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import RedirectResponse, HTMLResponse
import requests
import os
import logging
from urllib.parse import urlencode
import secrets
from jwt_auth import create_access_token
from database import (
    create_client_with_google,
    get_client_by_google_id,
    get_client_by_email,
    link_google_to_client,
    get_client_by_id
)

logger = logging.getLogger(__name__)

router = APIRouter()

# Google OAuth Configuration
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')
GOOGLE_REDIRECT_URI = os.getenv(
    'GOOGLE_REDIRECT_URI',
    'https://insta-dm-qualifier.onrender.com/auth/google/callback'
)

# Google OAuth endpoints
GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v2/userinfo"

# Scopes for Google OAuth
GOOGLE_SCOPES = [
    'openid',
    'https://www.googleapis.com/auth/userinfo.email',
    'https://www.googleapis.com/auth/userinfo.profile'
]


@router.get("/auth/google")
async def start_google_oauth(request: Request):
    """
    Step 1: Redirect user to Google OAuth
    """
    if not GOOGLE_CLIENT_ID:
        logger.error("❌ GOOGLE_CLIENT_ID not configured")
        return HTMLResponse("""
            <h1>Google OAuth Not Configured</h1>
            <p>Please configure GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in environment variables.</p>
        """, status_code=500)
    
    # Generate state for CSRF protection (store in session or return in redirect)
    state = secrets.token_urlsafe(32)
    
    # Build Google OAuth URL
    params = {
        'client_id': GOOGLE_CLIENT_ID,
        'redirect_uri': GOOGLE_REDIRECT_URI,
        'response_type': 'code',
        'scope': ' '.join(GOOGLE_SCOPES),
        'access_type': 'online',
        'prompt': 'select_account',  # Force account selection
        'state': state
    }
    
    oauth_url = f"{GOOGLE_AUTH_URL}?{urlencode(params)}"
    
    logger.info(f"🔗 Starting Google OAuth flow")
    logger.info(f"🔗 Redirect URI: {GOOGLE_REDIRECT_URI}")
    
    return RedirectResponse(url=oauth_url)


@router.get("/auth/google/callback")
async def google_oauth_callback(request: Request):
    """
    Step 2: Google redirects back with code
    Exchange code for user info and create/login user
    """
    code = request.query_params.get('code')
    state = request.query_params.get('state')
    error = request.query_params.get('error')
    error_description = request.query_params.get('error_description')
    
    # Handle OAuth errors
    if error:
        logger.error(f"Google OAuth error: {error} - {error_description}")
        return HTMLResponse(f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Authentication Failed - xstellar.systems</title>
                <style>
                    body {{ font-family: -apple-system, BlinkMacSystemFont, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; background: #0a0a0a; color: #fff; }}
                    .error {{ color: #ef4444; }}
                    .btn {{ display: inline-block; background: #3b82f6; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; margin-top: 20px; }}
                </style>
            </head>
            <body>
                <h1 class="error">❌ Google Authentication Failed</h1>
                <p><strong>Error:</strong> {error}</p>
                <p><strong>Description:</strong> {error_description or 'Unknown error'}</p>
                <a href="https://xstellar.systems/signup.html" class="btn">Try Again</a>
            </body>
            </html>
        """, status_code=400)
    
    if not code:
        raise HTTPException(status_code=400, detail="Missing authorization code")
    
    # Exchange code for access token
    token_data = {
        'code': code,
        'client_id': GOOGLE_CLIENT_ID,
        'client_secret': GOOGLE_CLIENT_SECRET,
        'redirect_uri': GOOGLE_REDIRECT_URI,
        'grant_type': 'authorization_code'
    }
    
    logger.info(f"🔄 Exchanging Google OAuth code for token...")
    
    token_response = requests.post(GOOGLE_TOKEN_URL, data=token_data)
    
    if token_response.status_code != 200:
        error_data = token_response.json()
        logger.error(f"Token exchange failed: {error_data}")
        return HTMLResponse(f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Authentication Failed - xstellar.systems</title>
                <style>
                    body {{ font-family: -apple-system, BlinkMacSystemFont, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; background: #0a0a0a; color: #fff; }}
                    .error {{ color: #ef4444; }}
                    .btn {{ display: inline-block; background: #3b82f6; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; margin-top: 20px; }}
                </style>
            </head>
            <body>
                <h1 class="error">❌ Token Exchange Failed</h1>
                <p><strong>Error:</strong> {error_data.get('error', 'Unknown error')}</p>
                <a href="https://xstellar.systems/signup.html" class="btn">Try Again</a>
            </body>
            </html>
        """, status_code=400)
    
    token_json = token_response.json()
    access_token = token_json.get('access_token')
    
    # Get user info from Google
    userinfo_response = requests.get(
        GOOGLE_USERINFO_URL,
        headers={'Authorization': f'Bearer {access_token}'}
    )
    
    if userinfo_response.status_code != 200:
        logger.error(f"Failed to get user info: {userinfo_response.text}")
        return HTMLResponse("""
            <h1>❌ Failed to Get User Information</h1>
            <p>Could not retrieve your Google account information.</p>
        """, status_code=400)
    
    user_info = userinfo_response.json()
    google_id = user_info.get('id')
    email = user_info.get('email')
    name = user_info.get('name', '')
    picture = user_info.get('picture', '')
    
    if not google_id or not email:
        logger.error(f"Incomplete user info from Google: {user_info}")
        return HTMLResponse("""
            <h1>❌ Incomplete User Information</h1>
            <p>Google did not provide required user information.</p>
        """, status_code=400)
    
    logger.info(f"✅ Got Google user info: {email} ({google_id})")
    
    # Check if user exists with this Google ID
    existing_client = get_client_by_google_id(google_id)
    
    if existing_client:
        # User already exists - log them in
        client_id = existing_client['id']
        logger.info(f"✅ Existing user logged in via Google: {email}")
    else:
        # Check if user exists with same email (link accounts)
        existing_email_client = get_client_by_email(email)
        
        if existing_email_client:
            # Link Google account to existing email account
            client_id = existing_email_client['id']
            success = link_google_to_client(client_id, google_id)
            
            if success:
                logger.info(f"✅ Linked Google account to existing email account: {email}")
            else:
                logger.warning(f"⚠️ Failed to link Google account (may already be linked to another account)")
                return HTMLResponse(f"""
                    <!DOCTYPE html>
                    <html>
                    <head>
                        <title>Account Link Failed - xstellar.systems</title>
                        <style>
                            body {{ font-family: -apple-system, BlinkMacSystemFont, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; background: #0a0a0a; color: #fff; }}
                            .error {{ color: #ef4444; }}
                            .btn {{ display: inline-block; background: #3b82f6; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; margin-top: 20px; }}
                        </style>
                    </head>
                    <body>
                        <h1 class="error">❌ Account Link Failed</h1>
                        <p>This Google account is already linked to another account, or there was an error linking accounts.</p>
                        <a href="https://xstellar.systems/login.html" class="btn">Go to Login</a>
                    </body>
                    </html>
                """, status_code=400)
        else:
            # New user - create account
            # Extract business name from name or use email domain
            business_name = name.split()[0] if name else email.split('@')[0]
            
            client_id = create_client_with_google(
                google_id=google_id,
                email=email,
                name=name,
                business_name=business_name
            )
            
            if not client_id:
                logger.error(f"Failed to create new Google OAuth client: {email}")
                return HTMLResponse("""
                    <h1>❌ Account Creation Failed</h1>
                    <p>Could not create your account. Please try again or contact support.</p>
                """, status_code=500)
            
            logger.info(f"✅ New user created via Google OAuth: {email} (client_id: {client_id})")
    
    # Redirect to dashboard with client_id
    # Create JWT token so frontend can call protected endpoints immediately
    client = get_client_by_id(client_id)
    token = create_access_token(
        {
            "client_id": client_id,
            "tenant_id": client.get("tenant_id") if client else None,
            "email": client.get("email") if client else email,
        }
    )

    # IMPORTANT: localStorage is per-domain. If we write localStorage from this callback
    # (insta-dm-qualifier.onrender.com), xstellar.systems cannot read it.
    # So we pass the JWT to xstellar.systems in the URL and let dashboard.html persist it.
    dashboard_params = {
        "client_id": client_id,
        "oauth": "google",
        "token": token,
        "email": email,
        "business": (client.get("business_name") if client else ""),
    }
    dashboard_url = f"https://xstellar.systems/dashboard.html?{urlencode(dashboard_params)}"

    return RedirectResponse(url=dashboard_url, status_code=302)






