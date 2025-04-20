# slack.py
import secrets
import base64
import json
import hashlib
import httpx
from fastapi import Request, HTTPException
from fastapi.responses import HTMLResponse
import asyncio
from redis_client import add_key_value_redis, get_value_redis, delete_key_redis
from integrations.integration_item import IntegrationItem

APP_ID = '11170790'
CLIENT_ID = 'b73a4f9a-0a2e-4de6-a118-5934c0362139'
CLIENT_SECRET = 'e51fcdb3-2678-484b-9b25-8e6abe1dae69'

REDIRECT_URI = 'http://localhost:8000/integrations/hubspot/oauth2callback'

scopes = [
   'crm.objects.contacts.read',
    'crm.objects.contacts.write',
    'crm.schemas.contacts.read',
    'oauth',
    'account-info.security.read'
]

authorization_base_url = 'https://app-na2.hubspot.com/oauth/authorize'
encoded_client_id_secret = base64.b64encode(f'{CLIENT_ID}:{CLIENT_SECRET}'.encode()).decode()

async def authorize_hubspot(user_id, org_id):
    state_data = {
        'state': secrets.token_urlsafe(32),
        'user_id': user_id,
        'org_id': org_id
    }
    encoded_state = base64.urlsafe_b64encode(json.dumps(state_data).encode('utf-8')).decode('utf-8')

    code_verifier = secrets.token_urlsafe(32)
    m = hashlib.sha256()
    m.update(code_verifier.encode('utf-8'))
    code_challenge = base64.urlsafe_b64encode(m.digest()).decode('utf-8').replace('=', '')

    auth_url = (f'{authorization_base_url}?client_id={CLIENT_ID}'
                f'&response_type=code&owner=user'
                f'&redirect_uri={REDIRECT_URI}'
                f'&state={encoded_state}'
                f'&code_challenge={code_challenge}'
                f'&code_challenge_method=S256'
                f'&scope={"%20".join(scopes)}')

    await asyncio.gather(
        add_key_value_redis(f'hubspot_state:{org_id}:{user_id}', json.dumps(state_data), expire=600),
        add_key_value_redis(f'hubspot_verifier:{org_id}:{user_id}', code_verifier, expire=600),
    )

    return auth_url


async def oauth2callback_hubspot(request: Request):
    print("request",request.query_params)
    if request.query_params.get('error'):
        raise HTTPException(status_code=400, detail=request.query_params.get('error_description'))
    
    code = request.query_params.get('code')
    encoded_state = request.query_params.get('state')
    
    try:
        state_data = json.loads(base64.urlsafe_b64decode(encoded_state).decode('utf-8'))
    except (TypeError, ValueError, json.JSONDecodeError) as e:
        raise HTTPException(status_code=400, detail=f'Invalid state parameter: {str(e)}')

    user_id = state_data.get('user_id')
    org_id = state_data.get('org_id')

    saved_state, code_verifier = await asyncio.gather(
        get_value_redis(f'hubspot_state:{org_id}:{user_id}'),
        get_value_redis(f'hubspot_verifier:{org_id}:{user_id}'),
    )

    if not saved_state:
        raise HTTPException(status_code=400, detail='State not found in storage')
    
    try:
        saved_state_data = json.loads(saved_state)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail='Invalid stored state format')

    if state_data.get('state') != saved_state_data.get('state'):
        raise HTTPException(status_code=400, detail='State mismatch')

    async with httpx.AsyncClient() as client:
        token_response = await client.post(
            'https://api.hubapi.com/oauth/v1/token',
            data={
                'grant_type': 'authorization_code',
                'client_id': CLIENT_ID,
                'client_secret': CLIENT_SECRET,  # ✅ Important
                'redirect_uri': REDIRECT_URI,
                'code': code,
                'code_verifier': code_verifier,
            },
            headers={
                'Content-Type': 'application/x-www-form-urlencoded',
            }
        )

    if token_response.status_code != 200:
        raise HTTPException(
            status_code=token_response.status_code,
            detail=f'Token exchange failed: {token_response.text}'
        )

    await asyncio.gather(
        delete_key_redis(f'hubspot_state:{org_id}:{user_id}'),
        delete_key_redis(f'hubspot_verifier:{org_id}:{user_id}'),
    )

    credentials = token_response.json()
    await add_key_value_redis(
        f'hubspot_credentials:{org_id}:{user_id}',
        json.dumps(credentials),
        expire=credentials.get('expires_in', 3600) - 60
    )

    return HTMLResponse(content="""
        <html>
            <script>
                window.close();
            </script>
        </html>
    """)


async def get_hubspot_credentials(user_id, org_id):
    credentials = await get_value_redis(f'hubspot_credentials:{org_id}:{user_id}')
    if not credentials:
        raise HTTPException(status_code=404, detail='No credentials found')
    
    try:
        credentials_dict = json.loads(credentials)
    except json.JSONDecodeError:
        raise HTTPException(status_code=500, detail='Invalid credential format')
    
    # await delete_key_redis(f'hubspot_credentials:{org_id}:{user_id}')
    return credentials_dict


async def fetch_items(access_token: str, url: str, aggregated_response: list, client: httpx.AsyncClient, offset=None):
    params = {'offset': offset} if offset is not None else {}
    headers = {'Authorization': f'Bearer {access_token}'}
    
    try:
        response = await client.get(url, headers=headers, params=params)
        response.raise_for_status()
        
        data = response.json()
        results = data.get('bases', [])
        aggregated_response.extend(results)
        
        new_offset = data.get('offset')
        if new_offset is not None:
            await fetch_items(access_token, url, aggregated_response, client, new_offset)
            
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=e.response.status_code, detail=f"API request failed: {str(e)}")


def create_integration_item_metadata_object(
    response_json: dict, item_type: str, parent_id=None, parent_name=None
) -> IntegrationItem:
    return IntegrationItem(
        id=f"{response_json.get('id')}_{item_type}",
        name=response_json.get('name'),
        type=item_type,
        parent_id=f"{parent_id}_Base" if parent_id else None,
        parent_path_or_name=parent_name,
    )


async def get_items_hubspot(credentials):
    if isinstance(credentials, str):
        print("credentials:", credentials)
        try:
            credentials = json.loads(credentials)
        except json.JSONDecodeError:
            raise HTTPException(status_code=400, detail='Invalid credentials format')

    list_of_integration_item_metadata = []
    list_of_responses = []
    
    async with httpx.AsyncClient() as client:
        try:
            await fetch_items(
                credentials.get('access_token'),
                'https://api.hubapi.com/crm/v3/objects/contacts',   # ✅ Change URL here
                list_of_responses,
                client
            )
            
            for response in list_of_responses:
                list_of_integration_item_metadata.append(
                    create_integration_item_metadata_object(response, 'Contact')  # ✅ Type: Contact
                )
                    
        except httpx.HTTPError as e:
            raise HTTPException(status_code=500, detail=f"HubSpot API error: {str(e)}")

    return list_of_integration_item_metadata
