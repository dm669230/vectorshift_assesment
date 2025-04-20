# slack.py
import secrets
import base64
import json
import hashlib
import httpx
import requests
from fastapi import Request, HTTPException
from fastapi.responses import HTMLResponse
import asyncio
from redis_client import add_key_value_redis, get_value_redis, delete_key_redis
from integrations.integration_item import IntegrationItem

APP_ID = '11170790'
CLIENT_ID = 'b73a4f9a-0a2e-4de6-a118-5934c0362139'
CLIENT_SECRET = 'e51fcdb3-2678-484b-9b25-8e6abe1dae69'

REDIRECT_URI = 'http://localhost:8000/integrations/hubspot/oauth2callback'
# STATE = str(uuid.uuid4())  # Optional for security

scopes = [
    "cms.functions.read",
    "cms.knowledge_base.articles.publish",
    "automation",
    "cms.knowledge_base.articles.read",
    "cms.knowledge_base.settings.read",
    "collector.graphql_schema.read",
    "communication_preferences.read",
    "oauth",
    "cms.membership.access_groups.read",
    "conversations.read",
    "conversations.custom_channels.read",
    "cms.performance.read",
    "files.ui_hidden.read",
    "business_units_view.read",
    "marketing.campaigns.read",
    "marketing.campaigns.revenue.read",
    "automation.sequences.enrollments.write",
    "automation.sequences.read",
    "communication_preferences.statuses.batch.read",
    "cms.domains.read"
]

# params = {
#     "client_id": CLIENT_ID,
#     "redirect_uri": REDIRECT_URI,
#     "scope": " ".join(scopes),
#     "response_type": "code",
#     "state": STATE
# }
authorization_url = f'https://app-na2.hubspot.com/oauth/authorize?client_id={CLIENT_ID}&response_type=code&owner=user&redirect_uri=http%3A%2F%2Flocalhost%3A8000%2Fintegrations%2Fhubspot%2Foauth2callback'
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

    auth_url = f'{authorization_url}&state={encoded_state}&code_challenge={code_challenge}&code_challenge_method=S256&scope={" ".join(scopes)}'
    await asyncio.gather(
        add_key_value_redis(f'hubspot_state:{org_id}:{user_id}', json.dumps(state_data), expire=600),
        add_key_value_redis(f'hubspot_verifier:{org_id}:{user_id}', code_verifier, expire=600),
    )

    return auth_url


async def oauth2callback_hubspot(request: Request):
    if request.query_params.get('error'):
        raise HTTPException(status_code=400, detail=request.query_params.get('error_description'))
    code = request.query_params.get('code')
    encoded_state = request.query_params.get('state')
    state_data = json.loads(base64.urlsafe_b64decode(encoded_state).decode('utf-8'))

    original_state = state_data.get('state')
    user_id = state_data.get('user_id')
    org_id = state_data.get('org_id')

    saved_state, code_verifier = await asyncio.gather(
        get_value_redis(f'hubspot_state:{org_id}:{user_id}'),
        get_value_redis(f'hubspot_verifier:{org_id}:{user_id}'),
    )

    if not saved_state or original_state != json.loads(saved_state).get('state'):
        raise HTTPException(status_code=400, detail='State does not match.')

    async with httpx.AsyncClient() as client:
        response, _, _ = await asyncio.gather(
            client.post(
                'https://app-na2.hubspot.com/oauth/token',
                data={
                    'grant_type': 'authorization_code',
                    'code': code,
                    'redirect_uri': REDIRECT_URI,
                    'client_id': CLIENT_ID,
                    'code_verifier': code_verifier.decode('utf-8'),
                },
                headers={
                    'Authorization': f'Basic {encoded_client_id_secret}',
                    'Content-Type': 'application/x-www-form-urlencoded',
                }
            ),
            delete_key_redis(f'hubspot_state:{org_id}:{user_id}'),
            delete_key_redis(f'hubspot_verifier:{org_id}:{user_id}'),
        )

    await add_key_value_redis(f'hubspot_credentials:{org_id}:{user_id}', json.dumps(response.json()), expire=600)
    
    close_window_script = """
    <html>
        <script>
            window.close();
        </script>
    </html>
    """
    return HTMLResponse(content=close_window_script)


async def get_hubspot_credentials(user_id, org_id):
    credentials = await get_value_redis(f'hubspot_credentials:{org_id}:{user_id}')
    if not credentials:
        raise HTTPException(status_code=400, detail='No credentials found')
    credentials = json.loads(credentials)
    await delete_key_redis(f'hubspot_credentials:{org_id}:{user_id}')

    return credentials

def create_integration_item_metadata_object(
    response_json: str, item_type: str, parent_id=None, parent_name=None
) -> IntegrationItem:
    parent_id = None if parent_id is None else parent_id + '_Base'
    integration_item_metadata = IntegrationItem(
        id=response_json.get('id', None) + '_' + item_type,
        name=response_json.get('name', None),
        type=item_type,
        parent_id=parent_id,
        parent_path_or_name=parent_name,
    )

    return integration_item_metadata

async def fetch_items(access_token: str, url: str, aggregated_response: list, client: httpx.AsyncClient, offset=None):
    params = {'offset': offset} if offset is not None else {}
    headers = {'Authorization': f'Bearer {access_token}'}
    response = await client.get(url, headers=headers, params=params)
    if response.status_code == 200:
        results = response.json().get('bases', [])
        aggregated_response.extend(results)
        new_offset = response.json().get('offset')
        if new_offset is not None:
            await fetch_items(access_token, url, aggregated_response, client, new_offset)


async def get_items_hubspot(credentials):
    list_of_integration_item_metadata = []
    list_of_responses = []
    async with httpx.AsyncClient() as client:
        await fetch_items(credentials.get('access_token'), 'https://api.app-na2.hubspot.com/v0/meta/bases', list_of_responses, client)
        for response in list_of_responses:
            list_of_integration_item_metadata.append(
                create_integration_item_metadata_object(response, 'Base')
            )
            tables_url = f'https://api.app-na2.hubspot.com/v0/meta/bases/{response.get("id")}/tables'
            tables_response = await client.get(
                tables_url,
                headers={'Authorization': f'Bearer {credentials.get("access_token")}'},
            )
            if tables_response.status_code == 200:
                tables_data = tables_response.json()
                for table in tables_data.get('tables', []):
                    list_of_integration_item_metadata.append(
                        create_integration_item_metadata_object(
                            table,
                            'Table',
                            response.get('id'),
                            response.get('name'),
                        )
                    )
    return list_of_integration_item_metadata