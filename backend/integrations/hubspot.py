import json
import httpx
import base64
import secrets
import asyncio
import requests
from fastapi.responses import HTMLResponse
from fastapi import HTTPException, Request
from integrations.integration_item import IntegrationItem
from redis_client import add_key_value_redis, get_value_redis, delete_key_redis

CLIENT_ID = 'c5da1ba4-5c00-4bee-b38f-5656a59ce351'
CLIENT_SECRET = '79469abd-6934-4638-bae4-31c7eacb9692'
SCOPE = 'crm.objects.contacts.write crm.schemas.contacts.write oauth crm.schemas.contacts.read crm.objects.contacts.read'
ENCODED_CLIENT_ID_SECRET = base64.b64encode(f'{CLIENT_ID}:{CLIENT_SECRET}'.encode()).decode()
REDIRECT_URI = 'http://localhost:8000/integrations/hubspot/oauth2callback'
AUTHORIZATION_URL = f'https://app-na2.hubspot.com/oauth/authorize?client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&scope={SCOPE}'

async def authorize_hubspot(user_id, org_id):
    state_data = {
        'state': secrets.token_urlsafe(32),
        'user_id': user_id,
        'org_id': org_id
    }
    encoded_state = json.dumps(state_data)
    await add_key_value_redis(f'hubspot_state:{org_id}:{user_id}', encoded_state, expire=600)

    return f'{AUTHORIZATION_URL}&state={encoded_state}&scope={SCOPE}'

async def oauth2callback_hubspot(request: Request):
    if request.query_params.get('error'):
        raise HTTPException(status_code=400, detail=request.query_params.get('error'))
    
    code = request.query_params.get('code')
    encoded_state = request.query_params.get('state')
    state_data = json.loads(encoded_state)

    original_state = state_data.get('state')
    user_id = state_data.get('user_id')
    org_id = state_data.get('org_id')

    saved_state = await get_value_redis(f'hubspot_state:{org_id}:{user_id}')

    if not saved_state or original_state != json.loads(saved_state).get('state'):
        raise HTTPException(status_code=400, detail='State does not match.')
    
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                'https://api.hubapi.com/oauth/v1/token',
                headers={
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Authorization': f'Basic {ENCODED_CLIENT_ID_SECRET}',
                },
                data={
                    'grant_type': 'authorization_code',
                    'code': code,
                    'redirect_uri': REDIRECT_URI,
                    'client_id': CLIENT_ID,
                    'client_secret': CLIENT_SECRET
                }
            )
            response.raise_for_status()
            token_data = response.json()
            print(f"Token data: {token_data}")
        except httpx.HTTPStatusError as e:
            print(f"HTTP error during token exchange: {e}")
            print(f"Status code: {e.response.status_code}")
            print(f"Response text: {e.response.text}")
            raise HTTPException(status_code=500, detail="Failed to exchange token") from e
        
        except Exception as e:
            print(f"An error occurred during token exchange: {e}")
            raise HTTPException(status_code=500, detail="Failed to exchange token 2") from e

    await asyncio.gather(
        add_key_value_redis(f'hubspot_credentials:{org_id}:{user_id}', json.dumps(token_data), expire=3600),
        delete_key_redis(f'hubspot_state:{org_id}:{user_id}'),
    )

    close_window_script = """
    <html>
        <script>
            window.close();
        </script>
    </html>
    """
    html_response = HTMLResponse(content=close_window_script)
    return html_response

async def get_hubspot_credentials(user_id, org_id):
    credentials = await get_value_redis(f'hubspot_credentials:{org_id}:{user_id}')
    if not credentials:
        raise HTTPException(status_code=400, detail='No credentials found.')
    credentials = json.loads(credentials)
    if not credentials:
        raise HTTPException(status_code=400, detail='No credentials found.')
    await delete_key_redis(f'hubspot_credentials:{org_id}:{user_id}')

    return credentials

async def create_integration_item_metadata_object(response_json):
    """Creates an IntegrationItem object from a HubSpot API response."""
    item_id = response_json.get('vid')
    name = response_json.get('properties', {}).get('firstname', {}).get('value', '') + ' ' + response_json.get('properties', {}).get('lastname', {}).get('value', '')
    # Extract email from identity-profiles
    email = ''
    for profile in response_json.get('identity-profiles', []):
        for identity in profile.get('identities', []):
            if identity.get('type') == 'EMAIL' and identity.get('is-primary'):
                email = identity.get('value')
                break
        if email:
            break
    
    object_type = 'contact'
    
    integration_item_metadata = IntegrationItem(
        id=item_id,
        name=name,
        email=email,
        type=object_type,
    )
    
    return integration_item_metadata

async def get_items_hubspot(credentials):
    credentials = json.loads(credentials)
    access_token = credentials.get('access_token')  
    response = requests.get(
        'https://api.hubapi.com/contacts/v1/lists/all/contacts/all',
        headers={
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json',
        },
    )
    print('response: ', response)
    # if response.status_code == 200:
    #     results = response.json().get('contacts', [])
    #     list_of_integration_item_metadata = []
    #     for result in results:
    #         integration_item = await create_integration_item_metadata_object(result)
    #         list_of_integration_item_metadata.append(integration_item)

    #     print(list_of_integration_item_metadata)
    #     return list_of_integration_item_metadata
    # else:
    #     raise HTTPException(status_code=response.status_code, detail="Failed to fetch items from HubSpot")
    return response.json() if response.status_code == 200 else response.text