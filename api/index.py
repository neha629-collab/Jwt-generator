import os
import sys
sys.path.append(os.path.dirname(__file__))

from flask import Flask, request, jsonify
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import requests
import jwt
import json
import base64
from google.protobuf import json_format

import freefire_pb2

app = Flask(__name__)

AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV = b'6oyZDr22E3ychjM%'

OAUTH_URLS = [
    'https://ffmconnect.live.gop.garenanow.com/api/v2/oauth/guest/token:grant',
    'https://100067.connect.garena.com/oauth/guest/token/grant',
]

MAJOR_LOGIN_URLS = [
    'https://loginbp.ggwhitehawk.com/MajorLogin',
    'https://loginbp.ggpolarbear.com/MajorLogin',
    'https://loginbp.ggblueshark.com/MajorLogin',
]

OAUTH_USER_AGENTS = [
    'GarenaMSDK/4.0.19P10(I2404 ;Android 15;en;US;)',
    'GarenaMSDK/4.0.19P9(SM-M526B ;Android 13;pt;BR;)',
]

MAJOR_LOGIN_USER_AGENTS = [
    'Dalvik/2.1.0 (Linux; U; Android 15; I2404 Build/AP3A.240905.015.A2_V000L1)',
    'Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)',
]

RELEASE_VERSIONS = ['OB54', 'OB53', 'OB51']


def encrypt_message(plaintext: bytes) -> bytes:
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    return cipher.encrypt(pad(plaintext, AES.block_size))


def decode_nickname(raw_nickname):
    if not raw_nickname:
        return None
    try:
        padded = raw_nickname + '=' * (-len(raw_nickname) % 4)
        return base64.b64decode(padded).decode('utf-8', errors='ignore')
    except Exception:
        return raw_nickname


def extract_account_level(decoded_token, login_response_dict):
    for key in ['AccountLevel', 'account_level', 'accountLevel', 'level', 'Level']:
        if decoded_token.get(key) not in [None, '']:
            return decoded_token.get(key)
        if login_response_dict.get(key) not in [None, '']:
            return login_response_dict.get(key)
    return None


def do_oauth(uid: str, password: str):
    last_error = 'OAuth failed'
    for oauth_url in OAUTH_URLS:
        for ua in OAUTH_USER_AGENTS:
            payload_json = {
                'uid': int(uid),
                'password': password,
                'response_type': 'token',
                'client_type': 2,
                'client_secret': '2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3',
                'client_id': 100067,
            }
            try:
                r = requests.post(
                    oauth_url,
                    json=payload_json,
                    headers={
                        'User-Agent': ua,
                        'Accept': 'application/json',
                        'Content-Type': 'application/json; charset=utf-8',
                    },
                    timeout=15
                )
                if r.status_code != 200:
                    last_error = f'OAuth returned {r.status_code} from {oauth_url}'
                    continue
                data = r.json()
                if 'data' in data and isinstance(data['data'], dict):
                    data = data['data']
                access_token = data.get('access_token')
                open_id = data.get('open_id')
                if access_token and open_id:
                    return {'access_token': access_token, 'open_id': open_id}, None
            except Exception as e:
                last_error = str(e)
    return None, last_error


def fetch_open_id_from_access_token(access_token: str):
    try:
        r = requests.get(
            'https://prod-api.reward.ff.garena.com/redemption/api/auth/inspect_token/',
            headers={
                'accept': 'application/json, text/plain, */*',
                'access-token': access_token,
                'user-agent': 'Mozilla/5.0'
            },
            timeout=15
        )
        if r.status_code != 200:
            return None, 'Failed to inspect access token'
        uid_value = r.json().get('uid')
        if not uid_value:
            return None, 'UID not found from access token'

        r2 = requests.post(
            'https://shop2game.com/api/auth/player_id_login',
            headers={
                'Accept': 'application/json, text/plain, */*',
                'Content-Type': 'application/json',
                'Origin': 'https://shop2game.com',
                'Referer': 'https://shop2game.com/',
                'User-Agent': 'Mozilla/5.0',
            },
            json={'app_id': 100067, 'login_id': str(uid_value)},
            timeout=15
        )
        if r2.status_code != 200:
            return None, 'Failed to fetch open_id'
        open_id = r2.json().get('open_id')
        if not open_id:
            return None, 'open_id not found'
        return {'uid': str(uid_value), 'open_id': open_id}, None
    except Exception as e:
        return None, str(e)


def access_token_from_eat(eat_token: str):
    try:
        parts = eat_token.split('.')
        if len(parts) < 2:
            return None, 'Invalid eat_token format'
        padded = parts[1] + '=' * (-len(parts[1]) % 4)
        decoded = json.loads(base64.urlsafe_b64decode(padded.encode()).decode())
        access_token = decoded.get('access_token') or decoded.get('token')
        open_id = decoded.get('open_id') or decoded.get('external_id')
        uid = decoded.get('uid') or decoded.get('external_uid')
        if not access_token:
            return None, 'No access_token found in eat_token'
        return {
            'access_token': access_token,
            'open_id': open_id,
            'uid': str(uid) if uid else ''
        }, None
    except Exception as e:
        return None, str(e)


def generate_jwt(access_token: str, open_id: str):
    last_error = 'MajorLogin failed'

    login_req = freefire_pb2.LoginReq()
    login_req.open_id = open_id
    login_req.open_id_type = '4'
    login_req.login_token = access_token
    login_req.orign_platform_type = '4'
    encrypted_payload = encrypt_message(login_req.SerializeToString())

    for url in MAJOR_LOGIN_URLS:
        for ua in MAJOR_LOGIN_USER_AGENTS:
            for release_version in RELEASE_VERSIONS:
                try:
                    r = requests.post(
                        url,
                        data=encrypted_payload,
                        headers={
                            'User-Agent': ua,
                            'Connection': 'Keep-Alive',
                            'Accept-Encoding': 'gzip',
                            'Content-Type': 'application/octet-stream',
                            'Expect': '100-continue',
                            'X-Unity-Version': '2018.4.11f1',
                            'X-GA': 'v1 1',
                            'ReleaseVersion': release_version,
                        },
                        timeout=15
                    )
                    if r.status_code != 200:
                        last_error = f'MajorLogin returned {r.status_code} from {url}'
                        continue

                    login_res = freefire_pb2.LoginRes()
                    login_res.ParseFromString(r.content)
                    login_data = json.loads(json_format.MessageToJson(login_res))
                    token_value = login_data.get('token')

                    if not token_value:
                        if login_data.get('queueInfo', {}).get('allow') is True:
                            last_error = 'Upstream protection/queue response returned instead of JWT token'
                        else:
                            last_error = f'No token in response from {url}'
                        continue

                    try:
                        decoded_token = jwt.decode(token_value, options={'verify_signature': False})
                    except Exception:
                        decoded_token = {}

                    return {
                        'success': True,
                        'status': 'success',
                        'uid': str(decoded_token.get('external_uid', '')),
                        'region': decoded_token.get('lock_region') or login_data.get('lockRegion') or '',
                        'token': token_value,
                        'token_access': access_token,
                        'account_id': str(decoded_token.get('account_id', '')),
                        'AccountLevel': extract_account_level(decoded_token, login_data),
                        'open_id': open_id,
                        'account_name': decode_nickname(decoded_token.get('nickname')),
                        'server_url': login_data.get('serverUrl', '')
                    }, None
                except Exception as e:
                    last_error = str(e)

    return None, last_error


@app.route('/api/public/token', methods=['GET'])
@app.route('/token', methods=['GET'])
def token_route():
    guest_uid = request.args.get('guest_uid') or request.args.get('uid')
    guest_password = request.args.get('guest_password') or request.args.get('password')
    access_token = request.args.get('access_token')
    eat_token = request.args.get('eat_token')
    open_id = request.args.get('open_id')

    if guest_uid and guest_password:
        oauth_data, err = do_oauth(guest_uid, guest_password)
        if err:
            return jsonify({'success': False, 'message': err}), 500
        result, err = generate_jwt(oauth_data['access_token'], oauth_data['open_id'])
        if err:
            return jsonify({'success': False, 'message': err}), 502
        return jsonify(result), 200

    if access_token:
        final_open_id = open_id
        if not final_open_id:
            info, err = fetch_open_id_from_access_token(access_token)
            if err:
                return jsonify({'success': False, 'message': err}), 502
            final_open_id = info['open_id']
        result, err = generate_jwt(access_token, final_open_id)
        if err:
            return jsonify({'success': False, 'message': err}), 502
        return jsonify(result), 200

    if eat_token:
        eat_data, err = access_token_from_eat(eat_token)
        if err:
            return jsonify({'success': False, 'message': err}), 400
        final_access_token = eat_data['access_token']
        final_open_id = eat_data.get('open_id')
        if not final_open_id:
            info, err = fetch_open_id_from_access_token(final_access_token)
            if err:
                return jsonify({'success': False, 'message': err}), 502
            final_open_id = info['open_id']
        result, err = generate_jwt(final_access_token, final_open_id)
        if err:
            return jsonify({'success': False, 'message': err}), 502
        return jsonify(result), 200

    return jsonify({
        'success': False,
        'message': 'Provide guest_uid & guest_password OR access_token OR eat_token'
    }), 400


@app.route('/api/public/health', methods=['GET'])
def health():
    return jsonify({'ok': True, 'service': 'ff-jwt-api'})


app = app
