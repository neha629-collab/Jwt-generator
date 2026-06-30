from flask import Flask, request, jsonify, send_file
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
VARY_HEADERS = [
    {},
    {'X-Forwarded-For': '8.8.8.8', 'X-Real-IP': '8.8.8.8'},
    {'X-Forwarded-For': '1.1.1.1', 'X-Real-IP': '1.1.1.1'},
]


def encrypt_message(plaintext: bytes) -> bytes:
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    padded_message = pad(plaintext, AES.block_size)
    return cipher.encrypt(padded_message)


def decode_nickname(raw_nickname):
    if not raw_nickname:
        return None
    try:
        padded = raw_nickname + '=' * (-len(raw_nickname) % 4)
        return base64.b64decode(padded).decode('utf-8', errors='ignore')
    except Exception:
        return raw_nickname


def extract_account_level(decoded_token, login_response_dict):
    possible_keys = [
        'AccountLevel', 'account_level', 'accountLevel', 'level', 'Level'
    ]
    for key in possible_keys:
        if key in decoded_token and decoded_token.get(key) not in [None, '']:
            return decoded_token.get(key)
        if key in login_response_dict and login_response_dict.get(key) not in [None, '']:
            return login_response_dict.get(key)
    return None


def fetch_open_id_from_access_token(access_token: str):
    inspect_urls = [
        'https://prod-api.reward.ff.garena.com/redemption/api/auth/inspect_token/',
    ]
    headers = {
        'accept': 'application/json, text/plain, */*',
        'access-token': access_token,
        'origin': 'https://reward.ff.garena.com',
        'referer': 'https://reward.ff.garena.com/',
        'user-agent': 'Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36'
    }

    uid_value = None
    for inspect_url in inspect_urls:
        try:
            r = requests.get(inspect_url, headers=headers, timeout=15)
            if r.status_code != 200:
                continue
            data = r.json()
            uid_value = data.get('uid')
            if uid_value:
                break
        except Exception:
            continue

    if not uid_value:
        return None, 'Failed to extract UID from access token'

    try:
        openid_url = 'https://shop2game.com/api/auth/player_id_login'
        openid_headers = {
            'Accept': 'application/json, text/plain, */*',
            'Content-Type': 'application/json',
            'Origin': 'https://shop2game.com',
            'Referer': 'https://shop2game.com/',
            'User-Agent': 'Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Mobile Safari/537.36'
        }
        payload = {
            'app_id': 100067,
            'login_id': str(uid_value)
        }
        r = requests.post(openid_url, headers=openid_headers, json=payload, timeout=15)
        if r.status_code != 200:
            return None, 'Failed to fetch open_id from shop2game'
        data = r.json()
        open_id = data.get('open_id')
        if not open_id:
            return None, 'open_id not found'
        return {'uid': str(uid_value), 'open_id': open_id}, None
    except Exception as e:
        return None, str(e)


def access_token_from_eat(eat_token: str):
    try:
        parts = eat_token.split('.')
        if len(parts) >= 2:
            payload_part = parts[1]
            padded = payload_part + '=' * (-len(payload_part) % 4)
            decoded = json.loads(base64.urlsafe_b64decode(padded.encode()).decode())
            access_token = decoded.get('access_token') or decoded.get('token')
            open_id = decoded.get('open_id') or decoded.get('external_id')
            uid = decoded.get('uid') or decoded.get('external_uid')
            if access_token:
                return {
                    'access_token': access_token,
                    'open_id': open_id,
                    'uid': str(uid) if uid else ''
                }, None
        return None, 'Unable to extract access_token from eat_token'
    except Exception as e:
        return None, str(e)


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
            payload_form = {
                'uid': uid,
                'password': password,
                'response_type': 'token',
                'client_type': '2',
                'client_secret': '2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3',
                'client_id': '100067',
            }
            variants = [
                ('json', payload_json, {
                    'User-Agent': ua,
                    'Accept': 'application/json',
                    'Content-Type': 'application/json; charset=utf-8',
                    'Connection': 'Keep-Alive',
                    'Accept-Encoding': 'gzip',
                }),
                ('form', payload_form, {
                    'User-Agent': ua,
                    'Connection': 'Keep-Alive',
                    'Accept-Encoding': 'gzip',
                }),
            ]
            for mode, payload, headers in variants:
                try:
                    if mode == 'json':
                        response = requests.post(oauth_url, json=payload, headers=headers, timeout=15)
                    else:
                        response = requests.post(oauth_url, data=payload, headers=headers, timeout=15)

                    if response.status_code != 200:
                        last_error = f'OAuth returned {response.status_code} from {oauth_url}'
                        continue

                    data = response.json()
                    if 'data' in data and isinstance(data['data'], dict):
                        data = data['data']

                    access_token = data.get('access_token')
                    open_id = data.get('open_id')
                    if access_token and open_id:
                        return {
                            'access_token': access_token,
                            'open_id': open_id,
                            'oauth_url': oauth_url,
                            'oauth_mode': mode,
                        }, None
                except Exception as e:
                    last_error = str(e)
    return None, last_error


def generate_jwt(access_token: str, open_id: str):
    last_error = 'MajorLogin failed'
    attempt_errors = []

    login_req = freefire_pb2.LoginReq()
    login_req.open_id = open_id
    login_req.open_id_type = '4'
    login_req.login_token = access_token
    login_req.orign_platform_type = '4'

    encrypted_payload = encrypt_message(login_req.SerializeToString())

    for url in MAJOR_LOGIN_URLS:
        for ua in MAJOR_LOGIN_USER_AGENTS:
            for release_version in RELEASE_VERSIONS:
                for extra_headers in VARY_HEADERS:
                    headers = {
                        'User-Agent': ua,
                        'Connection': 'Keep-Alive',
                        'Accept-Encoding': 'gzip',
                        'Content-Type': 'application/octet-stream',
                        'Expect': '100-continue',
                        'X-Unity-Version': '2018.4.11f1',
                        'X-GA': 'v1 1',
                        'ReleaseVersion': release_version,
                    }
                    headers.update(extra_headers)
                    try:
                        response = requests.post(url, data=encrypted_payload, headers=headers, timeout=15)
                        if response.status_code != 200:
                            last_error = f'MajorLogin returned {response.status_code} from {url}'
                            attempt_errors.append(last_error)
                            continue

                        login_res = freefire_pb2.LoginRes()
                        login_res.ParseFromString(response.content)
                        login_data = json.loads(json_format.MessageToJson(login_res))
                        token_value = login_data.get('token')
                        if not token_value:
                            last_error = f'No token in response from {url}'
                            attempt_errors.append(last_error)
                            continue

                        try:
                            decoded_token = jwt.decode(token_value, options={'verify_signature': False})
                        except Exception:
                            decoded_token = {}

                        account_level = extract_account_level(decoded_token, login_data)
                        account_name_raw = decoded_token.get('nickname')
                        account_name = decode_nickname(account_name_raw)

                        result = {
                            'success': True,
                            'uid': str(decoded_token.get('external_uid', '')),
                            'region': decoded_token.get('lock_region') or login_data.get('lockRegion') or '',
                            'token': token_value,
                            'token_access': access_token,
                            'account_id': str(decoded_token.get('account_id', '')),
                            'open_id': open_id,
                            'account_name': account_name,
                            'AccountLevel': account_level,
                            'server_url': login_data.get('serverUrl', ''),
                            'release_version': decoded_token.get('release_version', release_version),
                            'debug': {
                                'major_login_url': url,
                                'oauth_mode': None,
                                'payload_type': 'compact_loginreq',
                            }
                        }
                        return result, None
                    except Exception as e:
                        last_error = str(e)
                        attempt_errors.append(last_error)

    if attempt_errors:
        last_error = attempt_errors[-1]
    return None, last_error


@app.route('/', methods=['GET'])
def home():
    return send_file('index.html')


@app.route('/access-jwt', methods=['GET'])
def access_jwt():
    access_token = request.args.get('access_token')
    open_id = request.args.get('open_id')

    if not access_token or not open_id:
        return jsonify({'success': False, 'message': 'Missing access_token or open_id'}), 400

    result, error = generate_jwt(access_token, open_id)
    if error:
        return jsonify({'success': False, 'message': error}), 502

    return jsonify(result), 200


def format_public_response(result, team='arena'):
    return {
        'success': True,
        'status': 'success',
        'team': team,
        'uid': result.get('uid'),
        'region': result.get('region'),
        'token': result.get('token'),
        'token_access': result.get('token_access'),
        'account_id': result.get('account_id'),
        'AccountLevel': result.get('AccountLevel'),
        'open_id': result.get('open_id'),
        'account_name': result.get('account_name'),
        'server_url': result.get('server_url')
    }


@app.route('/token', methods=['GET'])
def token_route():
    uid = request.args.get('uid')
    password = request.args.get('password')

    if not uid or not password:
        return jsonify({'success': False, 'message': 'Missing uid or password'}), 400

    oauth_data, oauth_error = do_oauth(uid, password)
    if oauth_error:
        return jsonify({'success': False, 'message': oauth_error}), 500

    result, jwt_error = generate_jwt(oauth_data['access_token'], oauth_data['open_id'])
    if jwt_error:
        return jsonify({'success': False, 'message': jwt_error}), 502

    result['debug']['oauth_mode'] = oauth_data['oauth_mode']
    return jsonify(result), 200


@app.route('/api/public/token', methods=['GET'])
def public_token_route():
    guest_uid = request.args.get('guest_uid') or request.args.get('uid')
    guest_password = request.args.get('guest_password') or request.args.get('password')
    access_token = request.args.get('access_token')
    eat_token = request.args.get('eat_token')
    open_id = request.args.get('open_id')

    if guest_uid and guest_password:
        oauth_data, oauth_error = do_oauth(guest_uid, guest_password)
        if oauth_error:
            return jsonify({'success': False, 'message': oauth_error}), 500
        result, jwt_error = generate_jwt(oauth_data['access_token'], oauth_data['open_id'])
        if jwt_error:
            return jsonify({'success': False, 'message': jwt_error}), 502
        return jsonify(format_public_response(result)), 200

    if access_token:
        final_open_id = open_id
        uid_from_token = ''
        if not final_open_id:
            info, err = fetch_open_id_from_access_token(access_token)
            if err:
                return jsonify({'success': False, 'message': err}), 502
            final_open_id = info['open_id']
            uid_from_token = info['uid']
        result, jwt_error = generate_jwt(access_token, final_open_id)
        if jwt_error:
            return jsonify({'success': False, 'message': jwt_error}), 502
        if uid_from_token and not result.get('uid'):
            result['uid'] = uid_from_token
        return jsonify(format_public_response(result)), 200

    if eat_token:
        eat_data, eat_error = access_token_from_eat(eat_token)
        if eat_error:
            return jsonify({'success': False, 'message': eat_error}), 400
        final_access_token = eat_data.get('access_token')
        final_open_id = eat_data.get('open_id')
        uid_from_eat = eat_data.get('uid')
        if not final_access_token:
            return jsonify({'success': False, 'message': 'No access_token found in eat_token'}), 400
        if not final_open_id:
            info, err = fetch_open_id_from_access_token(final_access_token)
            if err:
                return jsonify({'success': False, 'message': err}), 502
            final_open_id = info['open_id']
            if not uid_from_eat:
                uid_from_eat = info['uid']
        result, jwt_error = generate_jwt(final_access_token, final_open_id)
        if jwt_error:
            return jsonify({'success': False, 'message': jwt_error}), 502
        if uid_from_eat and not result.get('uid'):
            result['uid'] = uid_from_eat
        return jsonify(format_public_response(result)), 200

    return jsonify({
        'success': False,
        'message': 'Provide guest_uid & guest_password OR access_token OR eat_token'
    }), 400


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=1080, debug=False)
