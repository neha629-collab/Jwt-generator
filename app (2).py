from flask import Flask, request, jsonify, render_template_string
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii
import requests
import my_pb2
import output_pb2
import jwt
from datetime import datetime
from urllib.parse import urlparse, parse_qs, unquote

app = Flask(__name__)

CREDIT = "t.me/Abdur081"
TEAM = "Abdur API"
BASE_URL = "https://jwt-generator-five.vercel.app"

AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV = b'6oyZDr22E3ychjM%'


def add_credit(payload):
    """Add owner credit to every API response."""
    if isinstance(payload, dict):
        payload.setdefault("credit", CREDIT)
        payload.setdefault("team", TEAM)
    return payload


@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    return response


def encrypt_message(plaintext):
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    padded_message = pad(plaintext, AES.block_size)
    return cipher.encrypt(padded_message)


def extract_eat_token(value):
    """Accept raw EAT token or a full redirect URL containing ?eat=."""
    if not value:
        return None
    value = unquote(value.strip())
    if "eat=" in value:
        try:
            parsed = urlparse(value)
            token = parse_qs(parsed.query).get("eat", [None])[0]
            if token:
                return token.strip()
        except Exception:
            pass
        # Fallback for malformed pasted URLs
        try:
            return value.split("eat=", 1)[1].split("&", 1)[0].strip()
        except Exception:
            return value
    return value


def guest_to_access(uid, password):
    oauth_url = "https://100067.connect.garena.com/oauth/guest/token/grant"
    payload = {
        'uid': uid,
        'password': password,
        'response_type': "token",
        'client_type': "2",
        'client_secret': "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        'client_id': "100067"
    }
    headers = {
        'User-Agent': "GarenaMSDK/4.0.19P9(SM-M526B ;Android 13;pt;BR;)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip"
    }
    oauth_response = requests.post(oauth_url, data=payload, headers=headers, timeout=15)
    if oauth_response.status_code != 200:
        try:
            return None, oauth_response.json(), oauth_response.status_code
        except ValueError:
            return None, {"status": "error", "message": oauth_response.text}, oauth_response.status_code
    try:
        oauth_data = oauth_response.json()
    except ValueError:
        return None, {"status": "error", "message": "Invalid JSON response from OAuth service"}, 500
    if 'access_token' not in oauth_data or 'open_id' not in oauth_data:
        return None, {"status": "error", "message": "OAuth response missing access_token or open_id", "oauth_response": oauth_data}, 500
    return oauth_data, None, 200


def eat_to_access(eat_token):
    """
    Convert EAT token to Garena access_token.
    EAT conversion is handled by the public converter API because Garena's browser OAuth
    callback requires the short-lived EAT value from the user's logged-in session.
    """
    eat_token = extract_eat_token(eat_token)
    if not eat_token:
        return None, {"status": "error", "message": "Missing eat_token"}, 400

    try:
        res = requests.get("https://freefire.us.cc/api", params={"eat": eat_token}, timeout=20)
        data = res.json()
    except Exception as e:
        return None, {"status": "error", "message": f"EAT to access conversion failed: {str(e)}"}, 500

    access_token = data.get("access_token") or data.get("token_access")
    if res.status_code != 200 or not access_token:
        return None, {"status": "error", "message": data.get("message", "Invalid or expired EAT token"), "upstream": data}, res.status_code if res.status_code >= 400 else 400

    return {
        "access_token": access_token,
        "open_id": data.get("open_id"),
        "uid": data.get("account_id") or data.get("uid"),
        "nickname": data.get("nickname"),
        "region": data.get("region")
    }, None, 200


def fetch_open_id(access_token):
    try:
        uid_url = "https://prod-api.reward.ff.garena.com/redemption/api/auth/inspect_token/"
        uid_headers = {
            "authority": "prod-api.reward.ff.garena.com",
            "method": "GET",
            "path": "/redemption/api/auth/inspect_token/",
            "scheme": "https",
            "accept": "application/json, text/plain, */*",
            "accept-encoding": "gzip, deflate, br",
            "accept-language": "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7",
            "access-token": access_token,
            "origin": "https://reward.ff.garena.com",
            "referer": "https://reward.ff.garena.com/",
            "sec-ch-ua": '"Not.A/Brand";v="99", "Chromium";v="124"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Android"',
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-site",
            "user-agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
        }

        uid_res = requests.get(uid_url, headers=uid_headers, timeout=15)
        uid_data = uid_res.json()
        uid = uid_data.get("uid")

        if not uid:
            return None, "Failed to extract UID"

        openid_url = "https://shop2game.com/api/auth/player_id_login"
        openid_headers = {
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "ar-MA,ar;q=0.9,en-US;q=0.8,en;q=0.7,ar-AE;q=0.6,fr-FR;q=0.5,fr;q=0.4",
            "Connection": "keep-alive",
            "Content-Type": "application/json",
            "Origin": "https://shop2game.com",
            "Referer": "https://shop2game.com/",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "User-Agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Mobile Safari/537.36",
            "sec-ch-ua-mobile": "?1",
            "sec-ch-ua-platform": '"Android"'
        }
        payload = {
            "app_id": 100067,
            "login_id": str(uid)
        }

        openid_res = requests.post(openid_url, headers=openid_headers, json=payload, timeout=15)
        openid_data = openid_res.json()
        open_id = openid_data.get("open_id")

        if not open_id:
            return None, "Failed to extract open_id"

        return open_id, None

    except Exception as e:
        return None, f"Exception occurred: {str(e)}"


def access_to_jwt(access_token, open_id=None):
    if not access_token:
        return None, {"status": "error", "message": "missing access_token"}, 400

    if not open_id:
        open_id, error = fetch_open_id(access_token)
        if error:
            # Fallback for social/EAT access tokens when local open_id extraction is blocked.
            try:
                upstream = requests.get("https://freefire.us.cc/api", params={"access": access_token}, timeout=35)
                data = upstream.json()
                if upstream.status_code == 200 and data.get("token"):
                    result = normalize_jwt_response(data, access_token=data.get("access_token") or access_token)
                    return result, None, 200
                return None, {"status": "error", "message": error, "upstream": data}, 400
            except Exception:
                return None, {"status": "error", "message": error}, 400

    platforms = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]

    for platform_type in platforms:
        game_data = my_pb2.GameData()
        game_data.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        game_data.game_name = "free fire"
        game_data.game_version = 1
        game_data.version_code = "1.118.1"
        game_data.os_info = "Android OS 13 / API-33"
        game_data.device_type = "Handheld"
        game_data.network_provider = "Verizon Wireless"
        game_data.connection_type = "WIFI"
        game_data.screen_width = 1280
        game_data.screen_height = 960
        game_data.dpi = "240"
        game_data.cpu_info = "ARMv7 VFPv3 NEON VMH | 2400 | 4"
        game_data.total_ram = 5951
        game_data.gpu_name = "Adreno (TM) 640"
        game_data.gpu_version = "OpenGL ES 3.0"
        game_data.user_id = "Google|74b585a9-0268-4ad3-8f36-ef41d2e53610"
        game_data.ip_address = "172.190.111.97"
        game_data.language = "en"
        game_data.open_id = open_id
        game_data.access_token = access_token
        game_data.platform_type = platform_type
        game_data.field_99 = str(platform_type)
        game_data.field_100 = str(platform_type)

        serialized_data = game_data.SerializeToString()
        encrypted_data = encrypt_message(serialized_data)
        hex_encrypted_data = binascii.hexlify(encrypted_data).decode('utf-8')

        url = "https://loginbp.ggblueshark.com/MajorLogin"
        headers = {
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 13; SM-M526B Build/TP1A.220624.014)",
            "Connection": "Keep-Alive",
            "Accept-Encoding": "gzip",
            "Content-Type": "application/octet-stream",
            "Expect": "100-continue",
            "X-Unity-Version": "2018.4.11f1",
            "X-GA": "v1 1",
            "ReleaseVersion": "OB54"
        }
        edata = bytes.fromhex(hex_encrypted_data)

        try:
            response = requests.post(url, data=edata, headers=headers, verify=False, timeout=15)

            if response.status_code == 200:
                data_dict = None
                try:
                    example_msg = output_pb2.Garena_420()
                    example_msg.ParseFromString(response.content)
                    data_dict = {field.name: getattr(example_msg, field.name)
                                 for field in example_msg.DESCRIPTOR.fields
                                 if field.name not in ["binary", "binary_data", "Garena420"]}
                except Exception:
                    try:
                        data_dict = response.json()
                    except ValueError:
                        continue

                if data_dict and "token" in data_dict:
                    token_value = data_dict["token"]
                    result = normalize_jwt_response(data_dict, access_token=access_token, open_id=open_id, token_value=token_value)
                    return result, None, 200
        except requests.RequestException:
            continue

    return None, {"status": "error", "message": "No valid platform found"}, 400


def normalize_jwt_response(data, access_token=None, open_id=None, token_value=None):
    token_value = token_value or data.get("token")
    decoded_token = {}
    if token_value:
        try:
            decoded_token = jwt.decode(token_value, options={"verify_signature": False})
        except Exception:
            decoded_token = {}

    uid = decoded_token.get("account_id") or data.get("uid") or data.get("account_id")
    nickname = decoded_token.get("nickname") or data.get("nickname") or data.get("account_name")
    region = decoded_token.get("lock_region") or data.get("region")
    open_id = open_id or decoded_token.get("external_id") or data.get("open_id")
    access_token = access_token or data.get("access_token") or data.get("token_access")

    return add_credit({
        "region": region,
        "status": "success",
        "team": TEAM,
        "credit": CREDIT,
        "token": token_value,
        "token_access": access_token,
        "access_token": access_token,
        "uid": uid,
        "account_id": uid,
        "account_name": nickname,
        "nickname": nickname,
        "open_id": open_id,
        "platform": decoded_token.get("external_type") or data.get("platform")
    })


def make_json(payload, status=200):
    return jsonify(add_credit(payload)), status


@app.route('/', methods=['GET'])
def home():
    html = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>FF JWT API - Abdur</title>
  <style>
    :root{--bg:#080b18;--card:#11182b;--muted:#9aa8c7;--text:#eef4ff;--brand:#5eead4;--brand2:#8b5cf6;--danger:#fb7185;--border:rgba(255,255,255,.12)}
    *{box-sizing:border-box} body{margin:0;font-family:Inter,system-ui,Segoe UI,Roboto,Arial,sans-serif;background:radial-gradient(circle at 10% 10%,rgba(139,92,246,.26),transparent 32%),radial-gradient(circle at 90% 0%,rgba(94,234,212,.18),transparent 30%),var(--bg);color:var(--text);min-height:100vh}
    .wrap{max-width:1050px;margin:0 auto;padding:34px 16px 60px}.hero{text-align:center;padding:34px 0}.badge{display:inline-flex;gap:8px;align-items:center;border:1px solid var(--border);background:rgba(255,255,255,.06);padding:8px 13px;border-radius:999px;color:var(--brand);font-weight:700}.pulse{width:9px;height:9px;border-radius:50%;background:#22c55e;box-shadow:0 0 0 7px rgba(34,197,94,.12)}
    h1{font-size:clamp(34px,7vw,68px);line-height:.98;margin:18px 0 10px;letter-spacing:-.05em}.grad{background:linear-gradient(90deg,var(--brand),#60a5fa,var(--brand2));-webkit-background-clip:text;background-clip:text;color:transparent}.sub{color:var(--muted);font-size:18px;margin:0 auto;max-width:680px;line-height:1.6}.grid{display:grid;grid-template-columns:1.1fr .9fr;gap:18px;margin-top:24px}@media(max-width:850px){.grid{grid-template-columns:1fr}}
    .card{background:linear-gradient(180deg,rgba(255,255,255,.08),rgba(255,255,255,.04));border:1px solid var(--border);border-radius:24px;padding:22px;box-shadow:0 20px 60px rgba(0,0,0,.35);backdrop-filter:blur(12px)}.card h2{margin:0 0 16px;font-size:22px}.tabs{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px}.tab{border:1px solid var(--border);background:#0d1324;color:var(--muted);padding:10px 12px;border-radius:13px;cursor:pointer;font-weight:700}.tab.active{background:linear-gradient(90deg,var(--brand2),#2563eb);color:white;border-color:transparent}
    label{display:block;color:#cbd5e1;font-size:13px;font-weight:700;margin:12px 0 7px}input{width:100%;background:#080d1d;color:var(--text);border:1px solid var(--border);border-radius:14px;padding:13px 14px;outline:none}input:focus{border-color:var(--brand);box-shadow:0 0 0 4px rgba(94,234,212,.1)}button.primary{width:100%;border:0;background:linear-gradient(90deg,var(--brand),#60a5fa,var(--brand2));color:#041018;font-weight:900;padding:14px 16px;border-radius:15px;margin-top:16px;cursor:pointer;font-size:15px}.endpoint{background:#07101f;border:1px solid var(--border);border-radius:14px;padding:12px;margin:10px 0;color:#dbeafe;overflow:auto}.endpoint code{white-space:nowrap}.muted{color:var(--muted)}pre{white-space:pre-wrap;word-break:break-word;background:#050814;border:1px solid var(--border);border-radius:16px;padding:14px;min-height:180px;color:#d1fae5}.foot{text-align:center;color:var(--muted);margin-top:24px}.foot a{color:var(--brand)}.hidden{display:none}.small{font-size:13px}.copy{float:right;background:rgba(255,255,255,.08);color:white;border:1px solid var(--border);border-radius:10px;padding:6px 9px;cursor:pointer}
  </style>
</head>
<body>
  <div class="wrap">
    <section class="hero">
      <div class="badge"><span class="pulse"></span> FF JWT API LIVE</div>
      <h1><span class="grad">Free Fire JWT</span><br>Generator API</h1>
      <p class="sub">Generate JWT using Guest UID + Password, Access Token, or EAT token. API credit: <b>{{ credit }}</b></p>
    </section>
    <div class="grid">
      <div class="card">
        <h2>Generate Token</h2>
        <div class="tabs">
          <button class="tab active" data-tab="guest">Guest UID + Password</button>
          <button class="tab" data-tab="access">Access Token</button>
          <button class="tab" data-tab="eat">EAT Token</button>
        </div>
        <form id="guest" class="form">
          <label>Guest UID</label><input name="guest_uid" placeholder="5365694386">
          <label>Guest Password</label><input name="guest_password" placeholder="guest password">
        </form>
        <form id="access" class="form hidden">
          <label>Access Token</label><input name="access_token" placeholder="Paste access token">
        </form>
        <form id="eat" class="form hidden">
          <label>EAT Token or Full URL</label><input name="eat_token" placeholder="https://ticket.kiosgamer.co.id/?eat=... or raw EAT">
        </form>
        <button class="primary" id="go">Generate JWT</button>
        <p class="small muted">Base URL: {{ base_url }}</p>
      </div>
      <div class="card">
        <button class="copy" onclick="copyResult()">Copy</button>
        <h2>API Response</h2>
        <pre id="out">Response will appear here...</pre>
      </div>
    </div>
    <div class="card" style="margin-top:18px">
      <h2>Endpoints</h2>
      <div class="endpoint"><code>GET {{ base_url }}/api/public/token?guest_uid=&lt;uid&gt;&guest_password=&lt;password&gt;</code></div>
      <div class="endpoint"><code>GET {{ base_url }}/api/public/token?access_token=&lt;access_token&gt;</code></div>
      <div class="endpoint"><code>GET {{ base_url }}/api/public/token?eat_token=&lt;eat_token_or_url&gt;</code></div>
      <div class="endpoint"><code>GET {{ base_url }}/api/public/access-token?eat_token=&lt;eat_token_or_url&gt;</code></div>
      <p class="muted">Response includes: <code>region, status, team, credit, token, token_access, uid</code></p>
    </div>
    <div class="foot">Created by <a href="https://t.me/Abdur081" target="_blank">{{ credit }}</a></div>
  </div>
<script>
let active='guest';
document.querySelectorAll('.tab').forEach(btn=>btn.onclick=()=>{active=btn.dataset.tab;document.querySelectorAll('.tab').forEach(b=>b.classList.remove('active'));btn.classList.add('active');document.querySelectorAll('.form').forEach(f=>f.classList.add('hidden'));document.getElementById(active).classList.remove('hidden')});
document.getElementById('go').onclick=async()=>{const form=document.getElementById(active);const p=new URLSearchParams(new FormData(form));const out=document.getElementById('out');out.textContent='Loading...';try{const r=await fetch('/api/public/token?'+p.toString());const j=await r.json();out.textContent=JSON.stringify(j,null,2)}catch(e){out.textContent=JSON.stringify({status:'error',message:e.message,credit:'{{ credit }}'},null,2)}};
function copyResult(){navigator.clipboard.writeText(document.getElementById('out').textContent)}
</script>
</body>
</html>
    """
    return render_template_string(html, base_url=BASE_URL, credit=CREDIT)


@app.route('/api/public/token', methods=['GET', 'OPTIONS'])
def public_token():
    if request.method == 'OPTIONS':
        return "", 204

    guest_uid = request.args.get('guest_uid') or request.args.get('uid')
    guest_password = request.args.get('guest_password') or request.args.get('password')
    access_token = request.args.get('access_token') or request.args.get('access')
    eat_token = request.args.get('eat_token') or request.args.get('eat') or request.args.get('eatjwt')

    if guest_uid and guest_password:
        oauth_data, error, status = guest_to_access(guest_uid, guest_password)
        if error:
            return make_json(error, status)
        result, error, status = access_to_jwt(oauth_data['access_token'], oauth_data.get('open_id'))
        if error:
            return make_json(error, status)
        result['token_access'] = oauth_data['access_token']
        result['access_token'] = oauth_data['access_token']
        result['open_id'] = oauth_data.get('open_id') or result.get('open_id')
        return make_json(result, status)

    if eat_token:
        access_data, error, status = eat_to_access(eat_token)
        if error:
            return make_json(error, status)
        result, error, status = access_to_jwt(access_data['access_token'], access_data.get('open_id'))
        if error:
            return make_json(error, status)
        # Preserve useful EAT conversion metadata when available
        result['token_access'] = access_data['access_token']
        result['access_token'] = access_data['access_token']
        result['uid'] = result.get('uid') or access_data.get('uid')
        result['account_id'] = result.get('account_id') or access_data.get('uid')
        result['nickname'] = result.get('nickname') or access_data.get('nickname')
        result['region'] = result.get('region') or access_data.get('region')
        return make_json(result, status)

    if access_token:
        result, error, status = access_to_jwt(access_token)
        if error:
            return make_json(error, status)
        return make_json(result, status)

    return make_json({
        "status": "error",
        "message": "Use guest_uid+guest_password OR access_token OR eat_token",
        "endpoints": {
            "guest": f"{BASE_URL}/api/public/token?guest_uid=<uid>&guest_password=<password>",
            "access": f"{BASE_URL}/api/public/token?access_token=<token>",
            "eat": f"{BASE_URL}/api/public/token?eat_token=<eat>",
            "eat_to_access": f"{BASE_URL}/api/public/access-token?eat_token=<eat>"
        }
    }, 400)


@app.route('/api/public/access-token', methods=['GET', 'OPTIONS'])
@app.route('/access-token', methods=['GET', 'OPTIONS'])
def public_access_token():
    if request.method == 'OPTIONS':
        return "", 204
    eat_token = request.args.get('eat_token') or request.args.get('eat')
    if not eat_token:
        return make_json({"status": "error", "message": "Missing eat_token"}, 400)
    access_data, error, status = eat_to_access(eat_token)
    if error:
        return make_json(error, status)
    return make_json({
        "status": "success",
        "access_token": access_data.get('access_token'),
        "token_access": access_data.get('access_token'),
        "uid": access_data.get('uid'),
        "account_id": access_data.get('uid'),
        "nickname": access_data.get('nickname'),
        "region": access_data.get('region')
    }, 200)


@app.route('/access-jwt', methods=['GET'])
def majorlogin_jwt():
    access_token = request.args.get('access_token')
    provided_open_id = request.args.get('open_id')
    result, error, status = access_to_jwt(access_token, provided_open_id)
    if error:
        return make_json(error, status)
    return make_json(result, status)


@app.route('/token', methods=['GET'])
def oauth_guest():
    """Backward compatible old endpoint: /token?uid=&password= or /token?access_token= or /token?eat_token="""
    return public_token()


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=1080, debug=False)
