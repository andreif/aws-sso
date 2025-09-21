#!/usr/bin/python3
import re
import signal
import sys
import json
import threading
import time
import os
import pathlib
import subprocess
import socket
import configparser
import urllib.parse
import urllib.request
import urllib.error
import datetime as dt
from typing import Any, Optional

assert (_ := sys.version_info) > (3, 9), _

HOST = '0.0.0.0'
PORT = 4550
PID = os.getpid()

LOCK = threading.Lock()
SHUTDOWN = threading.Event()

OIDC_URL = 'https://oidc.{}.amazonaws.com'
PORTAL_URL = 'https://portal.sso.{}.amazonaws.com'

AWS_CONFIG: Optional[configparser.ConfigParser] = None
AWS_CONFIG_PATH = pathlib.Path.home() / '.aws/config'
SSO_SESSION: Optional[dict[str, Any]] = None


def _shutdown(*_):
    SHUTDOWN.set()


signal.signal(signal.SIGINT, _shutdown)
signal.signal(signal.SIGTERM, _shutdown)


def error(msg: str) -> None:
    print('Error:', msg, file=sys.stderr)
    sys.exit(1)


def load_config() -> configparser.ConfigParser:
    global AWS_CONFIG
    if AWS_CONFIG:
        return AWS_CONFIG
    elif AWS_CONFIG_PATH.exists():
        AWS_CONFIG = configparser.ConfigParser()
        AWS_CONFIG.read(AWS_CONFIG_PATH)
        return AWS_CONFIG
    else:
        raise error(f'File not found {AWS_CONFIG_PATH}')


def load_sso_config(name=None):
    name = name or os.getenv('AWS_SSO_SESSION')
    config = load_config()

    sessions: list[tuple[str, configparser.SectionProxy]] = [
        (s[12:].strip(), config[s])  # strip leading 'sso-session '
        for s in config.sections()
        if s.startswith('sso-session ')
    ]
    if not sessions:
        raise error(f'No [sso-session <name>] found in {AWS_CONFIG_PATH}')

    if name:
        for _name, section in sessions:
            if _name == name:
                chosen = (name, section)
                break
        else:
            raise error(
                f'Requested sso-session {name!r} not found. '
                f'Available: {[n for n, _ in sessions]}'
            )
    else:
        chosen = sessions[0]
        if len(sessions) > 1:
            print(f'Warning: multiple sso-sessions found, selecting {chosen[0]}')

    name, section = chosen
    return {'name': name, **section}


def post_json(url: str, payload: dict[str, Any]) -> dict[str, Any]:
    print(url)
    req = urllib.request.Request(
        url=url,
        data=json.dumps(payload).encode(),
        headers={'Content-Type': 'application/json'},
    )
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors='ignore')
        raise RuntimeError(f'HTTP {e.code} POST {url}: {body}')


def get_sso_session(create=False):
    print(get_sso_session)
    global SSO_SESSION
    if _ := SSO_SESSION:
        d = now() - dt.datetime.fromisoformat(_['issuedAt'])
        x = dt.timedelta(seconds=_['expiresIn'])
        if d > x:
            print(f'Session expired: {_["issuedAt"]} {_["expiresIn"]}')
            with LOCK:
                SSO_SESSION = None

        elif d > dt.timedelta(minutes=10):
            url = OIDC_URL.format(_['region']) + '/token'
            tok = post_json(url=url, payload={
                'grantType': 'refresh_token',
                'clientId': _['clientId'],
                'clientSecret': _['clientSecret'],
                'refreshToken': _['refreshToken'],
            })
            # print('ref', tok)
            with LOCK:
                SSO_SESSION = {**SSO_SESSION, **tok, 'issuedAt': (_ := now().isoformat())}
            update_accounts(session=SSO_SESSION)
            print('Session refreshed', _)
            return SSO_SESSION
        else:
            print('Session still valid, remaining', int((x - d).total_seconds()))
            if update_accounts(session=SSO_SESSION):
                return SSO_SESSION
            else:
                with LOCK:
                    SSO_SESSION = None
    if not create:
        return None

    print('New session')
    _ = load_sso_config()
    start_url = _['sso_start_url']
    region = _['sso_region']
    scopes: list[str] = _['sso_registration_scopes'].split()
    base = OIDC_URL.format(region)

    reg = post_json(f'{base}/client/register', {
        'clientName': 'aws-sso-python',
        'clientType': 'public',
        'scopes': scopes,
    })
    client_id = reg['clientId']
    client_secret = reg['clientSecret']

    dev = post_json(f'{base}/device_authorization', {
        'clientId': client_id,
        'clientSecret': client_secret,
        'startUrl': start_url,
    })

    print('Authorize:', dev['userCode'])
    os.system('open ' + dev['verificationUriComplete'])

    interval = dev['interval']
    expires_at = now() + dt.timedelta(seconds=dev['expiresIn'])

    # Poll /token until authorized or expired
    while now() < expires_at and not SHUTDOWN.is_set():
        try:
            tok = post_json(f'{base}/token', {
                'grantType': 'urn:ietf:params:oauth:grant-type:device_code',
                'deviceCode': dev['deviceCode'],
                'clientId': client_id,
                'clientSecret': client_secret,
                'scope': scopes,
            })
        except RuntimeError as e:
            msg = str(e)
            # Handle polling errors per RFC 8628 / service semantics
            if 'authorization_pending' in msg:
                time.sleep(interval)
                continue
            if 'slow_down' in msg:
                interval += 1
                time.sleep(interval)
                continue
            if 'expired_token' in msg or 'access_denied' in msg:
                raise error(msg)
            # Other HTTP errors
            raise error(msg)
        else:
            # print('tok', tok)
            with LOCK:
                SSO_SESSION = _ = {
                    **tok,
                    'issuedAt': now().isoformat(),
                    'region': region,
                    'startUrl': start_url,
                    'scopes': scopes,
                    'clientId': client_id,
                    'clientSecret': client_secret,
                    # 'deviceCode': dev['deviceCode'],
                }
            update_accounts(session=SSO_SESSION)
            return _

    raise error('Timed out waiting for authorization.')


def portal(path, token, region, **query):
    url = PORTAL_URL.format(region) + path
    if query:
        url += '?' + urllib.parse.urlencode(query, safe='-_.~')
    print(url)
    req = urllib.request.Request(
        url=url,
        headers={'Accept': 'application/json', 'x-amz-sso_bearer_token': token},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return False


def get_accounts(session=None):
    if not session:
        session = SSO_SESSION
    if _ := portal(
        path='/assignment/accounts',
        token=session['accessToken'],
        region=session['region'],
        max_result=100,
    ):
        assert not _['nextToken'], _
        # there is also emailAddress
        return {a['accountId']: a['accountName'] for a in _['accountList']}
    return None


def get_roles(account_id, session=None):
    if not session:
        session = get_sso_session(create=True)
    if _ := portal(
        path=f'/assignment/roles',
        token=session['accessToken'],
        region=session['region'],
        account_id=account_id,
        # next_token=...,
        max_result=100,
    ):
        assert not _['nextToken'], _
        roles = []
        for r in _['roleList']:
            assert account_id == r['accountId']
            roles.append(r['roleName'])
        return roles
    return None


def update_accounts(session):
    if accounts := get_accounts(session=SSO_SESSION):
        with LOCK:
            session['accounts'] = accounts
        return accounts
    return False


def get_role_session(account_id, role_name):
    if session := get_sso_session(create=True):
        if data := portal(
            path='/federation/credentials',
            token=session['accessToken'],
            region=session['region'],
            account_id=account_id,
            role_name=role_name,
        ):
            rc = data.get('roleCredentials') or {}
            if not rc:
                raise RuntimeError("No roleCredentials in response")
            # def _utc_iso(ms_since_epoch: int) -> str:
            #     # AWS returns expiration in ms since epoch
            #     return dt.datetime.fromtimestamp(ms_since_epoch / 1000, tz=dt.UTC).isoformat()
            return {
                'AWS_ACCESS_KEY_ID': rc['accessKeyId'],
                'AWS_SECRET_ACCESS_KEY': rc['secretAccessKey'],
                'AWS_SESSION_TOKEN': rc['sessionToken'],
                # 'AWS_CREDENTIAL_EXPIRATION': _utc_iso(rc['expiration']),
            }
    return None


def now():
    return dt.datetime.now(tz=dt.timezone.utc)


def lsof(port):
    if isinstance(port, int) or isinstance(port, str) and port.isdigit():
        port = f':{port}'
    if _ := subprocess.run(f'lsof -nPi {port}'.split(), capture_output=True).stdout:
        h, *lines = _.decode().splitlines()
        h = h.lower().split()
        return [
            dict(zip(h, re.split(r'\s+', _, maxsplit=len(h))))
            for _ in lines
        ]
    return None


def verify_client(addr):
    client, server = None, None
    if addr[0] != '127.0.0.1':
        return print('Invalid address:', addr)
    if len(procs := lsof(port=f'TCP:{addr[1]}')) != 2:
        return print('Unexpected procs:', procs)
    for p in procs:
        n = p['name'].split('->')
        if len(n) == 2:
            f, t = n
            if f == f'127.0.0.1:{PORT}':
                server = p
            elif t == f'127.0.0.1:{PORT}':
                client = p
            else:
                return print('Invalid process:', p)
    if not client or client['command'] != 'Python':
        return print('Invalid client:', client)
    if not server or server['command'] != 'Python':
        return print('Invalid server:', server)
    if int(server['pid']) != PID:
        # TODO: react on server swap
        # os.system(f'ps -p {p["pid"]} -o lstart=')
        # os.system(f'ps -p {p["pid"]} -o command=')
        # os.system(f'ps -p {p["pid"]} -o comm=')
        return print('Invalid server pid:', server['pid'])
    if client['user'] != server['user']:
        return print('Invalid client user:', client['user'])
    return True


def wait(seconds):
    for _ in range(seconds * 10):
        if not SHUTDOWN.is_set():
            time.sleep(0.1)


def refresher() -> None:
    while not SHUTDOWN.is_set():
        get_sso_session()
        wait(seconds=60)


def serve():
    get_sso_session(create=True)

    thread = threading.Thread(target=refresher, daemon=True)
    thread.start()

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            # Allow reusing the address after the process exits
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind((HOST, PORT))
            except Exception as e:
                if 'Address already in use' in str(e):
                    # TODO: force kill the other hanging process if needed?
                    exit()
                raise
            s.listen()
            s.settimeout(0.5)  # allow responsive shutdown

            print(f"Server listening on {HOST}:{PORT}...")
            while not SHUTDOWN.is_set():
                try:
                    c, addr = s.accept()
                except (TimeoutError, socket.timeout):
                    continue
                except OSError as e:
                    if e.errno == 11:  # EAGAIN on some platforms
                        continue
                    raise
                with c:
                    if verify_client(addr):
                        print(f"Connected by {addr}")
                    else:
                        print(f"Rejected {addr}")
                        continue

                    try:
                        _args = json.loads(c.recv(1024))
                        assert isinstance(_args, list)
                    except Exception as e:
                        print(e)
                        c.sendall(repr(e).encode())
                        continue
                    else:
                        print(_args)
                        aliases = {
                            v: k for k, v in get_sso_session(create=True)['accounts'].items()
                        }
                        account_id = role_name = duration = None
                        for a in _args:
                            if a.isdigit():
                                if len(a) == 12:
                                    account_id = a
                                else:
                                    duration = a
                            elif '-' in a:
                                if _ := aliases.get(a):
                                    account_id = _
                                else:
                                    c.sendall(f"No access to account {a}, accessible: {aliases}".encode())
                                    break
                            else:
                                role_name = a
                        if not account_id:
                            ...  # TODO: role name is profile
                            c.sendall("Account ID, or name, or profile name are missing".encode())
                            continue
                        role_name = {
                            'admin': 'AdministratorAccess',
                            'read': 'ReadOnlyAccess',
                            None: 'ReadOnlyAccess',
                        }.get(role_name, role_name)

                        roles = get_roles(account_id=account_id)
                        if role_name not in roles:
                            c.sendall(f"Invalid role name {role_name}, allowed: {roles}".encode())
                        else:
                            _ = get_role_session(account_id=account_id, role_name=role_name)
                            c.sendall(json.dumps(_).encode())
    finally:
        SHUTDOWN.set()
        thread.join()


def request(data):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))

    # print("-->", data)
    s.sendall(json.dumps(data).encode())

    r = s.recv(4196)
    # print("<--", r.decode().strip() or '(none)')

    s.close()
    return r


def start_server():
    subprocess.Popen(
        sys.argv[:1] + ['serve'],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        preexec_fn=os.setsid,  # start in a new session
    )


def get_server():
    return [p for p in lsof(port=f'TCP:{PORT}') or [] if p['name'] == f'*:{PORT}']


def stop_server():
    if _ := get_server():
        _, = _
        os.kill(_['pid'], signal.SIGTERM)


def is_running():
    return bool(get_server())


if __name__ == '__main__':
    print('args', args := sys.argv[1:])
    print('pid', my_pid := os.getpid())
    print('server', get_server())

    if args == ['serve']:
        serve() and exit()

    elif args == ['stop']:
        stop_server() and exit()

    elif '--' not in args:
        error('-- is missing in args')

    sso_args = []
    while args:
        if args[0] == '--':
            args = args[1:]
            break
        else:
            sso_args.append(args.pop(0))

    started = False
    if not is_running():
        start_server()
        time.sleep(0.1)

    if _ := request(data=sso_args).strip():
        os.environ.update(json.loads(_))
        os.system(' '.join(args))

    # stop()

    # while True:
    #     with pathlib.Path('/tmp/aws-sso.log').open('a+') as fp:
    #         fp.write(f'{dt.datetime.now().isoformat()}\n')
    #     time.sleep(1)

    # while True:
    #     time.sleep(1)
    #     print(pathlib.Path('/tmp/aws-sso.log').read_text())

    # main()
