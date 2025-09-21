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
import urllib.request
import urllib.error
import datetime as dt
from typing import Any

assert sys.version.startswith('3.9.')

HOST = '0.0.0.0'
# HOST = '127.0.0.1'
PORT = 4550
PID = os.getpid()
LOCK = threading.Lock()
SSO_TOKEN: bytes | None = None
OIDC_URL = 'https://oidc.{}.amazonaws.com'

PING = b'PING\n'
PONG = b'PONG\n'
STOP = b'STOP\n'
BYE = b'BYE!\n'
GET_SSO = b'GET SSO\n'
PUT_SSO = b'PUT SSO '
OK = b'OK!\n'


def error(msg: str) -> None:
    print('Error:', msg, file=sys.stderr)
    sys.exit(1)


def load_sso_session():
    cfg_path = pathlib.Path.home() / '.aws/config'
    if not cfg_path.exists():
        raise error(f'File not found {cfg_path}')
    config = configparser.ConfigParser()
    config.read(cfg_path)

    # Prefer an explicit sso-session, otherwise take the first one
    sessions: list[tuple[str, configparser.SectionProxy]] = [
        (s[12:].strip(), config[s])  # strip leading 'sso-session '
        for s in config.sections()
        if s.startswith('sso-session ')
    ]
    if not sessions:
        raise error(f'No [sso-session <name>] found in {cfg_path}')

    # If multiple sessions exist, you can set AWS_SSO_SESSION to choose one
    env_pick = (sys.argv[1] if len(sys.argv) > 1 else None) or os.getenv('AWS_SSO_SESSION')
    if env_pick:
        for alias, section in sessions:
            if alias == env_pick:
                chosen = (alias, section)
                break
        else:
            raise error(
                f'Requested sso-session {env_pick!r} not found. '
                f'Available: {[a for a, _ in sessions]}'
            )
    else:
        chosen = sessions[0]
        if len(sessions) > 1:
            print(f'Warning: multiple sso-sessions found, selecting {chosen[0]}')

    alias, section = chosen
    try:
        region = section['sso_region'].strip()
        start_url = section['sso_start_url'].strip()
    except KeyError as e:
        raise error(f'Missing required key in sso-session {alias!r}: {e}')

    scopes = section.get('sso_registration_scopes', '').split()
    return {
        'alias': alias,
        'region': region,
        'start_url': start_url,
        'scopes': scopes,
    }


def post_json(url: str, payload: dict[str, Any]) -> dict[str, Any]:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, headers={'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors='ignore')
        raise RuntimeError(f'HTTP {e.code} POST {url}: {body}')


def sso_auth():
    sess = load_sso_session()
    region = sess['region']
    start_url = sess['start_url']
    scopes: list[str] = sess['scopes']

    base = OIDC_URL.format(region)

    reg = post_json(f'{base}/client/register', {
        'clientName': 'aws-sso-' + sess['alias'],
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
    expires_at = dt.datetime.now(tz=dt.timezone.utc) + dt.timedelta(seconds=dev['expiresIn'])

    # Poll /token until authorized or expired
    while dt.datetime.now(tz=dt.timezone.utc) < expires_at:
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
            print('tok', tok)
            t = dt.datetime.now(tz=dt.timezone.utc)
            return {
                **tok,
                'issuedAt': t.isoformat(),
                'expiresAt': (t + dt.timedelta(seconds=tok['expiresIn'])).isoformat(),
                'region': region,
                'startUrl': start_url,
                'scopes': scopes,
                'clientId': client_id,
                'clientSecret': client_secret,
                # 'deviceCode': dev['deviceCode'],
            }

    raise error('Timed out waiting for authorization.')


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
        return print('Invalid server pid:', server['pid'])
    if client['user'] != server['user']:
        return print('Invalid client user:', client['user'])
    return True


def serve():
    global SSO_TOKEN
    stop_event = threading.Event()

    def _shutdown(*_):
        stop_event.set()

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    def _refresher() -> None:
        global SSO_TOKEN
        while not stop_event.is_set():
            if SSO_TOKEN:
                session = json.loads(SSO_TOKEN)
                d = now() - dt.datetime.fromisoformat(session['issuedAt'])
                if d > dt.timedelta(seconds=session['expiresIn']):
                    SSO_TOKEN = None
                elif d > dt.timedelta(minutes=10):
                    base = OIDC_URL.format(session['region'])
                    tok = post_json(f'{base}/token', {
                        'grantType': 'refresh_token',
                        'clientId': session['clientId'],
                        'clientSecret': session['clientSecret'],
                        'refreshToken': session['refreshToken'],
                    })
                    print('ref', tok)
                    _ = now().isoformat()
                    SSO_TOKEN = json.dumps({**session, **tok, 'issuedAt': _}).encode()
                    assert request(PUT_SSO + json.dumps(session).encode() + b'\n') == OK

                    ...

            time.sleep(60)

    thread = threading.Thread(target=_refresher, daemon=True)
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
            while not stop_event.is_set():
                try:
                    c, addr = s.accept()
                except TimeoutError:
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

                    f = c.makefile('rb')  # line-buffered view over the socket
                    try:
                        for line in f:
                            print(line.split()[:2])
                            if line == PING:
                                c.sendall(PONG)
                            elif line == STOP:
                                c.sendall(BYE)
                                exit()
                            elif line == GET_SSO:
                                with LOCK:
                                    if sso_token:
                                        c.sendall(sso_token)
                                    else:
                                        c.sendall(b'\n')
                            elif line.startswith(PUT_SSO):
                                with LOCK:
                                    sso_token = line[len(PUT_SSO):]
                                c.sendall(OK)
                            elif line.startswith(b"PUT ROLE "):
                                c.sendall(b'')
                            elif line.startswith(b"GET ROLE "):
                                c.sendall(b'')
                    except ConnectionResetError as e:
                        print(e)
    finally:
        stop_event.set()
        thread.join()


def request(cmd):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))

    if isinstance(cmd, str):
        cmd = cmd.encode()
    cmd = cmd.strip() + b'\n'

    print("-->", cmd.strip().decode())
    s.sendall(cmd)
    r = s.recv(4196)
    print("<--", r.decode().strip() or '(none)')

    s.close()
    return r


def start():
    subprocess.Popen(
        sys.argv[:1] + ['start'],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        preexec_fn=os.setsid,  # start in a new session
    )
    time.sleep(0.1)
    return ping()


def stop():
    return request(STOP) == BYE


def ping():
    return request(PING) == PONG


def get_server():
    return [p for p in lsof(port=f'TCP:{PORT}') or [] if p['name'] == f'*:{PORT}']


def is_running():
    return bool(get_server())


if __name__ == '__main__':
    assert (_ := sys.version_info) > (3, 9), _
    print('pid', my_pid := os.getpid())
    print('args', args := sys.argv[1:])
    print('proc', get_server())

    if args == ['start']:
        serve() and exit()

    elif args == ['stop']:
        if stop():
            exit()
        else:
            raise error('Failed to stop server.')

    started = False
    if not is_running():
        started = start()
        if not started:
            raise error('Failed to start server.')

    if _ := request(GET_SSO).strip():
        session = json.loads(_)
        t = dt.datetime.fromisoformat(session['issuedAt'])
        print(now() - t)
        if now() - t > dt.timedelta(seconds=5):
            ...
    else:
        _ = sso_auth()
        assert request(PUT_SSO + json.dumps(_).encode() + b'\n') == OK

    # stop()

    # while True:
    #     with pathlib.Path('/tmp/aws-sso.log').open('a+') as fp:
    #         fp.write(f'{dt.datetime.now().isoformat()}\n')
    #     time.sleep(1)

    # while True:
    #     time.sleep(1)
    #     print(pathlib.Path('/tmp/aws-sso.log').read_text())

    # main()
