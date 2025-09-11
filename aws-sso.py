#!/usr/bin/python3
import sys
import json
import time
import os
import pathlib
import configparser
import urllib.request
import urllib.error
import datetime as dt
from typing import Any

assert sys.version.startswith('3.9.')


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


def main() -> None:
    sess = load_sso_session()
    region = sess['region']
    start_url = sess['start_url']
    scopes: list[str] = sess['scopes']

    base = f'https://oidc.{region}.amazonaws.com'

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
            out = {
                'accessToken': tok['accessToken'],
                'tokenType': tok.get('tokenType', 'Bearer'),
                'expiresIn': tok.get('expiresIn'),
                'refreshToken': tok.get('refreshToken'),
                'issuedAt': dt.datetime.now(tz=dt.timezone.utc).isoformat(),
                'region': region,
                'startUrl': start_url,
                'scopes': scopes,
            }
            print(json.dumps(out, indent=2))
            return

    raise error('Timed out waiting for authorization.')


if __name__ == '__main__':
    main()
