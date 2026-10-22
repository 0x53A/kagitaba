"""Exercise real Firefox HTTPS smart-Git fetch against a synthetic local remote.

Run with the same Selenium/cryptography dependencies as browser_smoke.py and Git.
No user wallets, remote credentials, or external Git servers are accessed.
"""
import base64
import datetime
import http.server
import json
import os
import pathlib
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.parse
import zipfile
import zlib
from local_installation import seed_installation

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from selenium import webdriver
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.firefox.service import Service

ROOT=pathlib.Path(__file__).resolve().parents[3]

def main():
    fixture=json.loads((ROOT/'target/browser-test-fixture.json').read_text())
    options=Options()
    options.add_argument('-headless')
    options.add_argument('-remote-allow-system-access')
    options.binary_location='/run/current-system/sw/bin/firefox'
    options.set_preference('network.dns.localDomains','example.test')
    with tempfile.TemporaryDirectory(prefix='kagitaba-smart-http-') as directory:
        temporary=pathlib.Path(directory)
        repo=temporary/'wallet.git'
        (repo/'objects').mkdir(parents=True)
        (repo/'refs/heads').mkdir(parents=True)
        (repo/'HEAD').write_text('ref: refs/heads/wallet\n')
        (repo/'refs/heads/wallet').write_text(fixture['wallet']['head']+'\n')
        (repo/'config').write_text('[core]\nrepositoryformatversion = 0\nbare = true\n[http]\nreceivepack = true\n')
        for obj in fixture['wallet']['objects']:
            raw=base64.urlsafe_b64decode(obj['data']+'='*((-len(obj['data']))%4))
            destination=repo/'objects'/obj['oid'][:2]/obj['oid'][2:]
            destination.parent.mkdir(exist_ok=True)
            destination.write_bytes(zlib.compress(f"{obj['type']} {len(raw)}\0".encode()+raw))
        key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'example.test')])
        now=datetime.datetime.now(datetime.timezone.utc)
        certificate=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(minutes=1)).not_valid_after(now+datetime.timedelta(days=1)).add_extension(x509.SubjectAlternativeName([x509.DNSName('example.test')]),False).sign(key,hashes.SHA256()))
        cert_path,key_path=temporary/'cert.pem',temporary/'key.pem'
        cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
        requests=[]
        class SmartGit(http.server.BaseHTTPRequestHandler):
            def do_GET(self): self.serve()
            def do_POST(self): self.serve()
            def serve(self):
                parsed=urllib.parse.urlsplit(self.path)
                requests.append((self.command,parsed.path))
                if not parsed.path.startswith('/wallet.git/'):
                    self.send_response(200);self.end_headers();self.wfile.write(b'Synthetic Git test');return
                auth='Basic '+base64.b64encode(b'synthetic:synthetic-token').decode()
                if self.headers.get('Authorization')!=auth:
                    self.send_response(401);self.send_header('WWW-Authenticate','Basic realm="Synthetic test"');self.end_headers();return
                env={**os.environ,'GIT_PROJECT_ROOT':str(temporary),'GIT_HTTP_EXPORT_ALL':'1','PATH_INFO':parsed.path,'QUERY_STRING':parsed.query,'REQUEST_METHOD':self.command,'CONTENT_TYPE':self.headers.get('Content-Type',''),'CONTENT_LENGTH':self.headers.get('Content-Length','0'),'REMOTE_USER':'synthetic'}
                body=self.rfile.read(int(env['CONTENT_LENGTH']))
                result=subprocess.run(['git','http-backend'],input=body,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True)
                header,body=result.stdout.split(b'\r\n\r\n',1)
                headers=[line.decode().split(':',1) for line in header.split(b'\r\n')]
                status=next((int(value.strip().split()[0]) for name,value in headers if name.lower()=='status'),200)
                self.send_response(status)
                for name,value in headers:
                    if name.lower()!='status':self.send_header(name,value.strip())
                self.end_headers();self.wfile.write(body)
            def log_message(self,*args): pass
        server=http.server.ThreadingHTTPServer(('127.0.0.1',0),SmartGit)
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(cert_path,key_path)
        server.socket=context.wrap_socket(server.socket,server_side=True)
        threading.Thread(target=server.serve_forever,daemon=True).start()
        xpi=temporary/'extension.xpi'
        with zipfile.ZipFile(xpi,'w') as archive:
            for file in (ROOT/'extension/firefox/dist').iterdir():archive.write(file,file.name)
        driver=webdriver.Firefox(options=options,service=Service(log_output=str(temporary/'driver.log')))
        try:
            driver.get(f'https://example.test:{server.server_port}/')
            driver.install_addon(str(xpi),temporary=True)
            driver.set_context('chrome')
            uuids=json.loads(driver.execute_script("return Services.prefs.getStringPref('extensions.webextensions.uuids');"))
            driver.set_context('content')
            driver.get(f"moz-extension://{uuids['firefox@kagitaba.local']}/app.html")
            driver.set_script_timeout(60)
            def send(message):
                result=driver.execute_async_script('const done=arguments[arguments.length-1];browser.runtime.sendMessage(arguments[0]).then(value=>done({value}),error=>done({error:error.message}));',message)
                assert 'error' not in result,(message['type'],result,requests)
                return result.get('value')
            seed_installation(driver, fixture['installation'])
            send({'type':'unlock','prf':fixture['prf']})
            driver.refresh()
            for _ in range(100):
                if driver.execute_script("return [...document.querySelectorAll('button')].some(b=>b.textContent==='Connect remote')"):break
                time.sleep(.05)
            remote_url=f'https://example.test:{server.server_port}/wallet.git'
            draft={'HTTPS Git remote URL':remote_url,'Remote username':'synthetic','Remote token / password':'wrong-synthetic-token'}
            driver.execute_script("for(const [name,value] of Object.entries(arguments[0])){const input=[...document.querySelectorAll('label')].find(l=>l.textContent===name).nextElementSibling;input.value=value;input.dispatchEvent(new Event('input',{bubbles:true}));}[...document.querySelectorAll('button')].find(b=>b.textContent==='Connect remote').click();",draft)
            for _ in range(200):
                if 'denied access' in driver.find_element('id','notice').text:break
                time.sleep(.05)
            assert 'denied access' in driver.find_element('id','notice').text
            retained=driver.execute_script("return Object.fromEntries([...document.querySelectorAll('label')].filter(l=>arguments[0].includes(l.textContent)).map(l=>[l.textContent,l.nextElementSibling.value]));",list(draft))
            assert retained==draft,'Connect failure must preserve the in-tab form draft'
            driver.save_screenshot(str(ROOT/'target/firefox-workflow-connect.png'))
            driver.execute_script("const input=[...document.querySelectorAll('label')].find(l=>l.textContent==='Remote token / password').control;input.value='synthetic-token';input.dispatchEvent(new Event('input',{bubbles:true}));const auto=[...document.querySelectorAll('label')].find(l=>l.textContent.includes('Automatically synchronize')).querySelector('input');if(auto?.checked)auto.click();[...document.querySelectorAll('button')].find(b=>b.textContent==='Connect remote').click();")
            for _ in range(200):
                if send({'type':'status'})['replica'].get('head') and 'Wallet connected' in driver.find_element('id','notice').text:break
                time.sleep(.05)
            assert 'Wallet connected' in driver.find_element('id','notice').text,driver.find_element('id','notice').text
            assert send({'type':'status'})['replica']['head']==fixture['wallet']['head']
            assert send({'type':'status'})['unlocked'],'Successful connect must retain the current unlock session'
            assert send({'type':'status'})['remoteAuth']['hasToken']
            stored=driver.execute_async_script("const done=arguments[arguments.length-1],r=indexedDB.open('kagitaba-installation');r.onsuccess=()=>{const db=r.result,q=db.transaction('records').objectStore('records').get('remote-auth');q.onsuccess=()=>{done(q.result);db.close();};};")
            assert stored['envelope'] and 'synthetic-token' not in json.dumps(stored)
            driver.execute_script("document.querySelector('#header-refresh button[aria-label=\"Synchronize\"]').click();")
            for _ in range(200):
                if 'up to date' in driver.find_element('id','notice').text:break
                time.sleep(.05)
            assert 'up to date' in driver.find_element('id','notice').text
            driver.save_screenshot(str(ROOT/'target/firefox-workflow-wallet.png'))
            driver.execute_script("[...document.querySelectorAll('button')].find(b=>b.textContent==='Settings').click();")
            for _ in range(100):
                if driver.execute_script("return [...document.querySelectorAll('button')].some(b=>b.textContent==='Repository connection')"):break
                time.sleep(.05)
            driver.execute_script("[...document.querySelectorAll('button')].find(b=>b.textContent==='Repository connection').click();")
            for _ in range(100):
                if driver.execute_script("return [...document.querySelectorAll('label')].some(l=>l.textContent==='Remote username')"):break
                time.sleep(.05)
            assert driver.execute_script("return [...document.querySelectorAll('label')].find(l=>l.textContent==='Remote username').control.value")=='synthetic'
            assert 'Saved securely' in driver.execute_script("return [...document.querySelectorAll('label')].find(l=>l.textContent==='Remote token / password').control.placeholder")
            driver.save_screenshot(str(ROOT/'target/firefox-workflow-settings.png'))
            payload=send({'type':'entry','id':fixture['entryId']})
            payload['entity']['title']='Locally edited before HTTPS push'
            draft=send({'type':'entry-draft','id':fixture['entryId']})
            send({'type':'save','id':fixture['entryId'],'payload':draft['payload'],'expectedPrimary':draft['primary'],'changes':{'title':payload['entity']['title']}})
            pushed=send({'type':'sync'})
            assert pushed['outcome']=='pushed',pushed
            assert (repo/'refs/heads/wallet').read_text().strip()==pushed['head']
            app_url=driver.current_url
            app_handle=driver.current_window_handle
            driver.switch_to.new_window('tab')
            driver.get(f'https://example.test:{server.server_port}/')
            standby=driver.current_window_handle
            driver.switch_to.window(app_handle)
            driver.execute_script('setTimeout(()=>browser.runtime.reload(),0);')
            time.sleep(1)
            driver.switch_to.window(standby)
            driver.get(app_url)
            assert not send({'type':'status'})['unlocked']
            assert send({'type':'status'})['remoteAuth']['hasToken']
            rejected=driver.execute_async_script("const done=arguments[arguments.length-1];browser.runtime.sendMessage({type:'sync'}).then(()=>done('unexpected success'),e=>done(e.message));")
            assert 'Unlock the wallet to use the saved remote token' in rejected,rejected
            send({'type':'unlock','prf':fixture['prf']})
            assert send({'type':'sync'})['outcome']=='up-to-date'
            send({'type':'remote-auth','username':'synthetic','password':'','remember':True,'autoSync':True})
            send({'type':'lock'})
            # A second disposable installation exercises an actual remote-ahead
            # pull. Both use deliberately shared synthetic fixture keys only.
            first=driver
            driver=webdriver.Firefox(options=options,service=Service(log_output=str(temporary/'peer-driver.log')))
            try:
                driver.get(f'https://example.test:{server.server_port}/')
                driver.install_addon(str(xpi),temporary=True)
                driver.set_context('chrome')
                peer_uuids=json.loads(driver.execute_script("return Services.prefs.getStringPref('extensions.webextensions.uuids');"))
                driver.set_context('content')
                driver.get(f"moz-extension://{peer_uuids['firefox@kagitaba.local']}/app.html")
                driver.set_script_timeout(60)
                seed_installation(driver, fixture['installation'])
                send({'type':'unlock','prf':fixture['prf']})
                send({'type':'connect','options':{'url':remote_url,'username':'synthetic','password':'synthetic-token','remember':True,'autoSync':False}})
                payload=send({'type':'entry','id':fixture['entryId']})
                payload['entity']['title']='Remote update from second synthetic browser'
                draft=send({'type':'entry-draft','id':fixture['entryId']})
                send({'type':'save','id':fixture['entryId'],'payload':draft['payload'],'expectedPrimary':draft['primary'],'changes':{'title':payload['entity']['title']}})
                assert send({'type':'sync'})['outcome']=='pushed'
            finally:
                driver.quit();driver=first
            send({'type':'unlock','prf':fixture['prf']})
            for _ in range(200):
                state=send({'type':'status'})
                if state['replica'].get('lastSync',{}).get('outcome')=='pulled':break
                time.sleep(.05)
            assert state['replica']['lastSync']['outcome']=='pulled',state['replica']
            assert send({'type':'entry','id':fixture['entryId']})['entity']['title']=='Remote update from second synthetic browser'
            payload=send({'type':'entry','id':fixture['entryId']})
            payload['entity']['title']='Automatically pushed local update'
            draft=send({'type':'entry-draft','id':fixture['entryId']})
            send({'type':'save','id':fixture['entryId'],'payload':draft['payload'],'expectedPrimary':draft['primary'],'changes':{'title':payload['entity']['title']}})
            for _ in range(200):
                state=send({'type':'status'})
                if state['replica'].get('synced')==state['replica']['head'] and state['replica']['lastSync'].get('outcome')=='pushed':break
                time.sleep(.05)
            assert state['replica']['lastSync']['outcome']=='pushed',state['replica']
            assert (repo/'refs/heads/wallet').read_text().strip()==state['replica']['head']
            assert any(method=='POST' and path.endswith('git-upload-pack') for method,path in requests),requests
            print('Real Firefox passed connect/settings/sync UI, failed-form retention, authenticated HTTPS fetch/push/automatic pull+push, encrypted local token persistence, background restart and lock-gated remembered credentials.')
        finally:
            driver.quit();server.shutdown()

if __name__=='__main__':main()
