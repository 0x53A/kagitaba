"""Headless Firefox with disposable profile and synthetic Rust/WASM fixture.

Run: nix-shell -p geckodriver --run 'uv run --with selenium --with cryptography extension/firefox/tests/browser_smoke.py'
Requires built dist and target/browser-test-fixture.json. Does not use a physical key.
"""
import base64
import datetime
import hashlib
import http.server
import json
import pathlib
import ssl
import tempfile
import threading
import time
import urllib.parse
import zipfile
from local_installation import seed_installation
from credential_tools_smoke import exercise_tools

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID
from selenium import webdriver
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.firefox.service import Service
from selenium.webdriver.support.ui import WebDriverWait

ROOT = pathlib.Path(__file__).resolve().parents[3]
DIST = ROOT / "extension/firefox/dist"


def main():
    fixture = json.loads((ROOT / "target/browser-test-fixture.json").read_text())
    options = Options()
    options.add_argument("-headless")
    options.add_argument("-remote-allow-system-access")
    options.binary_location = "/run/current-system/sw/bin/firefox"
    options.set_preference("network.dns.localDomains", "example.test")
    with tempfile.TemporaryDirectory(prefix="kagitaba-firefox-test-") as temporary:
        xpi = pathlib.Path(temporary) / "test.xpi"
        with zipfile.ZipFile(xpi, "w") as archive:
            for source in DIST.iterdir():
                archive.write(source, source.name)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.test")])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(minutes=1)).not_valid_after(now+datetime.timedelta(days=1)).add_extension(x509.SubjectAlternativeName([x509.DNSName("example.test")]), critical=False).sign(key,hashes.SHA256()))
        cert_path, key_path = pathlib.Path(temporary)/"cert.pem", pathlib.Path(temporary)/"key.pem"
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
        class Page(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"<!doctype html><title>Synthetic login</title><form><input autocomplete=username><input type=password></form>")
            def log_message(self,*args):
                pass
        server = http.server.ThreadingHTTPServer(("127.0.0.1",0),Page)
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_path,key_path)
        server.socket=context.wrap_socket(server.socket,server_side=True)
        threading.Thread(target=server.serve_forever,daemon=True).start()
        driver = webdriver.Firefox(options=options, service=Service(log_output=str(pathlib.Path(temporary) / "driver.log")))
        try:
            driver.set_window_size(540, 820)
            driver.install_addon(str(xpi), temporary=True)
            driver.set_context("chrome")
            uuids = json.loads(driver.execute_script("return Services.prefs.getStringPref('extensions.webextensions.uuids');"))
            driver.set_context("content")
            driver.get(f"moz-extension://{uuids['firefox@kagitaba.local']}/app.html")
            driver.set_script_timeout(60)

            def send(message):
                result = driver.execute_async_script("const done=arguments[arguments.length-1]; browser.runtime.sendMessage(arguments[0]).then(v=>done({value:v}),e=>done({error:e.message}));", message)
                assert not result.get("error"), f"Extension operation failed: {message['type']}: {result.get('error')}"
                return result.get("value")

            assert send({"type": "status"})["installation"] is None
            seed_installation(driver, fixture["installation"])
            send({"type": "import", "bundle": fixture["wallet"], "trust": {"root": fixture["root"], "checkpoint": fixture["checkpoint"]}})
            send({"type": "unlock", "prf": fixture["prf"]})
            status = send({"type": "status"})
            assert status["unlocked"] and len(status["entries"]) == 1
            participant = send({"type": "participant"})
            assert set(participant) == {"format", "encryption", "signing"}
            send({"type": "name-participant", "id": fixture["installation"]["participantId"], "name": "Private Firefox name"})
            named = send({"type": "status"})
            assert len(named["entries"]) == 1
            assert named["participants"][0]["name"] == "Private Firefox name"
            payload = send({"type": "entry", "id": fixture["entryId"]})
            payload["entity"]["title"] = "Edited in real Firefox"
            website_origin=f"https://example.test:{server.server_port}"
            payload["entity"]["scope"]["urls"]=[website_origin]
            draft = send({"type": "entry-draft", "id": fixture["entryId"]})
            send({"type": "save", "id": fixture["entryId"], "payload": draft["payload"], "expectedPrimary": draft["primary"], "changes": {"title": payload["entity"]["title"], "login": {"urls": [website_origin]}}})
            stale = driver.execute_async_script("const done=arguments[arguments.length-1];browser.runtime.sendMessage(arguments[0]).then(()=>done(false),e=>done(e.message.includes('changed or was deleted')));", {"type":"save","id":fixture["entryId"],"payload":draft["payload"],"expectedPrimary":draft["primary"]})
            assert stale, "A stale draft must not overwrite a newer revision"
            updated = send({"type": "export"})
            assert set(updated) == {"wallet"}
            assert updated["wallet"]["head"] != fixture["checkpoint"]
            send({"type": "lock"})
            assert send({"type": "status"})["entries"] == []
            assert all(not participant["name"] for participant in send({"type": "status"})["participants"])
            send({"type": "unlock", "prf": fixture["prf"]})
            assert send({"type": "status"})["participants"][0]["name"] == "Private Firefox name"
            assert send({"type": "entry", "id": fixture["entryId"]})["entity"]["title"] == "Edited in real Firefox"
            driver.refresh()
            def click(label):
                WebDriverWait(driver, 10).until(lambda d: d.execute_script("const root=document.querySelector('dialog[open]')??document;const b=[...root.querySelectorAll('button')].find(b=>b.textContent===arguments[0]||b.querySelector('strong')?.textContent===arguments[0]);if(!b||b.disabled)return false;b.click();return true;", label))
            encoded = lambda raw: base64.urlsafe_b64encode(bytes.fromhex(raw)).decode().rstrip("=")
            collection_id = "cc" * 16
            collection = {"format":"kagitaba-cxf","version":1,"cxfVersion":{"major":1,"minor":0},"kind":"collection","entity":{"id":encoded(collection_id),"title":"Test collection","items":[{"item":encoded(fixture["entryId"]),"account":"ZXh0ZXJuYWw"}],"subCollections":[{"id":encoded("dd"*16),"title":"Nested collection","items":[{"item":encoded(fixture["entryId"])}]}]}}
            send({"type":"save","id":collection_id,"payload":collection})
            driver.refresh()
            click("Entries not in a collection")
            WebDriverWait(driver,10).until(lambda d:d.execute_script("return document.querySelector('.collection-tree button[aria-current=true]')?.textContent==='Entries not in a collection' && !document.querySelector('.entries button')"))
            click("Test collection")
            WebDriverWait(driver,10).until(lambda d:d.execute_script("return document.querySelector('.collection-status')?.textContent.includes('1 unavailable')"))
            click("Nested collection")
            WebDriverWait(driver,10).until(lambda d:d.execute_script("return document.querySelector('.entries strong')?.textContent==='Edited in real Firefox'"))
            assert driver.execute_script("return document.querySelector('.entry-id').textContent") == fixture["entryId"][:8]
            assert driver.execute_script("return !!document.querySelector('.entry-usernames').textContent")
            driver.set_window_size(1100,820)
            driver.save_screenshot(str(ROOT / "target/firefox-collections-wide.png"))
            driver.set_window_size(540,820)
            WebDriverWait(driver,10).until(lambda d:d.execute_script("const t=document.querySelector('.collection-tree'),r=t.querySelector('[aria-current=true]');return r.getBoundingClientRect().bottom<=t.getBoundingClientRect().bottom+1;"))
            driver.save_screenshot(str(ROOT / "target/firefox-collections-narrow.png"))
            click("All entries")
            click("Edited in real Firefox")
            click("Edit entry")
            title = driver.execute_script("return [...document.querySelectorAll('label')].find(l=>l.textContent==='Title').control;")
            title.clear(); title.send_keys("Saved through the form")
            click("Save entry")
            WebDriverWait(driver, 10).until(lambda d: d.find_element("id", "notice").text == "Entry saved.")
            form_saved = send({"type": "entry", "id": fixture["entryId"]})
            assert form_saved["entity"]["title"] == "Saved through the form"
            assert form_saved["entity"]["credentials"] == payload["entity"]["credentials"]
            payload = exercise_tools(driver, send, click, fixture)
            driver.save_screenshot(str(ROOT / "target/firefox-entry-edit.png"))
            click("Back to entries")
            WebDriverWait(driver, 10).until(lambda d: d.execute_script("return !!document.querySelector('.entries button');"))
            driver.save_screenshot(str(ROOT / "target/firefox-extension-smoke.png"))
            app_handle=driver.current_window_handle
            driver.switch_to.new_window("tab")
            website_handle=driver.current_window_handle
            driver.get(f"{website_origin}/")
            driver.switch_to.window(app_handle)
            target_tab=driver.execute_async_script("const done=arguments[arguments.length-1],origin=arguments[0];browser.tabs.query({}).then(t=>done(t.find(tab=>tab.url?.startsWith(origin+'/')).id));",website_origin)
            assert send({"type":"matches","tabId":target_tab})["entries"][0]["id"]==fixture["entryId"]
            send({"type":"fill","tabId":target_tab,"id":fixture["entryId"]})
            driver.switch_to.window(website_handle)
            assert driver.execute_script("return document.querySelector('input[type=password]').value")==payload["entity"]["credentials"][0]["password"]["value"]
            driver.execute_script("document.querySelector('input[type=password]').value='synthetic-updated';")
            driver.switch_to.window(app_handle)
            assert send({"type":"capture","tabId":target_tab})["password"]=='synthetic-updated'
            driver.switch_to.window(website_handle)

            def wait_result(condition):
                for _ in range(200):
                    value=condition()
                    if value:
                        return value
                    time.sleep(.05)
                raise AssertionError("Browser request timed out")

            def approve_request(kind,extra=None):
                old_handles=set(driver.window_handles)
                script = "window.result=null;window.failure=null;navigator.credentials.%s({publicKey:%s}).then(c=>window.result=c.toJSON(),e=>window.failure=e.name);"
                options="{challenge:new Uint8Array(32).fill(7),rp:{id:'example.test',name:'Test'},user:{id:new Uint8Array([1,2]),name:'synthetic',displayName:'Synthetic'},pubKeyCredParams:[{type:'public-key',alg:-7}]}" if kind=="create" else "{challenge:new Uint8Array(32).fill(8),rpId:'example.test',userVerification:'required'}"
                driver.execute_script(script % (kind,options))
                chooser=wait_result(lambda:driver.execute_script("return document.querySelector('#kagitaba-passkey-chooser')?.shadowRoot.querySelector('[data-backend=browser]')"))
                chooser.click()
                handle=wait_result(lambda:next(iter(set(driver.window_handles)-old_handles),None))
                driver.switch_to.window(handle)
                wait_result(lambda:"request=" in driver.current_url)
                assert driver.execute_async_script("const done=arguments[arguments.length-1];browser.windows.getCurrent().then(w=>done(w.type));") == "popup"
                request_id=urllib.parse.parse_qs(urllib.parse.urlparse(driver.current_url).query)["request"][0]
                if not send({"type":"status"})["unlocked"]:
                    send({"type":"unlock","prf":fixture["prf"]})
                request=send({"type":"request","requestId":request_id})
                arguments={"type":"approve","requestId":request_id,"prf":fixture["prf"],"uv":True}
                if kind=="get":
                    arguments.update(request["accounts"][0])
                send(arguments)
                driver.close()
                driver.switch_to.window(website_handle)
                result=wait_result(lambda:driver.execute_script("return window.result || (window.failure ? {error:window.failure} : null)"))
                assert "error" not in result,result
                return result

            created=approve_request("create")
            # Native toolbar mode must not hide an existing browser wallet from
            # the chooser or prevent its existing unlock/approval flow.
            driver.switch_to.window(app_handle)
            send({"type":"backend-mode","mode":"native"})
            driver.switch_to.window(website_handle)
            authenticated=approve_request("get")
            decode=lambda value:base64.urlsafe_b64decode(value+"="*((-len(value))%4))
            public=serialization.load_der_public_key(decode(created["response"]["publicKey"]))
            auth=decode(authenticated["response"]["authenticatorData"])
            client=decode(authenticated["response"]["clientDataJSON"])
            public.verify(decode(authenticated["response"]["signature"]),auth+hashlib.sha256(client).digest(),ec.ECDSA(hashes.SHA256()))
            assert auth[:32]==hashlib.sha256(b"example.test").digest() and auth[32]&5==5 and auth[33:37]==bytes(4)
            assert json.loads(client)["origin"]==f"https://example.test:{server.server_port}"
            assert authenticated["id"]==created["id"]
            driver.switch_to.window(app_handle)
            assert len([entry for entry in send({"type":"status"})["entries"] if entry["kind"]=="item"])==2
            driver.switch_to.window(website_handle)
            old_handles=set(driver.window_handles)
            driver.execute_script("window.failure=null;navigator.credentials.get({publicKey:{challenge:new Uint8Array(32),rpId:'example.test'}}).catch(e=>window.failure=e.name)")
            wait_result(lambda:driver.execute_script("return !!document.querySelector('#kagitaba-passkey-chooser')"))
            driver.switch_to.window(app_handle)
            send({"type":"lock"})
            driver.switch_to.window(website_handle)
            assert wait_result(lambda:driver.execute_script("return window.failure"))=='NotAllowedError'
            print("Firefox smoke passed: local installation, trusted import, WASM unlock, signed durable edit, explicit password fill/capture, real page bridge registration/assertion with independently verified signature, and pending-request lock cancellation. Hardware PRF was simulated.")
        finally:
            driver.quit()
            server.shutdown()


if __name__ == "__main__":
    main()
