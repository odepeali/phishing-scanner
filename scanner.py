import ssl, socket, datetime, whois, requests, hashlib, logging, json, argparse
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import re


MAX_DOMAIN_AGE = 60
SUSPICIOUS_KEYWORDS = ["login","verify","account","secure","otp","password","signin","update","bank","credit"]
SUSPICIOUS_TLDS = {".tk",".xyz",".cf",".ga",".gq",".cc",".pw",".top"}

logging.basicConfig(filename="phishing_scan.log", level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")

def hash_data(data): return hashlib.sha256(data.encode()).hexdigest()


def get_rdap_creation(domain):
    try:
        tld = domain.split('.')[-1]
        resp = requests.get(f"https://rdap.verisign.com/{tld}/v1/domain/{domain}", timeout=8)
        for ev in resp.json().get("events", []):
            if ev.get("eventAction") in ("registration","create"):
                return datetime.datetime.fromisoformat(ev["eventDate"].replace('Z','+00:00'))
    except Exception as e:
        logging.error(f"RDAP lookup failed for {domain}: {e}")
    return None

def whois_info(domain):
    info = {"age_days":None,"is_new":False}
    cd = None
    try:
        w = whois.whois(domain); cd = w.creation_date[0] if isinstance(w.creation_date,list) else w.creation_date
    except:
        cd = None
    if cd and not cd.tzinfo: cd = cd.replace(tzinfo=datetime.timezone.utc)
    if not cd: cd = get_rdap_creation(domain)
    if cd:
        if not cd.tzinfo: cd = cd.replace(tzinfo=datetime.timezone.utc)
        now = datetime.datetime.now(datetime.timezone.utc)
        info["age_days"] = (now - cd).days
        info["is_new"] = info["age_days"] < MAX_DOMAIN_AGE
        logging.info(f"WHOIS age {domain}: {info}")
    else:
        logging.info(f"No WHOIS/RDAP date for {domain}")
    return info

def ssl_info(host):
    info = {"valid":False,"expires_in":None,"issuer":"N/A"}
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=host) as conn:
            conn.settimeout(5); conn.connect((host,443))
            cert = conn.getpeercert()
            issuer = "; ".join(f"{k}={v}" for rdn in cert.get("issuer",[]) for k,v in rdn)
            info["issuer"] = issuer
            expires = datetime.datetime.strptime(cert["notAfter"], '%b %d %H:%M:%S %Y %Z')
            if not expires.tzinfo: expires = expires.replace(tzinfo=datetime.timezone.utc)
            now = datetime.datetime.now(datetime.timezone.utc)
            days = (expires - now).days
            info.update(valid=(days>=0), expires_in=days)
            logging.info(f"SSL info {host}: {info}")
    except Exception as e:
        logging.error(f"SSL lookup failed for {host}: {e}")
    return info

def content_checks(url):
    data = {"keywords":0,"pw_field":False,"forms":False}
    try:
        r = requests.get(url, timeout=8, headers={"User-Agent":"Mozilla/5.0"})
        txt = r.text.lower()
        data["keywords"] = sum(txt.count(k) for k in SUSPICIOUS_KEYWORDS)
        soup = BeautifulSoup(r.text,"html.parser")
        data["pw_field"] = bool(soup.find("input",{"type":"password"}))
        data["forms"] = bool(soup.find("form",{"method":"post"}))
        logging.info(f"Content check {url}: {data}")
    except Exception as e:
        logging.error(f"Content check failed for {url}: {e}")
    return data

def heuristic_checks(domain):
    score, flags = 0, []
    if any(domain.lower().endswith(tld) for tld in SUSPICIOUS_TLDS):
        score+=2; flags.append("suspicious TLD")
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", domain):
        score+=2; flags.append("IP domain")
    if len(domain.split('.'))>3:
        score+=1; flags.append("deep subdomain")
    logging.info(f"Heuristics {domain}: {score}, {flags}")
    return score, flags

def vt_reputation(domain, vt_api_key):
    info = {"reputation":"unknown","malicious_reports":0,"score":0,"verdict":"UNKNOWN"}
    try:
        import virustotal_python
        with virustotal_python.Virustotal(vt_api_key) as vt:
            resp = vt.request(f"domains/{domain}")
            stats = resp.data["attributes"]["last_analysis_stats"]
            mal = stats.get("malicious",0)
            ver = "MALICIOUS" if mal>0 else "SAFE"
            info = {"reputation":ver.lower(),"malicious_reports":mal,"score":10 if mal>0 else 0,"verdict":ver}
    except Exception as e:
        logging.error(f"VirusTotal failed {domain}: {e}")
    return info

def gsb_check(url, gsb_api_key):
    info = {"reputation":"unknown","verdict":"UNKNOWN"}
    try:
        endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={gsb_api_key}"
        payload = {"client":{"clientId":"phishscanner","clientVersion":"1.0"},
                   "threatInfo":{"threatTypes":["MALWARE","SOCIAL_ENGINEERING"],
                                "platformTypes":["ANY_PLATFORM"],"threatEntryTypes":["URL"],
                                "threatEntries":[{"url":url}]}}
        resp = requests.post(endpoint, json=payload, timeout=10)
        j = resp.json()
        if j.get("matches"):
            info.update(reputation="malicious", verdict="UNSAFE")
        else:
            info.update(reputation="safe", verdict="SAFE")
    except Exception as e:
        logging.error(f"SafeBrowsing failed {url}: {e}")
    return info

def scan_target(target, vt_key=None, gsb_key=None):
    parsed = urlparse(target if "://" in target else f"https://{target}")
    domain = parsed.hostname or target
    url = target if "://" in target else f"https://{domain}"
    print(f"\nScanning {url}")
    wi = whois_info(domain)
    si = ssl_info(domain)
    cc = content_checks(url)
    hc, hf = heuristic_checks(domain)
    rep = {}
    score = wi["is_new"]*3 + (0 if si["valid"] else 2) + (1 if si["valid"] and si["expires_in"]<30 else 0)
    score += (3 if cc["pw_field"] else 0) + (2 if cc["forms"] else 0)
    score += min(cc["keywords"]//10,3) + hc

    if vt_key:
        vt = vt_reputation(domain, vt_key)
        rep["virustotal"] = vt
        if vt["score"]>0:
            score += vt["score"]
    if gsb_key:
        gsb = gsb_check(url, gsb_key)
        rep["gsb"] = gsb
        if gsb["reputation"]=="malicious":
            score += 10

    verdict = "LOW RISK" if score<4 else "MEDIUM RISK" if score<7 else "HIGH RISK"
    result = {"target":url,"whois":wi,"ssl":si,"content":cc,"heuristics":hf,"reputation":rep}
    logging.info(f"Result: {json.dumps(result)} Hash: {hash_data(json.dumps(result))}")
    print(f"WHOIS age:{wi['age_days']}d new?{wi['is_new']}")
    print(f"SSL valid?{si['valid']} expires in:{si['expires_in']}d issuer:{si['issuer']}")
    print(f"Keywords:{cc['keywords']}, pw_field?{cc['pw_field']}, forms?{cc['forms']}")
    if rep:
        print(rep)
    print(f"Heuristic flags: {hf}")
    print(f"Score: {score} → {verdict}")

if __name__=="__main__":
    parser = argparse.ArgumentParser(description="Phishing scanner with reputation")
    parser.add_argument("targets", nargs="+", help="URLs/domains/IPs to scan")
    parser.add_argument("--vt", help="VirusTotal API key")
    parser.add_argument("--gsb", help="Google Safe Browsing API key")
    args = parser.parse_args()
    for t in args.targets:
        scan_target(t, vt_key=args.vt, gsb_key=args.gsb)
