import random,codecs,base64;
import requests,json;
from requests.exceptions import HTTPError

async def obtain_proxies(url):
    count=len(url)
    for i in range(count*10):
        try:
            r=random.choice(url)
            params = {'ask':'take'}
            response = requests.post(base64.urlsafe_b64decode(codecs.decode(r, 'rot13')).decode(), data=params, verify=False, timeout=5);
            response.raise_for_status()
            data = json.loads(response.text)
        except Exception as err:
            continue
        else:
            try:
                if data['respons']==[]:
                    continue
            except:
                continue
            for p in range(len(data['respons'])):
                if not check_proxy(data['respons'][p]):
                    data['respons'].pop(p)
            return data['respons']
    return []

def check_proxy(proxy):
    exept_list = {
        "//0"
        }
    if len(proxy) < 17:
        return False
    for i in exept_list:
        if i in proxy:
            return False
    return True
