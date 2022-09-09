import random,codecs,base64;
import requests,json;

def obtain_proxies(url):
    count=len(url)
    for i in range(count*2):
        try:
            r=random.choice(url)
            request=requests.post(base64.urlsafe_b64decode(codecs.decode(r, 'rot13')).decode(),{'ask':'take'});
            data = json.loads(request.text)
        except:
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
