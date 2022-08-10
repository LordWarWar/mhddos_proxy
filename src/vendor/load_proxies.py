import random,codecs,base64;
import requests,json;

def obtain_proxies(url):
    count=len(url)
    for i in range(count):
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
            return data['respons']
        return []
