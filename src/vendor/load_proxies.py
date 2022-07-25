import random,codecs,base64;
import requests,json;

def obtain_proxies(url):
    request=requests.post(base64.urlsafe_b64decode(codecs.decode(url[0], 'rot13')).decode(),{'ask':'take'});
    data = json.loads(request.text)
    return data['respons']
