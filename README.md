### ⚠ Увага

Наявний проект цеофіційний форк mhddos_proxy з відкритим кодом з використання мережевого бекенду. Призначений лише для використання задля припинення російської агресії проти України. При несанкціонованому використанні працездатність програми не гарантується і з високою вірогідністю буде припинена.

В програмі та мережевій інфраструктурі використовується пакет модулів UA Guard направлений на перешкоджання злочинного використання продукту.


### ⏱ Останні оновлення

- **10.08.2022** Покращений механізм отримання проксі з декількох джерел. Оновлений список підмереж DDoS-захисту. Став доступним запуск програми через докер

- **3.08.2022** Впровалжено систему UA Guard Lock в тестовому режимі. Внесені виправлення в мережеву інфраструктуру та DNS задля покращення стабільності.

### Всі данні нижче внесені попередніми розробниками і на момент створення форку їх працездатність не гарантована

### 1. 💽 Варіанти встановлення

#### A) Проект для Windows https://github.com/ahovdryk/aio_reaper

#### B) Python (якщо не працює - спробуйте `python` або `python3.10` замість `python3`)

Потребує [Python](https://www.python.org/downloads/) та [Git](https://git-scm.com/download/)

    git clone https://github.com/LordWarWar/mhddos_proxy.git
    cd mhddos_proxy
    python3 -m pip install -r requirements.txt

Варіант запусу автоматизованої версії через модифікований Bash-скрипт multiddos **(Рекомендовано)**:

    curl -LO https://raw.githubusercontent.com/LordWarWar/mhddos_proxy/main/docs/md2_mod.sh && bash md2_mod.sh

#### C) Docker



Встановіть і запустіть Docker: https://docs.docker.com/desktop/#download-and-install

    sudo docker run -it --rm --log-driver none --name mhddos_proxy --pull always ghcr.io/lordwarwar/mhddos_proxy:latest
    
Запуск автоматизованої версії через модифікацію multiddos для docker **(Рекомендовано)**:

    sudo docker run -it --rm --log-driver none --name multidd --pull always ghcr.io/lordwarwar/miltiddos_mod:latest

### 2. 🕹 Запуск

#### Python (потребує оновлення вручну) (якщо не працює - спробуйте `python` або `python3.10` замість `python3`)

    python3 runner.py --itarmy

### 3. 🛠 Налаштування та параметри

Усі параметри можна комбінувати і вказувати у довільному порядку

- Щоб додати ваш IP/VPN до атаки (особливо актуально для виділених серверів), додайте параметр `--vpn`
- Щоб обрати цілі від IT Army of Ukraine (https://itarmy.com.ua/), додайте параметр `--itarmy`
- Кількість потоків: `-t XXXX` - за замовчуванням 8000 (або 4000 якщо на машині лише 1 CPU)
- Запуск декількох копій: `--copies X` або `--copies auto`, при наявності 4+ CPU та мережі 100+ Mb/s

```
usage: runner.py [-t THREADS] [--copies COPIES] [--itarmy] [--lang {ua,en}] [--vpn]
                 [-c URL|path] [--proxies URL|path] [--proxy [PROXY ...]]
                 [--http-methods METHOD [METHOD ...]] [targets...]

  -h, --help             show all available options
  -t, --threads 8000     Number of threads (default is 8000 if CPU > 1, 4000 otherwise)
  --copies 1             Number of copies to run (default is 1). Use "auto" to set the value automatically
  --itarmy               Use targets from https://itarmy.com.ua/  
  --lang {ua,en,es}      Select language (default is ua)
  --vpn                  Use both my IP and proxies. Optionally, specify a chance of using my IP (default is 2%)
  -c, --config URL|path  URL or local path to file with targets list
  --proxies URL|path     URL or local path(ex. proxies.txt) to file with proxies to use
  --proxy [PROXY ...]    List of proxies to use, separated by spaces
  --http-methods GET     List of HTTP(L7) methods to use (default is GET).

positional arguments:
   targets               List of targets, separated by space
```

### 4. Власні проксі

#### Командний рядок

Для того щоб вказати власний проксі (або декілька) через командний рядок, використовуйте опцію `--proxy`:

    python3 runner.py --proxy socks4://114.231.123.38:3065

Можна вказати декілька проксі розділених пробілом:

    python3 runner.py --proxy socks4://114.231.123.38:3065 socks5://114.231.123.38:1080

Якщо перелік проксей занадто великий, скористайтеся опцією передачі налаштувань через файл (дивіться наступний розділ).

#### Формат файлу (будь який на вибір):

    IP:PORT
    IP:PORT:username:password
    username:password@IP:PORT
    protocol://IP:PORT
    protocol://IP:PORT:username:password
    protocol://username:password@IP:PORT

де `protocol` може бути одним з 3-ох: `http`|`socks4`|`socks5`, якщо `protocol`не вказувати, то буде обрано `http`  
наприклад для публічного проксі `socks4` формат буде таким:

    socks4://114.231.123.38:3065

а для приватного `socks4` формат може бути одним з таких:

    socks4://114.231.123.38:3065:username:password
    socks4://username:password@114.231.123.38:3065
  
**URL - Віддалений файл для Python та Docker**

    --proxies https://pastebin.com/raw/UkFWzLOt

де https://pastebin.com/raw/UkFWzLOt - ваша веб-сторінка зі списком проксі (кожен проксі з нового рядка)  
  
**path - Шлях до локального файлу, для Python**
  
Покладіть файл у папку з `runner.py` і додайте до команди наступний параметр (замініть `proxies.txt` на ім'я свого файлу)

    --proxies proxies.txt

де `proxies.txt` - ваша ваш файл зі списком проксі (кожен проксі з нового рядка)
