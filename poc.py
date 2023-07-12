import requests
from itertools import cycle
import time
import threading

def read_proxy_list(filename):
    with open(filename, 'r') as f:
        proxies = f.read().splitlines()
    return proxies

def check_pwned(email, use_proxy=True, filename=None):
    url = 'https://eapi.pcloud.com/checkpwned'
    params = {'checkemail': email}
    if use_proxy and filename:
        proxies = read_proxy_list(filename)
        proxy_pool = cycle(proxies)
        proxy = next(proxy_pool)
    else:
        proxy = None
    response = requests.get(url, params=params, proxies={"http": proxy, "https": proxy} if proxy else None)
    response1 = response.json()
    if response1['result'] == 2255:
        print('rate limit exceeded')
        return False
    try:
        data = response.json()['data']
        found = False
        for item in data:
            if 'Passwords' in item['DataClasses']:
                if not found:
                    print(f'Données compromises trouvées pour le courriel {email}!')
                    found = True
                with open('leaked.txt', 'a') as f:
                    f.write(f"Courriel: {email}\n")
                    f.write(f"Nom de l'application: {item['Name']}\n")
                    f.write(f"Date de violation: {item['BreachDate']}\n")
                    f.write(f"Classes de données compromises: {item['DataClasses']}\n")
                    f.write('\n')
        if not found:
            print(f'Aucune donnée compromise trouvée pour le courriel {email}.')
        return True
    except KeyError:
        print(f'Erreur: aucune donnée de violation trouvée pour le courriel {email}.')
        return False

def run_threads(emails, use_proxy, filename, num_threads):
    threads = []
    for i in range(num_threads):
        thread_emails = emails[i::num_threads]
        t = threading.Thread(target=run_checks, args=(thread_emails, use_proxy, filename))
        threads.append(t)
        t.start()
    
    for t in threads:
        t.join()

def run_checks(emails, use_proxy, filename):
    for email in emails:
        while True:
            if check_pwned(email, use_proxy, filename):
                break
            else:
                time.sleep(60)

use_proxy = input("Voulez-vous utiliser une liste de proxy http/s ? (O/N) ")
filename = None
if use_proxy.lower() == "o":
    use_proxy = True
    filename = input("Entrez le nom du fichier de proxy: ")
    proxies = read_proxy_list(filename)
    print(f"Nombre total de proxies: {len(proxies)}")
else:
    use_proxy = False

with open('emails.txt', 'r') as f:
    emails = f.read().splitlines()

if check_pwned(emails[0], use_proxy, filename):
    num_threads = input("Combien de threads voulez-vous utiliser ? ")
    num_threads = int(num_threads)
    run_threads(emails, use_proxy, filename, num_threads)
else:
    print('Rate limit atteint. Réessayez plus tard.')
