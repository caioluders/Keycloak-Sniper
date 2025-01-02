# Keycloak-Sniper

Keycloak Sniper - Ferramenta de Testes de Vulnerabilidades

O Keycloak-Sniper é uma ferramenta desenvolvida em Python 3 para realizar testes de segurança em implementações do Keycloak, uma plataforma de gerenciamento de identidade e acesso (IAM - Identity and Access Management). 

O script executa uma série de testes para verificar a presença de vulnerabilidades conhecidas, como XSS, SSRF e outras, além de possibilitar a enumeração de keycloaks ativos e secretkey expostas.

Atenção: Antes de executar este script, garanta que você tem permissão para testar o ambiente. O uso não autorizado pode ser considerado ilegal.

Funcionalidades
O Keycloak-Sniper suporta os seguintes testes:

- Localizar Realms: Localiza os nomes dos realms de uma instância do Keycloak.
- Enumeração de IDs de Clientes: Enumera os IDs de clientes registrados em um realm específico.
- Testar Acesso aos Clientes: Verifica se há acesso a dados sensíveis dos clientes.
- Testar Vulnerabilidade CVE-2020-27838: Verifica a exposição de secretos de client_id e client_secret.
- Testar Vulnerabilidade CVE-2021-20323 (XSS): Verifica vulnerabilidades de Cross-Site Scripting (XSS) no protocolo OpenID Connect e na configuração padrão.
- Verificar Vulnerabilidade CVE-2020-10770 (SSRF): Testa a vulnerabilidade SSRF que pode permitir o acesso a servidores internos.

```
Instalação
Certifique-se de ter o Python 3 instalado em sua máquina. Você pode instalar as dependências necessárias com:

sudo apt install python3-venv python3

python3 -m venv venv

source venv/bin/activate

pip install -r requirements.txt

python3 Keycloak-Sniper.py [opções] --url <url> --realms <arquivo_de_realms>

Opções
-a - Localiza Realms disponíveis: <URL>/auth/realms/{realm-name}
-b - Enumera IDs de clientes: <URL>/auth/realms/{realm-name}/protocol/openid-connect/auth?client_id=account
-c - Testa o acesso aos dados dos clientes: <URL>/auth/admin/realms/{realm-name}/clients
-d - Testa a vulnerabilidade CVE-2020-27838: Exposição de segredo
-e - Testa a vulnerabilidade CVE-2021-20323 (XSS) no OpenID Connect
-f - Testa a vulnerabilidade CVE-2021-20323 (XSS) na configuração padrão
-g - Verifica vulnerabilidade CVE-2020-10770: SSRF
-h - Exibe a ajuda (help)

Parâmetros Obrigatórios
--url - Define a URL base do Keycloak (ex.: https://example.com).
--realms - Define o caminho para o arquivo contendo a lista de realms a serem testados.

Exemplos de Uso
Localizar Realms:

python3 Keycloak-Sniper.py -a --url https://example.com --realms realms.txt

Testar XSS (CVE-2021-20323):

python3 Keycloak-Sniper.py -e --url https://example.com --realms realms.txt

python3 Keycloak-Sniper.py -f --url https://example.com --realms realms.txt

Testar SSRF (CVE-2020-10770):

python3 Keycloak-Sniper.py -g --url https://example.com --realms realms.txt --hook c1746zvrghiftrf8k9j0prdk19.oastify.com

Testar várias opções juntas:

python3 Keycloak-Sniper.py -a -b -d --url https://example.com --realms realms.txt

ou

python3 Keycloak-Sniper.py -abcdef --url https://example.com --realms realms.txt
```


Avisos de Uso
Este script foi desenvolvido para testar a segurança de instâncias Keycloak. Utilize-o com responsabilidade e somente em ambientes que você tem autorização para testar.

O script foi desenvolvido e testado por Carlos Tuma (Bl4dsc4n), versão 0.1.

![image](https://github.com/user-attachments/assets/9d4904b5-d4ea-429c-b03d-d39847fec96d)
