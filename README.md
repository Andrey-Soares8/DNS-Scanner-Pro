# DNS Scanner Pro

Ferramenta gráfica em Python para **enumeração autorizada de subdomínios** via resolução DNS usando wordlists.

> Use apenas em domínios próprios, laboratórios ou ambientes onde você possui autorização explícita.

## Objetivo

Este projeto foi criado para praticar conceitos de reconhecimento, DNS, automação com Python, interface gráfica e execução concorrente de tarefas.

## Funcionalidades

- Interface gráfica com Tkinter
- Enumeração de subdomínios por wordlist
- Resolução de registros `A`, `AAAA` e `CNAME`
- Execução concorrente com `ThreadPoolExecutor`
- Atualização segura da GUI usando `queue.Queue` e `root.after()`
- Validação e normalização do domínio informado
- Limpeza da wordlist: remove comentários, duplicados e entradas inválidas
- Botão para cancelar scan em andamento
- Exportação dos resultados em `.csv` ou `.txt`
- Logging em `dns_scanner.log`

## Tecnologias e conceitos aplicados

- Python 3
- Tkinter
- DNS resolution
- Subdomain enumeration
- Threading
- Queue-based GUI updates
- Validação de entrada
- Exportação CSV
- Logging

## Instalação

```bash
git clone https://github.com/seu-usuario/dns-scanner-pro.git
cd dns-scanner-pro
python -m venv venv
```

No Windows:

```bash
venv\Scripts\activate
pip install -r requirements.txt
```

No Linux/macOS:

```bash
source venv/bin/activate
pip install -r requirements.txt
```

## Como usar

```bash
python app.py
```

Na interface:

1. Informe o domínio alvo, por exemplo `example.com`.
2. Selecione uma wordlist `.txt`.
3. Confirme que possui autorização para testar o domínio.
4. Clique em **Iniciar scan**.
5. Exporte os resultados, se necessário.

## Formato da wordlist

Uma entrada por linha:

```txt
www
mail
api
admin
staging
```

Comentários são ignorados:

```txt
# ambientes comuns
admin
portal
```

## Arquitetura

O projeto separa a lógica principal da interface gráfica:

```txt
scanner_core.py  # validação, wordlist, resolução DNS e modelos de dados
app.py           # interface Tkinter e controle do scan
```

Essa separação facilita testes, manutenção e futuras melhorias.

## Limitações

- A ferramenta não faz brute force agressivo nem bypass de controles.
- Resultados dependem da resolução DNS pública.
- Registros internos ou protegidos por DNS privado não serão encontrados.
- Wordlists muito grandes podem levar tempo, mesmo com threads.

## Melhorias futuras

- Suporte a importação de múltiplas wordlists
- Deduplicação avançada por wildcard DNS
- Relatório HTML
- Modo CLI além da GUI
- Testes unitários adicionais
- Empacotamento com PyInstaller

## Uso ético

Este projeto tem finalidade educacional e defensiva. Não utilize contra domínios de terceiros sem permissão.
