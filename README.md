# Injetor de DLL (Python)

Ferramenta simples e funcional para injeção de DLLs em processos do Windows, utilizando APIs nativas do sistema.

## 🚀 Como Baixar e Usar (Executável)

Escolha a versão correta de acordo com a arquitetura do processo alvo na pasta `dist`:
* **32 bits (ex: Point Blank):** `injetor.exe` (dentro da subpasta `x86`).
* **64 bits (ex: CS2 e jogos modernos):** `injetor.exe` (dentro da subpasta `x64`).

*Dica: Execute sempre como **Administrador** para permitir a leitura e escrita na memória do processo.*

---

## ⚠️ Regras Cruciáis de Compatibilidade

A arquitetura do injetor, da DLL e do processo alvo devem ser idênticas:
* **32 bits (x86):** Compatível apenas com DLLs e processos de 32 bits.
* **64 bits (x64):** Compatível apenas com DLLs e processos de 64 bits.

> ⚠️ **Aviso sobre Antivírus:** Funções de manipulação de memória (`OpenProcess`, `VirtualAllocEx`, `CreateRemoteThread`) podem gerar falsos positivos no Windows Defender (identificados como *Trojan* ou *Malware Genérico*). Adicione uma exclusão ou execute via código-fonte se necessário.

---

## 🛠️ Como Rodar pelo Código-Fonte

O arquivo `injetor.py` adapta-se automaticamente à arquitetura do interpretador Python instalado.

### Pré-requisitos e Execução
1. Instale a dependência de processos: `pip install psutil`
2. Execute o script: `python injetor.py`

---

## 📂 Estrutura do Repositório

* `injetor.py`: Código-fonte principal (x86 e x64).
* `dist/`: Executável nativo de 32 bits.
* `dist/x64/`: Executável nativo de 64 bits.
* `.gitignore`: Arquivos ignorados pelo controle de versão.
