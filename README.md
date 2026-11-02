# Injetor de DLL (Python)

Uma ferramenta simples e funcional para injeção de DLLs em processos do Windows, desenvolvida em Python utilizando chamadas de APIs nativas do sistema.

## 🚀 Como Baixar e Usar (Executável)

Se você deseja apenas utilizar a ferramenta sem precisar instalar o Python:
1. Acesse a pasta `dist` aqui no repositório.
2. Baixe o arquivo `injetor.exe`.
3. Execute o programa como **Administrador** (necessário para ter permissão de ler/escrever na memória dos processos).

> ⚠️ **Aviso sobre Antivírus:** Devido ao uso de funções de manipulação de memória de baixo nível (`OpenProcess`, `VirtualAllocEx`, etc.), o Windows Defender ou outros antivírus podem marcar o executável como um falso positivo. Se isso acontecer, será necessário criar uma exclusão para o arquivo ou rodar o script diretamente pelo código-fonte.

---

## 🛠️ Como Rodar pelo Código-Fonte

Caso prefira rodar diretamente o script Python por segurança ou para fazer modificações:

### Pré-requisitos
* Python 3.x instalado na máquina.

### Execução
1. Abra o terminal na pasta do projeto.
2. Execute o comando:
   ```bash
   python injetor.py
   ```

---

## 📂 Estrutura do Repositório

* `injetor.py`: Código-fonte principal em Python.
* `dist/`: Contém o executável compilado pronto para uso.
* `.gitignore`: Configuração para ignorar arquivos temporários e pastas de build.
