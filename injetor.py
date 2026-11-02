"""Carregador Win32 por LoadLibraryW, com validacao e confirmacao do modulo.

Python, DLL e processo precisam ter a mesma arquitetura (x86 ou x64).
Nao altera privilegios nem tenta contornar bloqueios de acesso.
"""
import ctypes as c
from ctypes import wintypes as w
import os
from pathlib import Path
import queue
import struct
import sys
import threading
import time
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import psutil

MACHINES = {0x014C: 'x86', 0x8664: 'x64'}
PROCESS_RIGHTS = 0x0002 | 0x0400 | 0x0008 | 0x0020 | 0x0010
WAIT_OBJECT_0, WAIT_TIMEOUT, WAIT_FAILED = 0, 258, 0xFFFFFFFF


class ModuleEntry(c.Structure):
    _fields_ = [('dwSize', w.DWORD), ('th32ModuleID', w.DWORD),
                ('th32ProcessID', w.DWORD), ('GlblcntUsage', w.DWORD),
                ('ProccntUsage', w.DWORD), ('modBaseAddr', c.c_void_p),
                ('modBaseSize', w.DWORD), ('hModule', w.HMODULE),
                ('szModule', w.WCHAR * 256), ('szExePath', w.WCHAR * 260)]


def dll_machine(path):
    """Valida o PE sem carregar ou executar a DLL no injetor."""
    with open(path, 'rb') as stream:
        size = os.fstat(stream.fileno()).st_size
        dos = stream.read(64)
        if len(dos) != 64 or dos[:2] != b'MZ':
            raise ValueError('O arquivo nao possui cabecalho PE valido.')
        pe = struct.unpack_from('<I', dos, 60)[0]
        if pe < 64 or pe > size - 24:
            raise ValueError('Cabecalho PE fora do arquivo.')
        stream.seek(pe)
        header = stream.read(24)
        if header[:4] != b'PE\0\0':
            raise ValueError('Assinatura PE invalida.')
        machine = struct.unpack_from('<H', header, 4)[0]
        flags = struct.unpack_from('<H', header, 22)[0]
        optional_size = struct.unpack_from('<H', header, 20)[0]
        if machine not in MACHINES or not flags & 0x2000:
            raise ValueError('Selecione uma DLL nativa x86 ou x64.')
        if optional_size < 2 or pe + 24 + optional_size > size:
            raise ValueError('Cabecalho opcional invalido.')
        magic = stream.read(2)
        expected = b'\x0b\x01' if machine == 0x14C else b'\x0b\x02'
        if magic != expected:
            raise ValueError('Arquitetura inconsistente no arquivo PE.')
        return machine


class Win32:
    def __init__(self):
        if sys.platform != 'win32':
            raise RuntimeError('Este programa requer Windows.')
        self.k = c.WinDLL('kernel32', use_last_error=True)
        signatures = {
            'OpenProcess': ([w.DWORD, w.BOOL, w.DWORD], w.HANDLE),
            'CloseHandle': ([w.HANDLE], w.BOOL),
            'GetCurrentProcess': ([], w.HANDLE),
            'IsWow64Process2': ([w.HANDLE, c.POINTER(w.WORD), c.POINTER(w.WORD)], w.BOOL),
            'GetProcessTimes': ([w.HANDLE] + [c.POINTER(w.FILETIME)] * 4, w.BOOL),
            'VirtualAllocEx': ([w.HANDLE, c.c_void_p, c.c_size_t, w.DWORD, w.DWORD], c.c_void_p),
            'VirtualFreeEx': ([w.HANDLE, c.c_void_p, c.c_size_t, w.DWORD], w.BOOL),
            'WriteProcessMemory': ([w.HANDLE, c.c_void_p, c.c_void_p, c.c_size_t, c.POINTER(c.c_size_t)], w.BOOL),
            'GetModuleHandleW': ([w.LPCWSTR], w.HMODULE),
            'GetProcAddress': ([w.HMODULE, w.LPCSTR], c.c_void_p),
            'GetModuleHandleExW': ([w.DWORD, c.c_void_p, c.POINTER(w.HMODULE)], w.BOOL),
            'GetModuleFileNameW': ([w.HMODULE, w.LPWSTR, w.DWORD], w.DWORD),
            'CreateToolhelp32Snapshot': ([w.DWORD, w.DWORD], w.HANDLE),
            'Module32FirstW': ([w.HANDLE, c.POINTER(ModuleEntry)], w.BOOL),
            'Module32NextW': ([w.HANDLE, c.POINTER(ModuleEntry)], w.BOOL),
            'CreateRemoteThread': ([w.HANDLE, c.c_void_p, c.c_size_t, c.c_void_p,
                                    c.c_void_p, w.DWORD, c.POINTER(w.DWORD)], w.HANDLE),
            'WaitForSingleObject': ([w.HANDLE, w.DWORD], w.DWORD),
            'GetExitCodeThread': ([w.HANDLE, c.POINTER(w.DWORD)], w.BOOL),
        }
        for name, (args, result) in signatures.items():
            try:
                function = getattr(self.k, name)
            except AttributeError as exc:
                raise RuntimeError(f'API {name} indisponivel nesta versao do Windows.') from exc
            function.argtypes, function.restype = args, result

    @staticmethod
    def error(operation):
        code = c.get_last_error()
        return OSError(code, f'{operation}: {c.FormatError(code).strip()} (Win32 {code})')

    def architecture(self, process):
        machine, native = w.WORD(), w.WORD()
        if not self.k.IsWow64Process2(process, c.byref(machine), c.byref(native)):
            raise self.error('IsWow64Process2')
        actual = machine.value or native.value
        if actual not in MACHINES:
            raise ValueError('Arquitetura nao suportada; use alvos Windows x86 ou x64.')
        return actual

    def modules(self, pid):
        snapshot = None
        for _ in range(5):
            snapshot = self.k.CreateToolhelp32Snapshot(0x18, pid)
            if snapshot != c.c_void_p(-1).value:
                break
            if c.get_last_error() != 24:  # ERROR_BAD_LENGTH: lista mudou.
                raise self.error('Snapshot de modulos')
            time.sleep(0.02)
        if snapshot in (None, c.c_void_p(-1).value):
            raise self.error('Snapshot de modulos')
        try:
            entry = ModuleEntry()
            entry.dwSize = c.sizeof(entry)
            result = []
            ok = self.k.Module32FirstW(snapshot, c.byref(entry))
            while ok:
                result.append(dict(name=entry.szModule, path=entry.szExePath,
                                   base=entry.modBaseAddr, size=entry.modBaseSize))
                ok = self.k.Module32NextW(snapshot, c.byref(entry))
            if c.get_last_error() != 18:
                raise self.error('Enumeracao de modulos')
            return result
        finally:
            self.k.CloseHandle(snapshot)

    def remote_loader(self, modules):
        # GetProcAddress pode retornar uma rotina encaminhada ao KernelBase.
        kernel = self.k.GetModuleHandleW('kernel32.dll')
        if not kernel:
            raise self.error('GetModuleHandleW(kernel32)')
        address = self.k.GetProcAddress(kernel, b'LoadLibraryW')
        if not address:
            raise self.error('GetProcAddress(LoadLibraryW)')
        owner = w.HMODULE()
        if not self.k.GetModuleHandleExW(0x6, address, c.byref(owner)):
            raise self.error('Localizar modulo da rotina LoadLibraryW')
        buffer = c.create_unicode_buffer(32768)
        length = self.k.GetModuleFileNameW(owner, buffer, len(buffer))
        if not length or length >= len(buffer):
            raise self.error('GetModuleFileNameW')
        matches = [m for m in modules if same_file(m['path'], buffer.value)]
        if len(matches) != 1:
            raise RuntimeError('Nao foi possivel identificar no alvo a mesma biblioteca do carregador local.')
        module = matches[0]
        offset = address - owner.value
        if not 0 <= offset < module['size']:
            raise RuntimeError('Rotina de carregamento fora dos limites do modulo alvo.')
        return module['base'] + offset


def same_file(first, second):
    try:
        return os.path.samefile(first, second)
    except OSError:
        return os.path.normcase(os.path.abspath(first)) == os.path.normcase(os.path.abspath(second))


def inject_dll(pid, path, log=lambda message: None, expected_created=None):
    path = str(Path(path).expanduser().resolve(strict=True))
    if not os.path.isfile(path) or '\0' in path:
        raise ValueError('Selecione um arquivo DLL valido.')
    machine = dll_machine(path)
    api = Win32()
    local_machine = api.architecture(api.k.GetCurrentProcess())
    if local_machine != machine:
        raise ValueError(f'DLL {MACHINES[machine]} e Python {MACHINES[local_machine]} incompativeis. '
                         f'Execute este script com Python {MACHINES[machine]}.')
    process = thread = remote = None
    finished = False
    try:
        process = api.k.OpenProcess(PROCESS_RIGHTS, False, pid)
        if not process:
            raise api.error('OpenProcess')
        if expected_created is not None:
            created, exited, kernel, user = (w.FILETIME() for _ in range(4))
            if not api.k.GetProcessTimes(process, c.byref(created), c.byref(exited), c.byref(kernel), c.byref(user)):
                raise api.error('GetProcessTimes')
            timestamp = ((created.dwHighDateTime << 32) | created.dwLowDateTime) / 10_000_000 - 11644473600
            if abs(timestamp - expected_created) > 0.001:
                raise RuntimeError('O PID foi reutilizado por outro processo. Atualize a lista.')
        target_machine = api.architecture(process)
        if machine != target_machine:
            raise ValueError(f'DLL {MACHINES[machine]} e processo {MACHINES[target_machine]} incompativeis.')
        log(f'[INFO] Python, DLL e processo: {MACHINES[machine]}. PID {pid}.')
        loader = api.remote_loader(api.modules(pid))
        payload = path.encode('utf-16-le') + b'\0\0'
        remote = api.k.VirtualAllocEx(process, None, len(payload), 0x3000, 0x04)
        if not remote:
            raise api.error('VirtualAllocEx')
        written = c.c_size_t()
        buffer = c.create_string_buffer(payload)
        if not api.k.WriteProcessMemory(process, remote, buffer, len(payload), c.byref(written)):
            raise api.error('WriteProcessMemory')
        if written.value != len(payload):
            raise RuntimeError(f'Escrita parcial: {written.value}/{len(payload)} bytes.')
        thread_id = w.DWORD()
        thread = api.k.CreateRemoteThread(process, None, 0, loader, remote, 0, c.byref(thread_id))
        if not thread:
            raise api.error('CreateRemoteThread')
        log(f'[INFO] Thread {thread_id.value} criada. Aguardando o carregamento...')
        result = api.k.WaitForSingleObject(thread, 15000)
        if result == WAIT_TIMEOUT:
            log('[AGUARDANDO] O carregamento ultrapassou 15 segundos. A memoria sera mantida ate a thread terminar.')
            result = api.k.WaitForSingleObject(thread, 0xFFFFFFFF)
        if result == WAIT_FAILED:
            raise api.error('WaitForSingleObject')
        if result != WAIT_OBJECT_0:
            raise RuntimeError(f'Retorno de espera inesperado: {result}.')
        finished = True
        exit_code = w.DWORD()
        if not api.k.GetExitCodeThread(thread, c.byref(exit_code)):
            raise api.error('GetExitCodeThread')
        # O retorno de uma thread e DWORD; nao use como HMODULE completo em x64.
        matches = [m for m in api.modules(pid) if same_file(m['path'], path)]
        if not matches or (machine == 0x14C and exit_code.value == 0):
            raise RuntimeError(f'Carregamento nao confirmado: DLL ausente da lista de modulos '
                               f'ou retorno nulo (thread=0x{exit_code.value:08X}). '
                               'Verifique dependencias, inicializacao da DLL e bloqueios de acesso. '
                               'Uma DLL que se descarrega rapidamente tambem pode nao ser observada.')
        log(f"[OK] DLL confirmada no processo: {matches[0]['base']:#x}. Isso nao valida o funcionamento interno da DLL.")
        return matches[0]
    finally:
        if remote and process:
            if not thread or finished:
                if not api.k.VirtualFreeEx(process, remote, 0, 0x8000):
                    log(f'[LIMPEZA] {api.error("VirtualFreeEx")}')
            else:
                log('[LIMPEZA] A thread pode continuar ativa; o buffer remoto nao foi liberado para evitar uso apos liberacao.')
        for handle in (thread, process):
            if handle and not api.k.CloseHandle(handle):
                log(f'[LIMPEZA] {api.error("CloseHandle")}')


class InjetorApp:
    def __init__(self, root):
        self.root, self.busy = root, False
        self.events = queue.Queue()
        self.processos_disponiveis = {}
        self.dll_path_var = tk.StringVar()
        self.status_var = tk.StringVar(value=f'Python {c.sizeof(c.c_void_p) * 8} bits. Selecione uma DLL e um processo.')
        root.title('Injetor de DLL - Win32')
        root.geometry('620x480')
        root.minsize(540, 440)
        root.maxsize(600, 500)
        #cor da janela
        root.configure(bg="#444242")
        tk.Label(root, text='1. Selecione a DLL:',fg="white", bg="#444242", font=('Arial', 10, 'bold')).pack(anchor='w', padx=15, pady=(15, 5))
        file_frame = tk.Frame(root)
        file_frame.pack(fill='x', padx=15)
        self.path_entry = tk.Entry(file_frame, textvariable=self.dll_path_var)
        self.path_entry.pack(side='left', fill='x', expand=True, ipady=3)
        self.browse = tk.Button(file_frame, padx=20, fg="white", bg="#1C349C", text='Procurar...', command=self.procurar_dll)
        self.browse.pack(side='right', padx=(5, 0))
        tk.Label(root, text='2. Selecione o processo:', fg="white", bg="#444242", font=('Arial', 10, 'bold')).pack(anchor='w', padx=15, pady=(15, 5)) 
        proc_frame = tk.Frame(root)
        proc_frame.pack(fill='x', padx=15)
        self.combo_proc = ttk.Combobox(proc_frame, state='readonly')
        self.combo_proc.pack(side='left', fill='x', expand=True, ipady=3)
        self.refresh = tk.Button(proc_frame, fg="white", bg="#1C349C", text='Atualizar', command=self.listar_processos)
        self.refresh.pack(side='right', padx=(5, 0))
        self.btn_injetar = tk.Button(root, text='CARREGAR DLL',fg="white", bg="#1C349C", font=('Arial', 12, 'bold'), command=self.executar_injecao)
        self.btn_injetar.pack(fill='x', padx=15, pady=15, ipady=6)
        tk.Label(root, textvariable=self.status_var, anchor='w', wraplength=580).pack(fill='x', padx=15)
        frame = tk.Frame(root)
        frame.pack(fill='both', expand=True, padx=15, pady=(8, 15))
        self.output = tk.Text(frame, height=9, state='disabled', wrap='word', font=('Consolas', 10))
        bar = ttk.Scrollbar(frame, command=self.output.yview)
        self.output.configure(yscrollcommand=bar.set)
        bar.pack(side='right', fill='y')
        self.output.pack(side='left', fill='both', expand=True)
        self.listar_processos()
        root.after(100, self.poll)
        root.protocol('WM_DELETE_WINDOW', self.close)

    def procurar_dll(self):
        path = filedialog.askopenfilename(title='Selecionar DLL', filetypes=[('DLL', '*.dll')])
        if path:
            self.dll_path_var.set(os.path.normpath(path))

    def listar_processos(self):
        previous = self.combo_proc.get()
        self.processos_disponiveis.clear()
        for process in psutil.process_iter(['pid', 'name', 'create_time', 'memory_info']):
            try:
                info = process.info
                if not info['name'] or info['pid'] == os.getpid() or info['create_time'] is None:
                    continue
                self.processos_disponiveis[f"{info['name']} (PID: {info['pid']}) ({info['memory_info'].rss // 1024 // 1024} MB)"] = (info['pid'], info['create_time'])
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        items = sorted(self.processos_disponiveis, key=str.casefold)
        self.combo_proc['values'] = items
        selected = previous if previous in self.processos_disponiveis else ''
        if not selected:
            # Nao escolhe arbitrariamente entre varias instancias do jogo.
            pb = [item for item in items if 'pointblank' in item.casefold()]
            if len(pb) == 1:
                selected = pb[0]
        self.combo_proc.set(selected)

    def log(self, text):
        self.output.configure(state='normal')
        self.output.insert('end', text + '\n')
        self.output.see('end')
        self.output.configure(state='disabled')

    def set_busy(self, busy):
        self.busy = busy
        for control in (self.browse, self.refresh, self.path_entry, self.btn_injetar):
            control.configure(state='disabled' if busy else 'normal')
        self.combo_proc.configure(state='disabled' if busy else 'readonly')

    def executar_injecao(self):
        selected = self.processos_disponiveis.get(self.combo_proc.get())
        if selected is None:
            messagebox.showerror('Processo', 'Selecione um processo ativo da lista.')
            return
        path = self.dll_path_var.get().strip().strip('"')
        if not path or not os.path.isfile(path):
            messagebox.showerror('DLL', 'Selecione um arquivo DLL existente.')
            return
        self.set_busy(True)
        self.status_var.set('Validando e carregando... acompanhe o log.')
        self.log(f'[INICIO] PID {selected[0]} | {path}')
        def work():
            try:
                result = inject_dll(selected[0], path,
                                    lambda text: self.events.put(('log', text)), selected[1])
                self.events.put(('success', result))
            except Exception as exc:
                self.events.put(('error', str(exc)))
        threading.Thread(target=work, daemon=True).start()

    def poll(self):
        try:
            while True:
                kind, value = self.events.get_nowait()
                if kind == 'log':
                    self.log(value)
                elif kind == 'success':
                    self.set_busy(False)
                    self.status_var.set('DLL confirmada na lista de modulos do processo.')
                    messagebox.showinfo('Carregamento confirmado', 'A DLL foi localizada no processo. Confira os logs da propria DLL para validar o diagnostico.')
                else:
                    self.set_busy(False)
                    self.status_var.set('Falha: consulte o log.')
                    self.log(f'[ERRO] {value}')
                    messagebox.showerror('Falha', value)
        except queue.Empty:
            pass
        self.root.after(100, self.poll)

    def close(self):
        if self.busy:
            messagebox.showwarning('Operacao em andamento', 'Aguarde a conclusao. Fechar a interface nao cancela uma thread ja iniciada no processo alvo.')
            return
        self.root.destroy()


if __name__ == '__main__':
    if sys.platform != 'win32':
        raise SystemExit('Este programa requer Windows.')
    root = tk.Tk()
    app = InjetorApp(root)
    root.mainloop()
