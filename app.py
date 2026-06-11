"""DNS Scanner Pro - Tkinter GUI.

Use only on domains you own or where you have explicit authorization.
"""

from __future__ import annotations

import csv
import logging
import queue
import threading
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext
import tkinter as tk
from tkinter import ttk

from scanner_core import DNSResolver, ScannerConfig, ScanResult, build_hostname, clean_wordlist, normalize_domain


APP_NAME = "DNS Scanner Pro"
LOG_FILE = "dns_scanner.log"


class DNSScannerApp:
    """Thread-safe Tkinter interface for authorized subdomain enumeration."""

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.config = ScannerConfig()
        self.events: queue.Queue[tuple[str, object]] = queue.Queue()
        self.cancel_event = threading.Event()
        self.worker_thread: threading.Thread | None = None
        self.found_results: list[ScanResult] = []
        self.total_items = 0
        self.processed_items = 0
        self.start_time = 0.0

        self._setup_logging()
        self._setup_window()
        self._create_variables()
        self._create_widgets()
        self._create_menu()
        self.root.after(100, self._process_events)

    def _setup_logging(self) -> None:
        logging.basicConfig(
            filename=LOG_FILE,
            level=logging.INFO,
            format="%(asctime)s | %(levelname)s | %(message)s",
            encoding="utf-8",
        )

    def _setup_window(self) -> None:
        self.root.title(APP_NAME)
        self.root.geometry("920x650")
        self.root.minsize(760, 520)

    def _create_variables(self) -> None:
        self.domain_var = tk.StringVar()
        self.wordlist_var = tk.StringVar(value="wordlist-example.txt")
        self.auth_var = tk.BooleanVar(value=False)
        self.progress_var = tk.DoubleVar(value=0)
        self.status_var = tk.StringVar(value="Pronto")
        self.stats_var = tk.StringVar(value="0 testados | 0 encontrados")

    def _create_widgets(self) -> None:
        main = ttk.Frame(self.root, padding=16)
        main.pack(fill=tk.BOTH, expand=True)

        title = ttk.Label(main, text="DNS Subdomain Scanner", font=("Segoe UI", 18, "bold"))
        title.pack(anchor=tk.W)

        subtitle = ttk.Label(
            main,
            text="Enumeração autorizada de subdomínios por wordlist e resolução DNS.",
        )
        subtitle.pack(anchor=tk.W, pady=(2, 14))

        form = ttk.LabelFrame(main, text="Configuração do scan", padding=12)
        form.pack(fill=tk.X)

        form.columnconfigure(1, weight=1)

        ttk.Label(form, text="Domínio alvo:").grid(row=0, column=0, sticky=tk.W, padx=(0, 8), pady=5)
        domain_entry = ttk.Entry(form, textvariable=self.domain_var)
        domain_entry.grid(row=0, column=1, sticky=tk.EW, pady=5)
        domain_entry.insert(0, "")

        ttk.Label(form, text="Wordlist:").grid(row=1, column=0, sticky=tk.W, padx=(0, 8), pady=5)
        ttk.Entry(form, textvariable=self.wordlist_var).grid(row=1, column=1, sticky=tk.EW, pady=5)
        ttk.Button(form, text="Selecionar", command=self._select_wordlist).grid(row=1, column=2, padx=(8, 0), pady=5)

        auth = ttk.Checkbutton(
            form,
            variable=self.auth_var,
            text="Confirmo que tenho autorização para testar este domínio.",
        )
        auth.grid(row=2, column=1, columnspan=2, sticky=tk.W, pady=(8, 0))

        controls = ttk.Frame(main)
        controls.pack(fill=tk.X, pady=12)

        self.start_button = ttk.Button(controls, text="Iniciar scan", command=self.start_scan)
        self.start_button.pack(side=tk.LEFT)

        self.cancel_button = ttk.Button(controls, text="Cancelar", command=self.cancel_scan, state=tk.DISABLED)
        self.cancel_button.pack(side=tk.LEFT, padx=(8, 0))

        ttk.Button(controls, text="Limpar", command=self.clear_results).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(controls, text="Exportar", command=self.export_results).pack(side=tk.RIGHT)

        progress_frame = ttk.Frame(main)
        progress_frame.pack(fill=tk.X)

        self.progress = ttk.Progressbar(progress_frame, variable=self.progress_var, maximum=100)
        self.progress.pack(fill=tk.X, expand=True, side=tk.LEFT)

        ttk.Label(progress_frame, textvariable=self.stats_var, width=26, anchor=tk.E).pack(side=tk.RIGHT, padx=(12, 0))

        results_frame = ttk.LabelFrame(main, text="Resultados", padding=8)
        results_frame.pack(fill=tk.BOTH, expand=True, pady=(12, 8))

        self.results_text = scrolledtext.ScrolledText(results_frame, wrap=tk.WORD, font=("Consolas", 10))
        self.results_text.pack(fill=tk.BOTH, expand=True)

        status = ttk.Label(main, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W, padding=(6, 3))
        status.pack(fill=tk.X)

    def _create_menu(self) -> None:
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Exportar resultados", command=self.export_results)
        file_menu.add_separator()
        file_menu.add_command(label="Sair", command=self.root.quit)
        menubar.add_cascade(label="Arquivo", menu=file_menu)

        settings_menu = tk.Menu(menubar, tearoff=0)
        settings_menu.add_command(label="Preferências", command=self.show_preferences)
        menubar.add_cascade(label="Configurações", menu=settings_menu)

        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="Sobre", command=self.show_about)
        menubar.add_cascade(label="Ajuda", menu=help_menu)

    def _select_wordlist(self) -> None:
        filename = filedialog.askopenfilename(
            title="Selecionar wordlist",
            filetypes=[("Arquivos de texto", "*.txt"), ("Todos os arquivos", "*.*")],
        )
        if filename:
            self.wordlist_var.set(filename)

    def start_scan(self) -> None:
        try:
            domain = normalize_domain(self.domain_var.get())
        except ValueError as error:
            messagebox.showerror("Domínio inválido", str(error))
            return

        if not self.auth_var.get():
            messagebox.showwarning("Autorização necessária", "Use a ferramenta apenas em domínios próprios ou autorizados.")
            return

        wordlist_path = Path(self.wordlist_var.get()).expanduser()
        if not wordlist_path.exists() or not wordlist_path.is_file():
            messagebox.showerror("Wordlist inválida", "Selecione uma wordlist .txt válida.")
            return

        try:
            lines = wordlist_path.read_text(encoding="utf-8", errors="ignore").splitlines()
            prefixes = clean_wordlist(lines)
        except OSError as error:
            messagebox.showerror("Erro ao ler wordlist", str(error))
            return

        if not prefixes:
            messagebox.showerror("Wordlist vazia", "A wordlist não possui entradas válidas.")
            return

        self.cancel_event.clear()
        self.found_results.clear()
        self.total_items = len(prefixes)
        self.processed_items = 0
        self.start_time = time.perf_counter()
        self.progress_var.set(0)
        self.stats_var.set(f"0 testados | 0 encontrados")
        self.results_text.delete("1.0", tk.END)
        self._append_text(f"Scan iniciado para: {domain}\n")
        self._append_text(f"Entradas válidas na wordlist: {self.total_items}\n")
        self._append_text(f"Registros DNS: {', '.join(self.config.record_types)}\n")
        self._append_text("-" * 70 + "\n")

        self.start_button.config(state=tk.DISABLED)
        self.cancel_button.config(state=tk.NORMAL)
        self.status_var.set("Escaneando...")

        self.worker_thread = threading.Thread(target=self._scan_worker, args=(domain, prefixes), daemon=True)
        self.worker_thread.start()

    def _scan_worker(self, domain: str, prefixes: list[str]) -> None:
        resolver = DNSResolver(self.config)
        iterator = iter(prefixes)
        futures = {}
        completed = 0
        found = 0
        queue_limit = max(self.config.max_threads * 2, 1)

        def submit_next(executor: ThreadPoolExecutor) -> bool:
            if self.cancel_event.is_set():
                return False
            try:
                prefix = next(iterator)
            except StopIteration:
                return False
            hostname = build_hostname(prefix, domain)
            futures[executor.submit(resolver.resolve, hostname)] = hostname
            return True

        try:
            with ThreadPoolExecutor(max_workers=self.config.max_threads) as executor:
                for _ in range(queue_limit):
                    if not submit_next(executor):
                        break

                while futures and not self.cancel_event.is_set():
                    done, _ = wait(futures, timeout=0.15, return_when=FIRST_COMPLETED)
                    if not done:
                        continue

                    for future in done:
                        futures.pop(future, None)
                        completed += 1
                        try:
                            result = future.result()
                        except Exception as error:  # defensive logging only
                            logging.exception("Erro ao resolver host: %s", error)
                            result = None

                        if result:
                            found += 1
                            self.events.put(("result", result))

                        progress = (completed / self.total_items) * 100 if self.total_items else 100
                        self.events.put(("progress", (completed, found, progress)))

                    while len(futures) < queue_limit:
                        if not submit_next(executor):
                            break

                if self.cancel_event.is_set():
                    for future in futures:
                        future.cancel()
                    self.events.put(("finished", (completed, found, True)))
                else:
                    self.events.put(("finished", (completed, found, False)))

        except Exception as error:
            logging.exception("Falha geral no scan")
            self.events.put(("error", str(error)))

    def _process_events(self) -> None:
        while True:
            try:
                event_type, payload = self.events.get_nowait()
            except queue.Empty:
                break

            if event_type == "result":
                result = payload
                if isinstance(result, ScanResult):
                    self.found_results.append(result)
                    self._append_text(result.to_display_line() + "\n")
            elif event_type == "progress":
                completed, found, progress = payload  # type: ignore[misc]
                self.processed_items = int(completed)
                self.progress_var.set(float(progress))
                self.stats_var.set(f"{completed} testados | {found} encontrados")
            elif event_type == "finished":
                completed, found, was_cancelled = payload  # type: ignore[misc]
                self._finish_scan(int(completed), int(found), bool(was_cancelled))
            elif event_type == "error":
                self._finish_with_error(str(payload))

        self.root.after(100, self._process_events)

    def _finish_scan(self, completed: int, found: int, was_cancelled: bool) -> None:
        elapsed = time.perf_counter() - self.start_time
        self.progress_var.set(100 if not was_cancelled else self.progress_var.get())
        self.start_button.config(state=tk.NORMAL)
        self.cancel_button.config(state=tk.DISABLED)

        self._append_text("-" * 70 + "\n")
        if was_cancelled:
            self._append_text(f"Scan cancelado. Testados: {completed}. Encontrados: {found}. Tempo: {elapsed:.2f}s\n")
            self.status_var.set("Cancelado")
        else:
            self._append_text(f"Scan concluído. Testados: {completed}. Encontrados: {found}. Tempo: {elapsed:.2f}s\n")
            self.status_var.set("Concluído")

    def _finish_with_error(self, message: str) -> None:
        self.start_button.config(state=tk.NORMAL)
        self.cancel_button.config(state=tk.DISABLED)
        self.status_var.set("Erro")
        self._append_text(f"[ERROR] {message}\n")
        messagebox.showerror("Erro", message)

    def cancel_scan(self) -> None:
        self.cancel_event.set()
        self.status_var.set("Cancelando...")
        self.cancel_button.config(state=tk.DISABLED)

    def clear_results(self) -> None:
        if self.worker_thread and self.worker_thread.is_alive():
            messagebox.showwarning("Scan em execução", "Cancele o scan antes de limpar os resultados.")
            return
        self.found_results.clear()
        self.results_text.delete("1.0", tk.END)
        self.progress_var.set(0)
        self.stats_var.set("0 testados | 0 encontrados")
        self.status_var.set("Pronto")

    def export_results(self) -> None:
        if not self.found_results:
            messagebox.showwarning("Sem resultados", "Não há subdomínios encontrados para exportar.")
            return

        filename = filedialog.asksaveasfilename(
            title="Exportar resultados",
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv"), ("Texto", "*.txt")],
        )
        if not filename:
            return

        path = Path(filename)
        try:
            if path.suffix.lower() == ".csv":
                with path.open("w", newline="", encoding="utf-8") as file:
                    writer = csv.writer(file)
                    writer.writerow(["hostname", "record_type", "value"])
                    for result in self.found_results:
                        for record in result.records:
                            writer.writerow([result.hostname, record.record_type, record.value])
            else:
                lines = [result.to_display_line() for result in self.found_results]
                path.write_text("\n".join(lines), encoding="utf-8")
            messagebox.showinfo("Exportado", f"Resultados salvos em:\n{path}")
        except OSError as error:
            messagebox.showerror("Erro ao exportar", str(error))

    def show_preferences(self) -> None:
        window = tk.Toplevel(self.root)
        window.title("Preferências")
        window.resizable(False, False)
        window.transient(self.root)
        window.grab_set()

        frame = ttk.Frame(window, padding=16)
        frame.pack(fill=tk.BOTH, expand=True)

        threads_var = tk.IntVar(value=self.config.max_threads)
        timeout_var = tk.DoubleVar(value=self.config.timeout)
        retries_var = tk.IntVar(value=self.config.retries)
        record_vars = {record: tk.BooleanVar(value=record in self.config.record_types) for record in ("A", "AAAA", "CNAME")}

        ttk.Label(frame, text="Threads máximas:").grid(row=0, column=0, sticky=tk.W, pady=5)
        ttk.Spinbox(frame, from_=1, to=100, textvariable=threads_var, width=8).grid(row=0, column=1, sticky=tk.W, pady=5)

        ttk.Label(frame, text="Timeout DNS (s):").grid(row=1, column=0, sticky=tk.W, pady=5)
        ttk.Spinbox(frame, from_=0.5, to=15.0, increment=0.5, textvariable=timeout_var, width=8).grid(
            row=1, column=1, sticky=tk.W, pady=5
        )

        ttk.Label(frame, text="Retries:").grid(row=2, column=0, sticky=tk.W, pady=5)
        ttk.Spinbox(frame, from_=0, to=5, textvariable=retries_var, width=8).grid(row=2, column=1, sticky=tk.W, pady=5)

        ttk.Label(frame, text="Tipos de registro:").grid(row=3, column=0, sticky=tk.W, pady=(10, 5))
        records_frame = ttk.Frame(frame)
        records_frame.grid(row=3, column=1, sticky=tk.W, pady=(10, 5))
        for record, variable in record_vars.items():
            ttk.Checkbutton(records_frame, text=record, variable=variable).pack(side=tk.LEFT, padx=(0, 8))

        def save() -> None:
            selected_records = tuple(record for record, variable in record_vars.items() if variable.get())
            if not selected_records:
                messagebox.showerror("Configuração inválida", "Selecione ao menos um tipo de registro DNS.")
                return
            try:
                self.config = ScannerConfig(
                    max_threads=threads_var.get(),
                    timeout=timeout_var.get(),
                    retries=retries_var.get(),
                    record_types=selected_records,
                )
            except ValueError as error:
                messagebox.showerror("Configuração inválida", str(error))
                return
            self.status_var.set(
                f"Configuração salva: {self.config.max_threads} threads, timeout {self.config.timeout}s"
            )
            window.destroy()

        buttons = ttk.Frame(frame)
        buttons.grid(row=4, column=0, columnspan=2, sticky=tk.E, pady=(16, 0))
        ttk.Button(buttons, text="Cancelar", command=window.destroy).pack(side=tk.RIGHT)
        ttk.Button(buttons, text="Salvar", command=save).pack(side=tk.RIGHT, padx=(0, 8))

    def show_about(self) -> None:
        messagebox.showinfo(
            "Sobre",
            "DNS Scanner Pro\n\nFerramenta educacional para enumeração autorizada de subdomínios.",
        )

    def _append_text(self, text: str) -> None:
        self.results_text.insert(tk.END, text)
        self.results_text.see(tk.END)


def main() -> None:
    root = tk.Tk()
    DNSScannerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
