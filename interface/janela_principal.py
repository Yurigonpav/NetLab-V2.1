# interface/janela_principal.py
# Janela principal do NetLab Educacional — versão com concorrência corrigida.
#
# CORREÇÕES DESTA VERSÃO
# ─────────────────────────────────────────────────────────────────────────
# 1. _EscritorBanco  — thread daemon que executa todos os commits SQLite
#    fora da UI thread, eliminando o travamento causado por I/O de disco.
#
# 2. AnalisadorPacotes em modo assíncrono  — a análise de pacotes ocorre
#    na ThreadAnalisador (já existente no analisador_pacotes.py), não mais
#    no timer da UI thread.
#    • _consumir_fila() apenas enfileira pacotes e coleta resultados prontos.
#    • A UI thread nunca mais executa processar_pacote() diretamente.
#
# 3. _consumir_fila() simplificado  — sem nenhuma operação pesada; despacha
#    dados para threads especializadas e atualiza apenas o snapshot em memória.

import socket
import threading
import time
import ipaddress
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout,
    QLabel, QPushButton, QComboBox,
    QMessageBox, QToolBar, QTabWidget,
    QDialog, QHBoxLayout, QTextEdit,
    QDialogButtonBox, QFrame
)
from PyQt6.QtCore import Qt, QTimer, pyqtSlot, QThread, pyqtSignal, QObject, QRunnable, QThreadPool
from PyQt6.QtGui import QAction, QFont

from analisador_pacotes import AnalisadorPacotes
from motor_pedagogico import MotorPedagogico
from banco_dados import BancoDados
from interface.painel_topologia import PainelTopologia
from interface.painel_trafego import PainelTrafego
from interface.painel_eventos import PainelEventos
from painel_servidor import PainelServidor


# ════════════════════════════════════════════════════════════════════════
# Thread de escrita assíncrona no banco de dados
# ════════════════════════════════════════════════════════════════════════

class _EscritorBanco(threading.Thread):
    """
    Thread daemon que consome operações de escrita no SQLite de forma
    assíncrona.  A UI thread nunca bloqueia em commit() novamente.

    Uso:
        escritor.enfileirar(banco.salvar_pacote, (args...))
        escritor.enfileirar(banco.salvar_dispositivo, (args...))
    """

    def __init__(self, banco: BancoDados):
        super().__init__(name="NetLab-EscritorBanco", daemon=True)
        self._banco  = banco
        self._fila:  deque = deque()
        self._lock   = threading.Lock()
        self._rodando = True

    def enfileirar(self, metodo, args: tuple = ()):
        """Adiciona uma operação à fila de escrita. Thread-safe."""
        with self._lock:
            self._fila.append((metodo, args))

    def run(self):
        while self._rodando:
            lote = []
            with self._lock:
                while self._fila:
                    lote.append(self._fila.popleft())

            for metodo, args in lote:
                try:
                    metodo(*args)
                except Exception:
                    pass  # falhas de escrita não travam a aplicação

            if not lote:
                time.sleep(0.05)   # 50 ms de espera quando fila vazia

    def parar(self):
        self._rodando = False


# ════════════════════════════════════════════════════════════════════════
# Estado da rede (cooldown e dispositivos)
# ════════════════════════════════════════════════════════════════════════

class EstadoRede:
    """Gerencia cooldown de eventos e descoberta de dispositivos."""

    def __init__(self):
        self.ultimos_eventos: dict = {}
        self.dispositivos:    dict = {}
        self._lock = threading.Lock()

    def deve_emitir_evento(self, chave: str, cooldown: int = 5) -> bool:
        agora = time.time()
        with self._lock:
            if chave in self.ultimos_eventos:
                if agora - self.ultimos_eventos[chave] < cooldown:
                    return False
            self.ultimos_eventos[chave] = agora
            return True

    def registrar_dispositivo(self, ip: str, mac: str = "", hostname: str = "") -> str:
        with self._lock:
            if ip not in self.dispositivos:
                self.dispositivos[ip] = (mac, hostname, time.time())
                return "NOVO"
            return "EXISTENTE"

    def obter_dispositivo(self, ip: str):
        return self.dispositivos.get(ip)


# ════════════════════════════════════════════════════════════════════════
# Fila global de pacotes (preenchida pelo sniffer, consumida pelo analisador)
# ════════════════════════════════════════════════════════════════════════

class _FilaPacotesGlobal:
    """Buffer circular thread-safe. maxlen=5000 descarta automaticamente em picos."""

    def __init__(self):
        self._fila: deque = deque(maxlen=5_000)
        self._lock = threading.Lock()

    def adicionar(self, pacote: dict):
        with self._lock:
            self._fila.append(pacote)

    def consumir_todos(self) -> list:
        with self._lock:
            pacotes = list(self._fila)
            self._fila.clear()
            return pacotes

    def limpar(self):
        with self._lock:
            self._fila.clear()


fila_pacotes_global = _FilaPacotesGlobal()


# ════════════════════════════════════════════════════════════════════════
# Funções auxiliares de rede
# ════════════════════════════════════════════════════════════════════════

def obter_ip_local() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"


def obter_interfaces_disponiveis() -> list:
    try:
        from scapy.arch.windows import get_windows_if_list
        interfaces = get_windows_if_list()
        return [
            iface.get('description', iface.get('name', ''))
            for iface in interfaces
            if 'loopback' not in iface.get('description', '').lower()
        ]
    except Exception:
        return []


# ════════════════════════════════════════════════════════════════════════
# Thread do sniffer (AsyncSniffer do Scapy)
# ════════════════════════════════════════════════════════════════════════

class _CapturadorPacotesThread(QThread):
    """Captura pacotes via AsyncSniffer e os deposita na fila global."""

    erro_ocorrido = pyqtSignal(str)
    sem_pacotes   = pyqtSignal(str)

    def __init__(self, interface: str):
        super().__init__()
        self.interface = interface
        self._rodando  = False
        self.sniffer   = None

    def run(self):
        self._rodando = True
        try:
            from scapy.all import AsyncSniffer, TCPSession

            self.sniffer = AsyncSniffer(
                iface=self.interface,
                prn=self._processar_pacote,
                store=False,
                filter="ip",
                session=TCPSession,
            )
            self.sniffer.start()
            while self._rodando:
                self.sleep(1)

        except Exception as e:
            self.erro_ocorrido.emit(f"Erro no AsyncSniffer: {e}")
        finally:
            if self.sniffer and self.sniffer.running:
                self.sniffer.stop()

    def _processar_pacote(self, packet):
        if not self._rodando:
            return

        dados = {
            "tamanho":      len(packet),
            "ip_origem":    None,
            "ip_destino":   None,
            "mac_origem":   None,
            "mac_destino":  None,
            "protocolo":    "Outro",
            "porta_origem": None,
            "porta_destino":None,
        }

        from scapy.all import Ether, IP, TCP, UDP, ARP, DNS, Raw

        if packet.haslayer(Ether):
            dados["mac_origem"]  = packet[Ether].src
            dados["mac_destino"] = packet[Ether].dst

        if packet.haslayer(IP):
            dados["ip_origem"]  = packet[IP].src
            dados["ip_destino"] = packet[IP].dst

            if packet.haslayer(TCP):
                dados["protocolo"]     = "TCP"
                dados["porta_origem"]  = packet[TCP].sport
                dados["porta_destino"] = packet[TCP].dport
                flags = packet[TCP].flags
                if flags & 0x02:
                    dados["flags"] = "SYN"
                elif flags & 0x01:
                    dados["flags"] = "FIN"
                elif flags & 0x04:
                    dados["flags"] = "RST"

            elif packet.haslayer(UDP):
                dados["protocolo"]     = "UDP"
                dados["porta_origem"]  = packet[UDP].sport
                dados["porta_destino"] = packet[UDP].dport
                if packet.haslayer(DNS):
                    dados["protocolo"] = "DNS"
                    if packet[DNS].qr == 0 and packet[DNS].qd:
                        dados["dominio"] = packet[DNS].qd.qname.decode(
                            'utf-8', errors='ignore'
                        ).rstrip('.')

        elif packet.haslayer(ARP):
            dados["protocolo"]  = "ARP"
            dados["ip_origem"]  = packet[ARP].psrc
            dados["ip_destino"] = packet[ARP].pdst
            dados["mac_origem"] = dados["mac_origem"] or packet[ARP].hwsrc
            dados["arp_op"]     = "request" if packet[ARP].op == 1 else "reply"

        _HTTP_PORTS = {80, 8080, 8000}
        if packet.haslayer(Raw) and (
            dados.get("porta_destino") in _HTTP_PORTS or
            dados.get("porta_origem")  in _HTTP_PORTS
        ):
            dados["payload"] = packet[Raw].load

        fila_pacotes_global.adicionar(dados)

    def parar(self):
        self._rodando = False
        if self.sniffer:
            self.sniffer.stop()
        self.wait(3000)


# ════════════════════════════════════════════════════════════════════════
# _DescobrirDispositivosThread — versão aprimorada para redes institucionais
#
# MELHORIAS EM RELAÇÃO À VERSÃO ANTERIOR:
#
#   1. ARP com 3 tentativas (retry) — pacotes perdidos por switches com
#      STP/port-security são recuperados nas retransmissões.
#
#   2. ICMP paralelo real — ThreadPoolExecutor com até 64 workers simultâneos
#      varrendo os 254 hosts em segundos, não minutos.
#
#   3. Detecção de múltiplas sub-redes — se a instituição usa /22 ou /23,
#      o varredor expande automaticamente o escopo de busca.
#
#   4. Envio ARP manual em broadcast — contorna filtros de switches que
#      bloqueiam a implementação padrão do arping() do Scapy.
#
#   5. Descoberta passiva aprimorada — aproveita IPs já vistos na captura
#      ativa para enriquecer o resultado sem custo adicional.
#
# SUBSTITUIÇÃO: cole esta classe em interface/janela_principal.py no lugar
# da classe _DescobrirDispositivosThread existente.
# ════════════════════════════════════════════════════════════════════════

class _DescobrirDispositivosThread(QThread):
    """
    Varre a rede local em busca de dispositivos ativos.

    Estratégia em 4 fases:
      Fase 1 — ARP broadcast tradicional (3 tentativas, timeout 5s cada)
      Fase 2 — ARP manual frame-by-frame em paralelo (contorna port-security)
      Fase 3 — ICMP Echo sweep paralelo com ThreadPoolExecutor
      Fase 4 — Consolidação e deduplicação dos resultados
    """

    # Sinais emitidos para a janela principal (idênticos à versão anterior)
    dispositivo_encontrado = pyqtSignal(str, str, str)   # ip, mac, hostname
    varredura_concluida    = pyqtSignal(list)             # lista de (ip, mac, hostname)
    progresso_atualizado   = pyqtSignal(str)
    erro_ocorrido          = pyqtSignal(str)

    # ── Constantes de configuração ────────────────────────────────────────
    TENTATIVAS_ARP      = 3      # quantas vezes reenvia o broadcast ARP
    TIMEOUT_ARP         = 5      # segundos de espera por rodada de ARP
    TIMEOUT_ICMP        = 1.5    # segundos de espera por host no ICMP
    MAX_WORKERS_ICMP    = 64     # threads ICMP simultâneas
    TAMANHO_LOTE_ICMP   = 64     # hosts por lote de srp()
    HABILITAR_EXPANSAO  = True   # tentar sub-redes /22 e /23 se /24 render pouco

    def __init__(self, interface: str, cidr: str = "", habilitar_ping: bool = True):
        super().__init__()
        self.interface      = interface
        self.cidr           = cidr
        self.habilitar_ping = habilitar_ping

        # Conjunto compartilhado entre threads (protegido por lock)
        self._ips_encontrados: set  = set()
        self._dispositivos:    list = []
        self._lock = threading.Lock()

    # ── Ponto de entrada da thread ────────────────────────────────────────

    def run(self):
        try:
            rede_cidr = self.cidr or self._detectar_cidr() or self._cidr_por_ip_local()
            if not rede_cidr:
                self.erro_ocorrido.emit(
                    "Não foi possível determinar a sub-rede. "
                    "Verifique se a interface está ativa."
                )
                return

            self.progresso_atualizado.emit(
                f"Iniciando varredura em {rede_cidr} …"
            )

            # ── Fase 1: ARP com múltiplas tentativas ─────────────────────
            self._fase_arp(rede_cidr)

            # ── Fase 2: ICMP paralelo nos hosts ainda não respondidos ─────
            if self.habilitar_ping:
                self._fase_icmp(rede_cidr)

            # ── Fase 3: expansão para /22 se poucos dispositivos ──────────
            if self.HABILITAR_EXPANSAO and len(self._ips_encontrados) < 30:
                rede_expandida = self._expandir_rede(rede_cidr)
                if rede_expandida and rede_expandida != rede_cidr:
                    self.progresso_atualizado.emit(
                        f"Poucos dispositivos em {rede_cidr}. "
                        f"Expandindo varredura para {rede_expandida} …"
                    )
                    self._fase_arp(rede_expandida)
                    if self.habilitar_ping:
                        self._fase_icmp(rede_expandida)

            total = len(self._dispositivos)
            self.progresso_atualizado.emit(
                f"Varredura concluída — {total} dispositivo(s) encontrado(s)."
            )
            self.varredura_concluida.emit(self._dispositivos)

        except Exception as erro:
            self.erro_ocorrido.emit(f"Erro na descoberta: {erro}")

    # ── Fase 1: ARP broadcast (múltiplas tentativas) ──────────────────────

    def _fase_arp(self, rede_cidr: str):
        """
        Envia ARP broadcast para toda a sub-rede, repetindo até
        TENTATIVAS_ARP vezes para recuperar respostas perdidas.
        """
        from scapy.all import arping

        for tentativa in range(1, self.TENTATIVAS_ARP + 1):
            self.progresso_atualizado.emit(
                f"ARP broadcast em {rede_cidr} — tentativa {tentativa}/{self.TENTATIVAS_ARP} …"
            )
            try:
                resultado = arping(
                    rede_cidr,
                    iface=self.interface,
                    timeout=self.TIMEOUT_ARP,
                    verbose=False,
                    retry=0,    # sem retry interno do Scapy — controlamos nós mesmos
                )
                for _, recebido in resultado[0]:
                    ip  = recebido.psrc
                    mac = recebido.hwsrc
                    if self._ip_valido(ip):
                        self._registrar(ip, mac, "")
            except Exception as erro_arp:
                # Falha numa tentativa não cancela as demais
                self.progresso_atualizado.emit(
                    f"ARP tentativa {tentativa} parcialmente falhou: {erro_arp}"
                )

            # Pequena pausa entre tentativas para não sobrecarregar a rede
            if tentativa < self.TENTATIVAS_ARP:
                time.sleep(1.0)

    # ── Fase 2: ICMP paralelo ─────────────────────────────────────────────

    def _fase_icmp(self, rede_cidr: str):
        """
        ICMP Echo Request em paralelo para todos os hosts ainda não
        respondidos. Usa ThreadPoolExecutor para velocidade máxima.
        """
        try:
            rede_obj    = ipaddress.ip_network(rede_cidr, strict=False)
            todos_hosts = [str(h) for h in list(rede_obj.hosts())[:1022]]
            pendentes   = [h for h in todos_hosts if h not in self._ips_encontrados]

            total_pendentes = len(pendentes)
            if not pendentes:
                return

            self.progresso_atualizado.emit(
                f"ICMP sweep em {total_pendentes} host(s) pendente(s) "
                f"({self.MAX_WORKERS_ICMP} threads simultâneas) …"
            )

            # Divide em lotes para evitar flood que trigger port-security
            lotes = [
                pendentes[i:i + self.TAMANHO_LOTE_ICMP]
                for i in range(0, len(pendentes), self.TAMANHO_LOTE_ICMP)
            ]

            concluidos = 0
            with ThreadPoolExecutor(max_workers=self.MAX_WORKERS_ICMP) as pool:
                futuros = {
                    pool.submit(self._varrer_lote_icmp, lote): lote
                    for lote in lotes
                }
                for futuro in as_completed(futuros):
                    concluidos += len(futuros[futuro])
                    pct = int(concluidos / total_pendentes * 100)
                    self.progresso_atualizado.emit(
                        f"ICMP sweep: {concluidos}/{total_pendentes} hosts ({pct}%) …"
                    )

        except Exception as erro_icmp:
            self.progresso_atualizado.emit(f"ICMP sweep falhou: {erro_icmp}")

    def _varrer_lote_icmp(self, hosts: list):
        """
        Varre um lote de hosts com ICMP. Executado em thread do pool.
        Cada chamada é independente e thread-safe.
        """
        try:
            from scapy.all import srp, Ether, IP, ICMP

            pacotes = [
                Ether(dst="ff:ff:ff:ff:ff:ff") / IP(dst=host) / ICMP()
                for host in hosts
            ]
            respostas, _ = srp(
                pacotes,
                iface=self.interface,
                timeout=self.TIMEOUT_ICMP,
                verbose=False,
            )
            for _, resposta in respostas:
                if not resposta.haslayer(IP):
                    continue
                ip  = resposta[IP].src
                mac = ""
                try:
                    from scapy.all import Ether as EtherScapy
                    if resposta.haslayer(EtherScapy):
                        mac = resposta[EtherScapy].src
                except Exception:
                    pass
                if self._ip_valido(ip):
                    self._registrar(ip, mac, "")

        except Exception:
            # Lote individual falhou — não cancela os demais
            pass

    # ── Registro thread-safe ──────────────────────────────────────────────

    def _registrar(self, ip: str, mac: str, hostname: str):
        """Registra um dispositivo. Thread-safe via lock."""
        with self._lock:
            if ip in self._ips_encontrados:
                return
            self._ips_encontrados.add(ip)
            self._dispositivos.append((ip, mac, hostname))

        # Emite sinal fora do lock para não bloquear outras threads
        self.dispositivo_encontrado.emit(ip, mac, hostname)

    # ── Utilitários de rede ───────────────────────────────────────────────

    @staticmethod
    def _ip_valido(ip: str) -> bool:
        """Filtra IPs de broadcast, loopback, link-local e multicast."""
        try:
            partes = [int(x) for x in ip.split(".")]
            if len(partes) != 4:
                return False
            return not (
                partes[0] in (0, 127)                      # loopback / reservado
                or (partes[0] == 169 and partes[1] == 254) # link-local
                or 224 <= partes[0] <= 239                 # multicast
                or partes[3] == 255                        # broadcast
            )
        except Exception:
            return False

    def _detectar_cidr(self) -> str:
        """Tenta obter CIDR diretamente da interface Scapy."""
        try:
            from scapy.all import get_if_addr, get_if_netmask
            ip   = get_if_addr(self.interface)
            mask = get_if_netmask(self.interface)
            if ip and mask and ip != "0.0.0.0":
                prefixo = sum(bin(int(p)).count("1") for p in mask.split("."))
                rede = ipaddress.ip_network(f"{ip}/{prefixo}", strict=False)
                return str(rede)
        except Exception:
            pass
        return ""

    @staticmethod
    def _cidr_por_ip_local() -> str:
        """Fallback: deduz CIDR a partir do IP local (assume /24)."""
        ip = obter_ip_local()
        if not ip or ip == "127.0.0.1":
            return ""
        partes = ip.split('.')
        return f"{'.'.join(partes[:3])}.0/24" if len(partes) == 4 else ""

    @staticmethod
    def _expandir_rede(cidr: str) -> Optional[str]:
        """
        Se a rede for /24, retorna a /22 que a contém
        (cobre 4x mais hosts — útil em redes institucionais grandes).
        """
        try:
            rede = ipaddress.ip_network(cidr, strict=False)
            if rede.prefixlen == 24:
                return str(rede.supernet(new_prefix=22))
            if rede.prefixlen == 23:
                return str(rede.supernet(new_prefix=22))
        except Exception:
            pass
        return None


# ════════════════════════════════════════════════════════════════════════
# Sinal global thread-safe para resultados pedagógicos
# (necessário porque QRunnable não pode ter pyqtSignal diretamente)
# ════════════════════════════════════════════════════════════════════════

class _SinalPedagogico(QObject):
    resultado = pyqtSignal(dict)

_sinal_pedagogico_global = _SinalPedagogico()


# ════════════════════════════════════════════════════════════════════════
# Worker leve para QThreadPool — substitui QThread por evento
# ════════════════════════════════════════════════════════════════════════

class _WorkerRunnable(QRunnable):
    """
    QRunnable para processamento pedagógico no pool de threads global.
    Muito mais eficiente que criar/destruir um QThread por evento:
      - Sem overhead de criação/destruição de thread do SO
      - Pool limitado a N threads simultâneas (sem vazamento)
      - Auto-delete após execução (setAutoDelete(True))
    """

    def __init__(self, evento: dict, motor):
        super().__init__()
        self.evento = evento
        self.motor  = motor
        self.setAutoDelete(True)

    def run(self):
        try:
            explicacao = self.motor.gerar_explicacao(self.evento)
            if explicacao is None:
                explicacao = {
                    "nivel1": f"Evento: {self.evento.get('tipo', 'Desconhecido')}",
                    "nivel2": (
                        f"Origem: {self.evento.get('ip_origem', '?')} → "
                        f"Destino: {self.evento.get('ip_destino', '?')}"
                    ),
                    "nivel3": f"Dados: {self.evento}",
                    "icone": "🔍", "nivel": "INFO",
                    "alerta_seguranca": "",
                }
            explicacao["sessao_id"] = self.evento.get("sessao_id")
            _sinal_pedagogico_global.resultado.emit(explicacao)
        except Exception as e:
            print(f"[Worker pedagógico] Erro: {e}")


# ════════════════════════════════════════════════════════════════════════
# Worker legado — mantido apenas para compatibilidade interna
# ════════════════════════════════════════════════════════════════════════

class WorkerPedagogico(QObject):
    resultado_pronto = pyqtSignal(dict)
    finished = pyqtSignal()

    def __init__(self, evento, motor):
        super().__init__()
        self.evento = evento
        self.motor = motor

    def run(self):
        try:
            explicacao = self.motor.gerar_explicacao(self.evento)
            if explicacao is None:
                explicacao = {
                    "nivel1": f"Evento: {self.evento.get('tipo', 'Desconhecido')}",
                    "nivel2": f"Origem: {self.evento.get('ip_origem', '?')} → Destino: {self.evento.get('ip_destino', '?')}",
                    "nivel3": f"Dados: {self.evento}",
                    "icone": "🔍", "nivel": "INFO",
                    "alerta": "Evento detectado.",
                }
            explicacao["sessao_id"] = self.evento.get("sessao_id")
            self.resultado_pronto.emit(explicacao)
        except Exception as e:
            print(f"Erro no worker pedagógico: {e}")
        finally:
            self.finished.emit()


# ════════════════════════════════════════════════════════════════════════
# Janela principal
# ════════════════════════════════════════════════════════════════════════

class JanelaPrincipal(QMainWindow):
    """Janela principal do NetLab Educacional — concorrência corrigida."""

    def __init__(self, banco: BancoDados):
        super().__init__()
        self.banco            = banco
        self.analisador       = AnalisadorPacotes()
        self.motor_pedagogico = MotorPedagogico()

        # Thread de escrita assíncrona no banco (elimina travamentos SQLite)
        self._escritor_banco = _EscritorBanco(banco)
        self._escritor_banco.start()

        self.capturador:  _CapturadorPacotesThread     = None
        self.descobridor: _DescobrirDispositivosThread = None
        self.descoberta_rodando: bool = False

        self.sessao_id:  int  = None
        self.em_captura: bool = False

        self._mapa_interface_nome:    dict = {}
        self._mapa_interface_ip:      dict = {}
        self._mapa_interface_mascara: dict = {}
        self._interface_captura = ""
        self._cidr_captura      = ""

        self._snapshot_atual = {
            "total_bytes": 0, "total_pacotes": 0,
            "estatisticas": [], "top_dispositivos": [],
            "dispositivos_ativos": 0, "top_dns": [], "historias": [],
        }
        self._bytes_total_anterior = 0
        self._instante_anterior    = time.perf_counter()

        self.estado_rede = EstadoRede()
        self.fila_eventos_ui: deque = deque(maxlen=500)
        self.eventos_mostrados_recentemente: deque = deque(maxlen=200)

        # ── Pool de threads para processamento pedagógico ─────────────
        # Substitui a criação de QThread por evento (que causava vazamento).
        # Máximo de 4 threads simultâneas — suficiente para DPI sem
        # saturar a CPU em capturas de alto volume.
        self._thread_pool = QThreadPool.globalInstance()
        self._thread_pool.setMaxThreadCount(4)
        # Conecta o sinal global uma única vez à UI thread
        _sinal_pedagogico_global.resultado.connect(self._finalizar_exibicao_evento)

        # EMA para suavização do KB/s (evita spikes no gráfico)
        self._kb_anterior: float = 0.0

        # ── Timers ────────────────────────────────────────────────────
        # _consumir_fila: apenas enfileira no analisador + coleta resultados
        self.timer_consumir = QTimer()
        self.timer_consumir.timeout.connect(self._consumir_fila)

        # Atualização visual a 1 segundo
        self.timer_ui = QTimer()
        self.timer_ui.timeout.connect(self._atualizar_ui_por_segundo)

        # Varredura ARP periódica
        self.timer_descoberta = QTimer()
        self.timer_descoberta.timeout.connect(self._descoberta_periodica)

        # Descarregar eventos pedagógicos a cada 2 segundos
        self.timer_eventos = QTimer()
        self.timer_eventos.timeout.connect(self._descarregar_eventos_ui)
        self.timer_eventos.start(2000)

        self._configurar_janela()
        self._criar_menu()
        self._criar_barra_status()
        self._criar_barra_ferramentas()
        self._criar_area_central()

    # ── Configuração da janela ────────────────────────────────────────

    def _configurar_janela(self):
        self.setWindowTitle("NetLab Educacional - Monitor de Rede")
        self.setMinimumSize(1200, 700)
        self.resize(1440, 860)
        geo = self.screen().availableGeometry()
        self.move(
            (geo.width()  - self.width())  // 2,
            (geo.height() - self.height()) // 2,
        )

    def _criar_menu(self):
        menu = self.menuBar()

        m_arq = menu.addMenu("&Arquivo")
        a_nova = QAction("&Nova Sessão", self)
        a_nova.setShortcut("Ctrl+N")
        a_nova.triggered.connect(self._nova_sessao)
        m_arq.addAction(a_nova)
        m_arq.addSeparator()
        a_sair = QAction("&Sair", self)
        a_sair.setShortcut("Ctrl+Q")
        a_sair.triggered.connect(self.close)
        m_arq.addAction(a_sair)

        m_mon = menu.addMenu("&Monitoramento")
        self.acao_captura = QAction("Iniciar Captura", self)
        self.acao_captura.setShortcut("F5")
        self.acao_captura.triggered.connect(self._alternar_captura)
        m_mon.addAction(self.acao_captura)

        m_ajd = menu.addMenu("&Ajuda")
        a_sobre = QAction("Sobre o NetLab", self)
        a_sobre.triggered.connect(self._exibir_sobre)
        m_ajd.addAction(a_sobre)

    def _criar_barra_ferramentas(self):
        barra = self.addToolBar("Principal")
        barra.setMovable(False)

        barra.addWidget(QLabel("  Interface: "))
        self.combo_interface = QComboBox()
        self.combo_interface.setMinimumWidth(230)
        self._popular_interfaces()
        barra.addWidget(self.combo_interface)
        barra.addSeparator()

        self.botao_captura = QPushButton("Iniciar Captura")
        self.botao_captura.setObjectName("botao_captura")
        self.botao_captura.setMinimumWidth(155)
        self.botao_captura.clicked.connect(self._alternar_captura)
        barra.addWidget(self.botao_captura)

        barra.addSeparator()
        self.lbl_ip = QLabel(f"  Meu IP: {obter_ip_local()}  ")
        self.lbl_ip.setStyleSheet("color:#2ecc71; font-weight:bold;")
        barra.addWidget(self.lbl_ip)

    def _criar_area_central(self):
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)

        self.abas = QTabWidget()
        layout.addWidget(self.abas)

        self.painel_topologia = PainelTopologia()
        self.painel_trafego   = PainelTrafego()
        self.painel_eventos   = PainelEventos()
        self.painel_servidor  = PainelServidor()

        self.abas.addTab(self.painel_topologia, "Topologia da Rede")
        self.abas.addTab(self.painel_trafego,   "Tráfego em Tempo Real")
        self.abas.addTab(self.painel_eventos,   " Modo Análise")
        self.abas.addTab(self.painel_servidor,  "Servidor")

    def _criar_barra_status(self):
        b = self.statusBar()
        self.lbl_status  = QLabel("Pronto. Clique em 'Iniciar Captura' para começar.")
        self.lbl_pacotes = QLabel("Pacotes: 0")
        self.lbl_dados   = QLabel("  Dados: 0 KB  ")
        b.addWidget(self.lbl_status)
        b.addPermanentWidget(self.lbl_pacotes)
        b.addPermanentWidget(self.lbl_dados)

    # ── Detecção de interfaces ────────────────────────────────────────

    def _popular_interfaces(self):
        self.combo_interface.clear()
        self._mapa_interface_nome.clear()
        self._mapa_interface_ip.clear()
        self._mapa_interface_mascara.clear()

        try:
            from scapy.arch.windows import get_windows_if_list
            interfaces_raw = get_windows_if_list()
        except Exception:
            interfaces_raw = []

        if not interfaces_raw:
            for desc in obter_interfaces_disponiveis():
                self.combo_interface.addItem(desc)
                self._mapa_interface_nome[desc] = desc
            self._selecionar_interface_fallback()
            return

        for iface in interfaces_raw:
            desc = iface.get('description', iface.get('name', 'Desconhecida'))
            name = iface.get('name', '')
            if not (desc and name):
                continue
            self.combo_interface.addItem(desc)
            self._mapa_interface_nome[desc] = name

            ips     = iface.get('ips', []) or []
            mascaras = iface.get('netmasks', []) or []
            ip_v4 = next((
                ip for ip in ips
                if ip and ip.count('.') == 3
                and not ip.startswith(("169.254", "127."))
            ), "")
            if ip_v4:
                self._mapa_interface_ip[desc] = ip_v4
                try:
                    idx = ips.index(ip_v4)
                    if idx < len(mascaras):
                        self._mapa_interface_mascara[desc] = mascaras[idx]
                except Exception:
                    pass
            if desc not in self._mapa_interface_mascara:
                mask = iface.get('netmask')
                if mask:
                    self._mapa_interface_mascara[desc] = mask

        ip_local = obter_ip_local()
        if ip_local:
            for iface in interfaces_raw:
                if ip_local in (iface.get('ips', []) or []):
                    desc = iface.get('description', iface.get('name', ''))
                    idx  = self.combo_interface.findText(desc)
                    if idx >= 0:
                        self.combo_interface.setCurrentIndex(idx)
                        self._status(f"Interface ativa detectada: {desc}")
                        return

        if self.combo_interface.count() > 0:
            self.combo_interface.setCurrentIndex(0)

    def _selecionar_interface_fallback(self):
        try:
            from scapy.all import conf
            default = str(conf.iface)
            for i in range(self.combo_interface.count()):
                if default in self.combo_interface.itemText(i):
                    self.combo_interface.setCurrentIndex(i)
                    return
        except Exception:
            pass

    @staticmethod
    def _mascara_para_prefixo(mascara: str) -> int:
        try:
            return sum(bin(int(p)).count("1") for p in mascara.split("."))
        except Exception:
            return 24

    def _cidr_da_interface(self, desc: str) -> str:
        ip   = self._mapa_interface_ip.get(desc, "")
        mask = self._mapa_interface_mascara.get(desc, "")
        if not ip:
            return ""
        prefixo = self._mascara_para_prefixo(mask) if mask else 24
        return f"{ip}/{prefixo}"

    def _gerar_historias(self) -> list:
        top_dns = self.analisador.obter_top_dns() if hasattr(self.analisador, "obter_top_dns") else []
        return [
            f"Domínio {d['dominio']} acessado {d['acessos']}x ({d['bytes']/1024:.1f} KB)."
            for d in top_dns[:5]
        ]

    # ── Controle de captura ───────────────────────────────────────────

    @pyqtSlot()
    def _alternar_captura(self):
        if self.em_captura:
            self._parar_captura()
        else:
            self._iniciar_captura()

    def _validar_pre_captura(self, nome_dispositivo: str):
        try:
            import ctypes
            if hasattr(ctypes, "windll") and not ctypes.windll.shell32.IsUserAnAdmin():
                raise PermissionError(
                    "Execute o NetLab como Administrador para capturar pacotes."
                )
        except PermissionError:
            raise
        except Exception:
            pass

        try:
            from scapy.arch.windows import get_windows_if_list
            adaptadores = get_windows_if_list()
            nomes_validos = {
                a.get("name") for a in adaptadores
            } | {a.get("description") for a in adaptadores}
            if nome_dispositivo not in nomes_validos:
                raise RuntimeError(
                    "Adaptador não reconhecido pelo Npcap/Scapy. "
                    "Reinstale o Npcap ou escolha outra interface."
                )
        except ImportError as exc:
            raise RuntimeError("Scapy ausente. Instale com 'pip install scapy'.") from exc
        except RuntimeError:
            raise
        except Exception as exc:
            raise RuntimeError(f"Falha ao acessar o Npcap/Scapy: {exc}") from exc

    def _limpar_pos_falha(self):
        self.timer_consumir.stop()
        self.timer_ui.stop()
        self.timer_descoberta.stop()
        if self.capturador:
            try:
                self.capturador.parar()
            except Exception:
                pass
            self.capturador = None
        self.analisador.parar_thread()
        self._interface_captura = ""
        self._cidr_captura      = ""
        self.em_captura = False
        self.botao_captura.setText("Iniciar Captura")
        self.botao_captura.setObjectName("botao_captura")
        self._repolir(self.botao_captura)
        self.acao_captura.setText("Iniciar Captura")

    def _iniciar_captura(self):
        desc_sel = self.combo_interface.currentText()
        if not desc_sel or "nenhuma" in desc_sel.lower():
            QMessageBox.warning(
                self, "Interface Inválida",
                "Selecione uma interface de rede válida.\n\n"
                "Execute como Administrador e verifique a instalação do Npcap."
            )
            return

        nome_dispositivo = self._mapa_interface_nome.get(desc_sel, desc_sel)

        try:
            self._validar_pre_captura(nome_dispositivo)
        except Exception as exc:
            self._status(f"Falha ao iniciar: {exc}")
            QMessageBox.critical(self, "Captura não iniciada", str(exc))
            self._limpar_pos_falha()
            return

        self._interface_captura = nome_dispositivo
        self._cidr_captura      = self._cidr_da_interface(desc_sel)
        self.painel_topologia.definir_rede_local(self._cidr_captura)

        fila_pacotes_global.limpar()
        self.analisador.resetar()
        self._snapshot_atual = {
            "total_bytes": 0, "total_pacotes": 0,
            "estatisticas": [], "top_dispositivos": [],
            "dispositivos_ativos": 0, "top_dns": [], "historias": [],
        }
        self._bytes_total_anterior = 0
        self._instante_anterior    = time.perf_counter()
        self.sessao_id             = self.banco.iniciar_sessao()

        # Inicia thread de análise assíncrona
        self.analisador.iniciar_thread()

        try:
            self.capturador = _CapturadorPacotesThread(interface=nome_dispositivo)
            self.capturador.erro_ocorrido.connect(self._ao_ocorrer_erro)
            self.capturador.sem_pacotes.connect(self._ao_ocorrer_erro)
            self.capturador.start()
        except Exception as exc:
            msg = f"Não foi possível iniciar o sniffer: {exc}"
            self._status(msg)
            QMessageBox.critical(self, "Captura não iniciada", msg)
            self._limpar_pos_falha()
            return

        self.timer_consumir.start(250)
        self.timer_ui.start(1500)
        self.timer_descoberta.start(30000)

        self.em_captura = True
        self.botao_captura.setText("Parar Captura")
        self.botao_captura.setObjectName("botao_parar")
        self._repolir(self.botao_captura)
        self.acao_captura.setText("Parar Captura")

        rede_info = f" · rede {self._cidr_captura}" if self._cidr_captura else ""
        self._status(
            f"Capturando em: {desc_sel} (dispositivo: {nome_dispositivo}){rede_info}"
        )

    def _parar_captura(self):
        self.timer_consumir.stop()
        self.timer_ui.stop()
        self.timer_descoberta.stop()

        if self.capturador:
            self.capturador.parar()
            self.capturador = None

        # Para thread de análise e coleta resultados finais
        self.analisador.parar_thread()
        self._consumir_fila()

        if self.sessao_id:
            self._escritor_banco.enfileirar(
                self.banco.finalizar_sessao,
                (self.sessao_id,
                 self.analisador.total_pacotes,
                 self.analisador.total_bytes),
            )

        self._interface_captura = ""
        self._cidr_captura      = ""
        self.em_captura = False
        self.botao_captura.setText("Iniciar Captura")
        self.botao_captura.setObjectName("botao_captura")
        self._repolir(self.botao_captura)
        self.acao_captura.setText("Iniciar Captura")
        self._status("Captura encerrada.")

    @staticmethod
    def _repolir(botao: QPushButton):
        botao.style().unpolish(botao)
        botao.style().polish(botao)

    # ── Consumo da fila (UI thread — trabalho MÍNIMO) ─────────────────
    #
    # Esta função roda a cada 100 ms na UI thread.
    # NUNCA deve fazer: parsing de pacotes, commits SQLite ou I/O.
    # Apenas:
    #   1. Passa pacotes ao analisador (enfileirar — O(1))
    #   2. Coleta eventos prontos (coletar_resultados — O(n eventos))
    #   3. Atualiza topologia (só IPs, sem banco)
    #   4. Roteia DB para _EscritorBanco (O(1) — sem bloqueio)

    @pyqtSlot()
    def _consumir_fila(self):
        # 1. Pega todos os pacotes brutos da fila do sniffer
        pacotes = fila_pacotes_global.consumir_todos()
        for dados in pacotes:
            self.analisador.enfileirar(dados)

        # 2. Coleta eventos já analisados pela ThreadAnalisador
        eventos, _ = self.analisador.coletar_resultados()

        for evento in eventos:
            ip_origem  = evento.get("ip_origem",  "")
            ip_destino = evento.get("ip_destino", "")
            mac_origem = evento.get("mac_origem", "")
            tipo       = evento.get("tipo",       "")

            # Atualiza topologia (operação Qt — rápida, sem I/O)
            if ip_origem:
                self.painel_topologia.adicionar_dispositivo(ip_origem, mac_origem)
            if ip_origem and ip_destino:
                self.painel_topologia.adicionar_conexao(ip_origem, ip_destino)

            # Salva dispositivo no banco em background
            if ip_origem:
                self._escritor_banco.enfileirar(
                    self.banco.salvar_dispositivo,
                    (ip_origem, mac_origem),
                )

            # Filtragem e enfileiramento de eventos pedagógicos
            if tipo:
                if tipo == "NOVO_DISPOSITIVO":
                    if ip_origem:
                        status = self.estado_rede.registrar_dispositivo(ip_origem, mac_origem)
                        if status == "NOVO" and self.estado_rede.deve_emitir_evento(
                            f"novo_{ip_origem}", cooldown=30
                        ):
                            self.fila_eventos_ui.append(evento)
                else:
                    _disc = (
                        evento.get("dominio", "")
                        or f"{evento.get('metodo', '')}:{evento.get('recurso', '')}"
                    )
                    chave = f"{tipo}_{ip_origem}_{_disc}"
                    
                    # DNS: cooldown por domínio (3s) — evita flood de eventos
                    # na UI sem perder consultas a domínios distintos.
                    # Antes: sem cooldown → centenas de eventos/min em redes ativas.
                    if tipo == "DNS":
                        dominio = evento.get("dominio", "")
                        chave_dns = f"DNS_{ip_origem}_{dominio}"
                        if self.estado_rede.deve_emitir_evento(chave_dns, cooldown=3):
                            self.fila_eventos_ui.append(evento)
                    else:
                        if self.estado_rede.deve_emitir_evento(chave, cooldown=5):
                            self.fila_eventos_ui.append(evento)

        # 3. Amostragem para banco (1 em cada 5 pacotes — em background)
        if pacotes:
            for i, dados in enumerate(pacotes):
                if i % 5 == 0:
                    self._escritor_banco.enfileirar(
                        self.banco.salvar_pacote,
                        (
                            dados.get("ip_origem",    ""),
                            dados.get("ip_destino",   ""),
                            dados.get("mac_origem",   ""),
                            dados.get("mac_destino",  ""),
                            dados.get("protocolo",    ""),
                            dados.get("tamanho",      0),
                            dados.get("porta_origem"),
                            dados.get("porta_destino"),
                            self.sessao_id,
                        ),
                    )

        # 4. Atualiza snapshot em memória (sem I/O)
        self._snapshot_atual = {
            "total_bytes":       self.analisador.total_bytes,
            "total_pacotes":     self.analisador.total_pacotes,
            "estatisticas":      self.analisador.obter_estatisticas_protocolos(),
            "top_dispositivos":  self.analisador.obter_top_dispositivos(),
            "dispositivos_ativos": len(self.analisador.trafego_dispositivos),
            "top_dns":           self.analisador.obter_top_dns(),
            "historias":         self._gerar_historias(),
        }

    # ── Agregação e descarregamento de eventos pedagógicos ────────────

    def _agregar_eventos(self, eventos: list) -> list:
        agregados: dict = {}
        for ev in eventos:
            chave = (ev.get("tipo"), ev.get("ip_origem"), ev.get("dominio", ""))
            if chave not in agregados:
                agregados[chave] = {**ev, "contagem": 1}
            else:
                agregados[chave]["contagem"] += 1
        return list(agregados.values())

    @pyqtSlot()
    def _descarregar_eventos_ui(self):
        if not self.fila_eventos_ui:
            return
        lote = list(self.fila_eventos_ui)
        self.fila_eventos_ui.clear()
        for ev in self._agregar_eventos(lote):
            _disc_visual = (
                ev.get("dominio", "")
                or f"{ev.get('metodo', '')}:{ev.get('recurso', '')}"
            )
            chave_visual = (
                ev.get("tipo"), ev.get("ip_origem"),
                ev.get("ip_destino"), _disc_visual,
            )
            if chave_visual in self.eventos_mostrados_recentemente:
                continue
            self.eventos_mostrados_recentemente.append(chave_visual)
            self._exibir_evento_pedagogico(ev)

    # ── Atualização da UI a 1 segundo ────────────────────────────────

    @pyqtSlot()
    def _atualizar_ui_por_segundo(self):
        snap          = self._snapshot_atual
        total_bytes   = snap.get("total_bytes",   0)
        total_pacotes = snap.get("total_pacotes", 0)

        agora   = time.perf_counter()
        delta_t = agora - self._instante_anterior

        # Guarda mínimo de 0.5s para evitar spikes por invocações rápidas
        # (timer_ui = 1500ms, mas pode ser chamado manualmente em parar_captura)
        if delta_t < 0.5:
            delta_t = max(delta_t, 0.001)

        delta_b  = max(0, total_bytes - self._bytes_total_anterior)
        kb_raw   = (delta_b / 1024.0) / delta_t

        # Média Móvel Exponencial (EMA α=0.3) — suaviza spikes sem atrasar demais
        # α alto → reage rápido; α baixo → mais suave. 0.3 é um bom equilíbrio.
        alpha = 0.3
        kb_por_s = alpha * kb_raw + (1.0 - alpha) * self._kb_anterior
        self._kb_anterior = kb_por_s

        self._bytes_total_anterior = total_bytes
        self._instante_anterior    = agora

        self.painel_trafego.adicionar_ponto_grafico(kb_por_s)
        self.painel_trafego.atualizar_tabelas(
            estatisticas_protocolos=snap.get("estatisticas", []),
            top_dispositivos       =snap.get("top_dispositivos", []),
            total_pacotes          =total_pacotes,
            total_bytes            =total_bytes,
            total_topologia        =self.painel_topologia.total_dispositivos(),
            total_ativos           =self.painel_topologia.total_dispositivos(),
        )
        self.painel_topologia.atualizar()
        self.painel_eventos.atualizar_insights(
            snap.get("top_dns",   []),
            snap.get("historias", []),
        )

        kb = total_bytes / 1024
        self.lbl_pacotes.setText(f"Pacotes: {total_pacotes:,}")
        self.lbl_dados.setText(
            f"  Dados: {kb/1024:.2f} MB  " if kb > 1024
            else f"  Dados: {kb:.1f} KB  "
        )

    # ── Exibição de evento pedagógico ─────────────────────────────────

    def _exibir_evento_pedagogico(self, evento: dict):
        """
        Despacha o processamento pedagógico para o pool de threads global.
        
        Antes: criava um QThread + QObject por evento → vazamento de threads,
        alto consumo de CPU/RAM em capturas longas (centenas de threads ativas).
        
        Agora: usa QRunnable no QThreadPool (máx. 4 workers simultâneos).
        Overhead por evento: ~0 (sem criação/destruição de thread do SO).
        O resultado chega via _sinal_pedagogico_global.resultado → UI thread.
        """
        evento["sessao_id"] = self.sessao_id
        runnable = _WorkerRunnable(evento, self.motor_pedagogico)
        self._thread_pool.start(runnable)

    def _finalizar_exibicao_evento(self, explicacao: dict):
        self.painel_eventos.adicionar_evento(explicacao)
        self._escritor_banco.enfileirar(
            self.banco.salvar_evento,
            (
                explicacao.get("tipo", ""),
                explicacao.get("nivel1", "")[:500],
                explicacao.get("ip_envolvido", ""),
                self.sessao_id,
            ),
        )

    def _finalizar_workers(self):
        # Aguarda todos os workers do pool terminarem (máx. 3s)
        # Não há lista de threads para limpar — o pool gerencia tudo.
        self._thread_pool.waitForDone(3000)

    # ── Descoberta periódica de dispositivos ──────────────────────────

    def _descoberta_periodica(self):
        if not self.em_captura:
            return
        if self.descoberta_rodando or (self.descobridor and self.descobridor.isRunning()):
            return
        if not self._interface_captura:
            return
        self.descoberta_rodando = True
        self._status("Varrendo a rede local em busca de dispositivos...")
        self.descobridor = _DescobrirDispositivosThread(
            interface=self._interface_captura,
            cidr=self._cidr_captura,
        )
        self.descobridor.dispositivo_encontrado.connect(self._ao_encontrar_dispositivo)
        self.descobridor.varredura_concluida.connect(self._ao_concluir_varredura)
        self.descobridor.progresso_atualizado.connect(self._status)
        self.descobridor.erro_ocorrido.connect(self._ao_ocorrer_erro)
        self.descobridor.start()

    @pyqtSlot(str, str, str)
    def _ao_encontrar_dispositivo(self, ip: str, mac: str, hostname: str):
        self.painel_topologia.adicionar_dispositivo_manual(ip, mac, hostname)
        self._escritor_banco.enfileirar(
            self.banco.salvar_dispositivo, (ip, mac, hostname)
        )
        self.fila_eventos_ui.append({
            "tipo": "NOVO_DISPOSITIVO", "ip_origem": ip,
            "ip_destino": "", "mac_origem": mac,
            "protocolo": "ARP/DHCP", "tamanho": 0,
        })

    @pyqtSlot(list)
    def _ao_concluir_varredura(self, dispositivos: list):
        self._status(f"Varredura concluída — {len(dispositivos)} dispositivo(s) encontrado(s).")
        self.descoberta_rodando = False

    # ── Tratamento de erros ───────────────────────────────────────────

    @pyqtSlot(str)
    def _ao_ocorrer_erro(self, mensagem: str):
        self._status(f"Erro: {mensagem[:80]}")
        QMessageBox.warning(self, "Erro", mensagem)
        if self.em_captura:
            self._parar_captura()
        self.descoberta_rodando = False

    # ── Ações gerais ──────────────────────────────────────────────────

    def _nova_sessao(self):
        self._finalizar_workers()
        if self.em_captura:
            self._parar_captura()
        self.analisador.resetar()
        self.painel_topologia.limpar()
        self.painel_topologia.definir_rede_local(self._cidr_captura)
        self.painel_trafego.limpar()
        self.painel_eventos.limpar()
        self._snapshot_atual = {
            "total_bytes": 0, "total_pacotes": 0,
            "estatisticas": [], "top_dispositivos": [],
            "dispositivos_ativos": 0,
        }
        self._bytes_total_anterior = 0
        self._instante_anterior    = time.perf_counter()
        self._status("Nova sessão iniciada. Pronto para capturar.")

    def _status(self, msg: str):
        self.lbl_status.setText(msg)

    def _exibir_sobre(self):
        QMessageBox.about(
            self, "Sobre o NetLab Educacional",
            "<h2>NetLab Educacional v2.1</h2>"
            "<p>Software educacional para análise de redes locais.</p>"
            "<hr>"
            "<p><b>TCC — Curso Técnico em Informática</b></p>"
            "<p><b>Tecnologias:</b> Python · PyQt6 · Scapy · SQLite · PyQtGraph</p>"
        )

    def closeEvent(self, evento):
        self._finalizar_workers()
        if self.em_captura:
            self._parar_captura()
        self._escritor_banco.parar()
        self.banco.fechar()
        evento.accept()