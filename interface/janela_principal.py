# interface/janela_principal.py
# Janela principal do NetLab Educacional — VERSÃO OTIMIZADA v3.0
#
# ARQUITETURA DE PERFORMANCE
# ──────────────────────────
#  Captura (AsyncSniffer)
#       │  fila_pacotes_global  ←  buffer circular deque(maxlen=5000)
#       ▼                           evita acumulação ilimitada em picos
#  _ProcessadorThread  (QThread background)
#       │  Processa lotes de até MAX_LOTE pacotes por ciclo (50 ms)
#       │  Possui seu próprio AnalisadorPacotes (sem disputa de lock com GUI)
#       │  Emite sinais batch para a main thread:
#       │    • snapshot_pronto(dict)    → estado consolidado a cada 500 ms
#       │    • batch_conexoes(list)     → (ip_src, ip_dst, mac_src)
#       │    • batch_eventos(list)      → eventos detectados
#       │    • batch_banco(list)        → pacotes a salvar no DB
#       ▼
#  Main thread  (apenas recebe sinais e atualiza UI)
#       │  timer_ui (1 s)       → gráfico de throughput + labels
#       │  timer_insights (30 s) → passa snapshot p/ painel de insights
#       │  timer_eventos (2 s)  → descarrega eventos na lista visual
#       └  timer_descoberta (30 s) → varredura ARP periódica
#
# EXTENSÃO C NATIVA (opcional)
#  Se netlab_core estiver compilado e disponível, _ProcessadorThread usa
#  nl_adicionar_pacote() para contagem/estatísticas de alta frequência,
#  reduzindo overhead do Python puro para parsing/agregação.

import socket
import threading
import time
from collections import deque

from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout,
    QLabel, QPushButton, QComboBox,
    QMessageBox, QToolBar, QTabWidget,
    QDialog, QHBoxLayout, QTextEdit,
    QDialogButtonBox, QFrame
)
from PyQt6.QtCore import Qt, QTimer, pyqtSlot, QThread, pyqtSignal
from PyQt6.QtGui import QAction, QFont

from analisador_pacotes import AnalisadorPacotes
from motor_pedagogico import MotorPedagogico
from banco_dados import BancoDados
from interface.painel_topologia import PainelTopologia
from interface.painel_trafego import PainelTrafego
from interface.painel_eventos import PainelEventos
from painel_servidor import PainelServidor

# Tenta carregar a extensão C nativa; usa fallback Python se ausente.
try:
    from netlab_core import NetlabCore as _NetlabCore
    _CORE_NATIVO = True
except ImportError:
    _CORE_NATIVO = False

# ============================================================================
# EstadoRede
# ============================================================================

class EstadoRede:
    """Gerencia estado da rede, cooldown de eventos e descoberta de dispositivos."""
    def __init__(self):
        self.ultimos_eventos = {}
        self.dispositivos    = {}
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

    def resetar(self):
        with self._lock:
            self.ultimos_eventos.clear()
            self.dispositivos.clear()

# ============================================================================
# Buffer Circular Global de Pacotes (thread-safe)
# ============================================================================

class _FilaPacotesGlobal:
    """
    Buffer circular thread-safe usando deque(maxlen).
    Com maxlen=5000 o deque descarta automaticamente pacotes antigos em
    picos de tráfego, limitando o consumo de memória sem perder controle.
    """
    _CAPACIDADE = 5_000

    def __init__(self):
        self._fila = deque(maxlen=self._CAPACIDADE)
        self._lock  = threading.Lock()

    def adicionar(self, pacote: dict):
        with self._lock:
            self._fila.append(pacote)

    def consumir_lote(self, maximo: int = 200) -> list:
        """Retira até `maximo` pacotes do buffer de forma atômica."""
        with self._lock:
            lote = []
            for _ in range(min(maximo, len(self._fila))):
                lote.append(self._fila.popleft())
            return lote

    def consumir_todos(self) -> list:
        with self._lock:
            pacotes = list(self._fila)
            self._fila.clear()
            return pacotes

    def limpar(self):
        with self._lock:
            self._fila.clear()

    def tamanho(self) -> int:
        return len(self._fila)


fila_pacotes_global = _FilaPacotesGlobal()

# ============================================================================
# Funções auxiliares de rede
# ============================================================================

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
            if iface.get('description', '') and
               'loopback' not in iface.get('description', '').lower()
        ]
    except Exception:
        return []

# ============================================================================
# Thread de Captura de Pacotes (AsyncSniffer)
# ============================================================================

class _CapturadorPacotesThread(QThread):
    """Thread que captura pacotes usando AsyncSniffer do Scapy."""
    erro_ocorrido = pyqtSignal(str)
    sem_pacotes   = pyqtSignal(str)

    # Portas HTTP onde capturamos payload
    _HTTP_PORTS = frozenset({80, 8080, 8000})

    def __init__(self, interface: str):
        super().__init__()
        self.interface = interface
        self._running  = False
        self.sniffer   = None

    def run(self):
        self._running = True
        try:
            from scapy.all import AsyncSniffer, TCPSession
            self.sniffer = AsyncSniffer(
                iface=self.interface,
                prn=self._processar_pacote,
                store=False,
                filter="ip",
                session=TCPSession
            )
            self.sniffer.start()
            while self._running:
                self.sleep(1)
        except Exception as e:
            self.erro_ocorrido.emit(f"Erro no AsyncSniffer: {str(e)}")
        finally:
            if self.sniffer and self.sniffer.running:
                self.sniffer.stop()

    def _processar_pacote(self, packet):
        if not self._running:
            return

        from scapy.all import Ether, IP, TCP, UDP, ARP, DNS, Raw

        dados = {
            "tamanho":       len(packet),
            "ip_origem":     None,
            "ip_destino":    None,
            "mac_origem":    None,
            "mac_destino":   None,
            "protocolo":     "Outro",
            "porta_origem":  None,
            "porta_destino": None,
        }

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
                        qname = packet[DNS].qd.qname.decode('utf-8', errors='ignore')
                        dados["dominio"] = qname.rstrip('.')

        elif packet.haslayer(ARP):
            dados["protocolo"]  = "ARP"
            dados["ip_origem"]  = packet[ARP].psrc
            dados["ip_destino"] = packet[ARP].pdst
            if not dados["mac_origem"]:
                dados["mac_origem"]  = packet[ARP].hwsrc
            if not dados["mac_destino"]:
                dados["mac_destino"] = packet[ARP].hwdst
            dados["arp_op"] = "request" if packet[ARP].op == 1 else "reply"

        # Payload HTTP (apenas nas portas HTTP configuradas)
        pd = dados.get("porta_destino")
        po = dados.get("porta_origem")
        if packet.haslayer(Raw) and (pd in self._HTTP_PORTS or po in self._HTTP_PORTS):
            dados["payload"] = packet[Raw].load

        fila_pacotes_global.adicionar(dados)

    def parar(self):
        self._running = False
        if self.sniffer:
            try:
                self.sniffer.stop()
            except Exception:
                pass
        self.wait(3000)

# ============================================================================
# Thread de Processamento de Pacotes (desacoplada da UI)
# ============================================================================

class _ProcessadorThread(QThread):
    """
    Background thread que:
      1. Drena lotes do buffer circular fila_pacotes_global
      2. Chama AnalisadorPacotes.processar_pacote() internamente
      3. Emite sinais batch para que a main thread atualize UI e banco

    DESACOPLAMENTO
    ──────────────
    Coleta (Sniffer) → fila_pacotes_global → _ProcessadorThread → signals → UI
    Cada estágio opera em seu próprio ritmo; a fila absorve variações.

    EXTENSÃO C NATIVA
    ─────────────────
    Se netlab_core estiver disponível, usa nl_adicionar_pacote() para
    contabilidade de alta frequência (bytes/protocolo/segundo), evitando
    overhead de dicionários Python em caminhos críticos.
    """
    snapshot_pronto = pyqtSignal(dict)   # estatísticas consolidadas (a cada ~500 ms)
    batch_conexoes  = pyqtSignal(list)   # [(ip_src, ip_dst, mac_src), ...]
    batch_eventos   = pyqtSignal(list)   # [evento_dict, ...]
    batch_banco     = pyqtSignal(list)   # [dados_pacote, ...] para salvar no DB

    _LOTE_MAXIMO     = 200   # pacotes por ciclo de processamento
    _INTERVALO_MS    = 50    # intervalo de polling da fila (ms)
    _CICLOS_SNAPSHOT = 10    # emite snapshot a cada N ciclos (10 × 50 ms = 500 ms)

    # Mapeamento protocolo → índice para o núcleo C
    _PROTO_IDX = {
        "TCP": 0, "UDP": 1, "DNS": 2, "HTTP": 3,
        "HTTPS": 4, "ARP": 5, "ICMP": 6, "DHCP": 7,
        "TCP_SYN": 8,
    }

    def __init__(self, parent=None):
        super().__init__(parent)
        self.analisador = AnalisadorPacotes()
        self._running   = False
        self._ciclos    = 0
        self._core      = _NetlabCore() if _CORE_NATIVO else None

    def resetar(self):
        """Reinicia o estado interno do analisador (chamado antes de nova sessão)."""
        self.analisador.resetar()
        if self._core:
            self._core.resetar()

    def run(self):
        self._running = True
        self._ciclos  = 0
        while self._running:
            self._processar_lote()
            self._ciclos += 1
            if self._ciclos % self._CICLOS_SNAPSHOT == 0:
                self._emitir_snapshot()
            self.msleep(self._INTERVALO_MS)

        # Drena e emite snapshot final antes de encerrar
        self._processar_lote()
        self._emitir_snapshot()

    def _processar_lote(self):
        pacotes = fila_pacotes_global.consumir_lote(self._LOTE_MAXIMO)
        if not pacotes:
            return

        conexoes   = []
        eventos    = []
        banco_lote = []

        for dados in pacotes:
            evento     = self.analisador.processar_pacote(dados)
            ip_origem  = dados.get("ip_origem",  "")
            ip_destino = dados.get("ip_destino", "")
            mac_origem = dados.get("mac_origem", "")
            protocolo  = dados.get("protocolo",  "Outro")

            # Registra no núcleo C para métricas de alta frequência
            if self._core:
                idx = self._PROTO_IDX.get(protocolo, 9)
                self._core.adicionar_pacote(idx, dados.get("tamanho", 0))

            if ip_origem or ip_destino:
                conexoes.append((ip_origem, ip_destino, mac_origem))

            if evento and evento.get("tipo"):
                eventos.append(evento)

            # Amostragem DB: 1 em cada 5 pacotes
            if self.analisador.total_pacotes % 5 == 0:
                banco_lote.append(dados)

        # Emite apenas se houver dados para processar
        if conexoes:
            self.batch_conexoes.emit(conexoes)
        if eventos:
            self.batch_eventos.emit(eventos)
        if banco_lote:
            self.batch_banco.emit(banco_lote)

    def _emitir_snapshot(self):
        """Constrói e emite o snapshot consolidado de estatísticas."""
        snap = {
            "total_bytes":        self.analisador.total_bytes,
            "total_pacotes":      self.analisador.total_pacotes,
            "estatisticas":       self.analisador.obter_estatisticas_protocolos(),
            "top_dispositivos":   self.analisador.obter_top_dispositivos(),
            "dispositivos_ativos": len(
                getattr(self.analisador, "trafego_dispositivos", {})
            ),
            "top_dns": self.analisador.obter_top_dns(),
        }
        # Enriquece com métricas do núcleo C se disponível
        if self._core:
            snap["bps_core"] = self._core.bytes_por_segundo(1000)
        self.snapshot_pronto.emit(snap)

    def obter_totais(self) -> tuple:
        """Retorna (total_pacotes, total_bytes) — usado ao finalizar sessão."""
        return self.analisador.total_pacotes, self.analisador.total_bytes

    def parar(self):
        self._running = False
        self.wait(4000)

# ============================================================================
# Thread de Descoberta de Dispositivos (ARP)
# ============================================================================

class _DescobrirDispositivosThread(QThread):
    dispositivo_encontrado = pyqtSignal(str, str, str)
    varredura_concluida    = pyqtSignal(list)
    progresso_atualizado   = pyqtSignal(str)
    erro_ocorrido          = pyqtSignal(str)

    def __init__(self, interface: str, cidr: str = "", habilitar_ping: bool = True):
        super().__init__()
        self.interface     = interface
        self.cidr          = cidr
        self.habilitar_ping = habilitar_ping

    def run(self):
        try:
            rede = self.cidr or self._cidr_por_interface() or self._cidr_por_ip_local()
            if not rede:
                self.erro_ocorrido.emit(
                    "Não foi possível determinar a sub-rede da interface selecionada."
                )
                return

            self.progresso_atualizado.emit(f"Varredura ARP em andamento ({rede})...")

            from scapy.all import arping
            resultado  = arping(rede, iface=self.interface, timeout=2, verbose=False)
            dispositivos = []
            vistos     = set()

            for sent, received in resultado[0]:
                ip  = received.psrc
                mac = received.hwsrc
                if not self._ip_util(ip):
                    continue
                chave = (ip, mac)
                if chave in vistos:
                    continue
                vistos.add(chave)
                dispositivos.append((ip, mac, ""))
                self.dispositivo_encontrado.emit(ip, mac, "")

            self.progresso_atualizado.emit(
                f"Varredura concluída: {len(dispositivos)} dispositivo(s)."
            )
            self.varredura_concluida.emit(dispositivos)
        except Exception as e:
            self.erro_ocorrido.emit(f"Erro na descoberta: {str(e)}")

    @staticmethod
    def _ip_util(ip: str) -> bool:
        if not ip:
            return False
        try:
            partes = [int(p) for p in ip.split(".")]
            if len(partes) != 4:
                return False
            if partes[0] in (127, 0):
                return False
            if partes[0] == 169 and partes[1] == 254:
                return False
            if 224 <= partes[0] <= 239:
                return False
            if partes[3] == 255:
                return False
            return True
        except Exception:
            return False

    def _cidr_por_interface(self) -> str:
        try:
            from scapy.all import get_if_addr, get_if_netmask
            ip_iface = get_if_addr(self.interface)
            mascara  = get_if_netmask(self.interface)
            if ip_iface and mascara:
                bits = sum(bin(int(p)).count('1') for p in mascara.split('.'))
                return f"{ip_iface}/{bits}"
        except Exception:
            pass
        return ""

    @staticmethod
    def _cidr_por_ip_local() -> str:
        ip_local = obter_ip_local()
        if not ip_local or ip_local == "127.0.0.1":
            return ""
        partes = ip_local.split('.')
        if len(partes) == 4:
            return f"{'.'.join(partes[:3])}.0/24"
        return ""

# ============================================================================
# JANELA PRINCIPAL
# ============================================================================

class JanelaPrincipal(QMainWindow):
    """Janela principal do NetLab Educacional — pipeline desacoplada v3.0."""

    def __init__(self, banco: BancoDados):
        super().__init__()
        self.banco            = banco
        self.motor_pedagogico = MotorPedagogico()

        # Threads gerenciadas
        self.capturador:   _CapturadorPacotesThread    = None
        self.processador:  _ProcessadorThread          = None
        self.descobridor:  _DescobrirDispositivosThread = None
        self.descoberta_rodando: bool = False

        self.sessao_id:  int  = None
        self.em_captura: bool = False

        # Mapeamento interface
        self._mapa_interface_nome    = {}
        self._mapa_interface_ip      = {}
        self._mapa_interface_mascara = {}
        self._interface_captura      = ""
        self._cidr_captura           = ""

        # Snapshot único — sempre atualizado pelo sinal snapshot_pronto
        self._snapshot_atual = {
            "total_bytes":        0,
            "total_pacotes":      0,
            "estatisticas":       [],
            "top_dispositivos":   [],
            "dispositivos_ativos": 0,
            "top_dns":            [],
            "historias":          [],
        }
        self._bytes_total_anterior = 0
        self._instante_anterior    = time.perf_counter()

        # Estado de cooldown e deduplicação
        self.estado_rede = EstadoRede()
        # Buffer circular de eventos pendentes de exibição
        self.fila_eventos_ui = deque(maxlen=500)
        # Buffer circular de deduplicação visual
        self.eventos_mostrados_recentemente = deque(maxlen=200)

        # ── Timers da main thread ──────────────────────────────────────────
        # Atualiza gráfico de throughput + labels de status (1 s)
        self.timer_ui = QTimer()
        self.timer_ui.timeout.connect(self._atualizar_ui_por_segundo)

        # Atualiza Insights (30 s) — intervalo baixo, sem re-renders desnecessários
        self.timer_insights = QTimer()
        self.timer_insights.setInterval(30_000)
        self.timer_insights.timeout.connect(self._atualizar_insights_periodico)

        # Descarrega eventos na lista visual (2 s)
        self.timer_eventos = QTimer()
        self.timer_eventos.timeout.connect(self._descarregar_eventos_ui)
        self.timer_eventos.start(2_000)

        # Varredura ARP periódica (30 s) — inicia junto com captura
        self.timer_descoberta = QTimer()
        self.timer_descoberta.timeout.connect(self._descoberta_periodica)

        self._configurar_janela()
        self._criar_menu()
        self._criar_barra_status()
        self._criar_barra_ferramentas()
        self._criar_area_central()

    # ──────────────────────────────────────────────────────────────────────
    # Configuração da janela e menus
    # ──────────────────────────────────────────────────────────────────────

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

        m_arq   = menu.addMenu("&Arquivo")
        a_nova  = QAction("&Nova Sessão", self)
        a_nova.setShortcut("Ctrl+N")
        a_nova.triggered.connect(self._nova_sessao)
        m_arq.addAction(a_nova)
        m_arq.addSeparator()
        a_sair  = QAction("&Sair", self)
        a_sair.setShortcut("Ctrl+Q")
        a_sair.triggered.connect(self.close)
        m_arq.addAction(a_sair)

        m_mon   = menu.addMenu("&Monitoramento")
        self.acao_captura = QAction("Iniciar Captura", self)
        self.acao_captura.setShortcut("F5")
        self.acao_captura.triggered.connect(self._alternar_captura)
        m_mon.addAction(self.acao_captura)

        m_ajd   = menu.addMenu("&Ajuda")
        a_sobre = QAction("Sobre o NetLab", self)
        a_sobre.triggered.connect(self._exibir_sobre)
        m_ajd.addAction(a_sobre)

    def _criar_barra_ferramentas(self):
        barra = self.addToolBar("Principal")
        barra.setMovable(False)

        barra.addWidget(QLabel("  Interface: "))
        self.combo_interface = QComboBox()
        self.combo_interface.setMinimumWidth(230)
        self.combo_interface.setToolTip(
            "Interface de rede a ser monitorada.\n"
            "A interface ativa é selecionada automaticamente."
        )
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
        self.abas.addTab(self.painel_trafego,   "Trafego em Tempo Real")
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

    # ──────────────────────────────────────────────────────────────────────
    # Detecção de interfaces
    # ──────────────────────────────────────────────────────────────────────

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
            ip_v4   = next(
                (ip for ip in ips
                 if ip and ip.count('.') == 3
                 and not ip.startswith("169.254")
                 and not ip.startswith("127.")),
                ""
            )
            if ip_v4:
                self._mapa_interface_ip[desc] = ip_v4
                try:
                    idx = ips.index(ip_v4)
                    if idx < len(mascaras):
                        self._mapa_interface_mascara[desc] = mascaras[idx]
                except Exception:
                    pass
            if desc not in self._mapa_interface_mascara:
                mascara_unitaria = iface.get('netmask')
                if mascara_unitaria:
                    self._mapa_interface_mascara[desc] = mascara_unitaria

        ip_local = obter_ip_local()
        if ip_local:
            for iface in interfaces_raw:
                if ip_local in (iface.get('ips') or []):
                    desc = iface.get('description', iface.get('name', ''))
                    if desc:
                        idx = self.combo_interface.findText(desc)
                        if idx >= 0:
                            self.combo_interface.setCurrentIndex(idx)
                            self._status(f"Interface ativa detectada: {desc}")
                            return

        if self.combo_interface.count() > 0:
            self.combo_interface.setCurrentIndex(0)

    def _selecionar_interface_fallback(self):
        try:
            from scapy.all import conf
            default_iface = str(conf.iface)
            for i in range(self.combo_interface.count()):
                if default_iface in self.combo_interface.itemText(i):
                    self.combo_interface.setCurrentIndex(i)
                    return
        except Exception:
            pass
        try:
            ip_local    = obter_ip_local()
            ultimo_octeto = ip_local.split(".")[-1] if ip_local else ""
            for i in range(self.combo_interface.count()):
                if ultimo_octeto and ultimo_octeto in self.combo_interface.itemText(i):
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

    def _cidr_da_interface(self, descricao_iface: str) -> str:
        ip_iface = self._mapa_interface_ip.get(descricao_iface)
        mascara  = self._mapa_interface_mascara.get(descricao_iface, "")
        if not ip_iface:
            return ""
        if mascara:
            prefixo = self._mascara_para_prefixo(mascara)
            return f"{ip_iface}/{prefixo}"
        return f"{ip_iface}/24"

    # ──────────────────────────────────────────────────────────────────────
    # Controle de captura
    # ──────────────────────────────────────────────────────────────────────

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
                    "Execute o NetLab como Administrador para que o Npcap "
                    "permita a captura de pacotes."
                )
        except Exception:
            pass
        try:
            from scapy.arch.windows import get_windows_if_list
            adaptadores   = get_windows_if_list()
            nomes_validos = (
                {a.get("name") for a in adaptadores}
                | {a.get("description") for a in adaptadores}
            )
            if nome_dispositivo not in nomes_validos:
                raise RuntimeError(
                    "Adaptador não reconhecido pelo Npcap/Scapy. "
                    "Reinstale o Npcap ou escolha outra interface."
                )
        except ImportError as exc:
            raise RuntimeError(
                "Biblioteca Scapy ausente. "
                "Instale-a com 'pip install scapy'."
            ) from exc
        except RuntimeError:
            raise
        except Exception as exc:
            raise RuntimeError(f"Falha ao acessar o Npcap/Scapy: {exc}") from exc

    def _limpar_pos_falha(self):
        self.timer_ui.stop()
        self.timer_insights.stop()
        self.timer_descoberta.stop()
        if self.capturador:
            try:
                self.capturador.parar()
            except Exception:
                pass
            self.capturador = None
        if self.processador and self.processador.isRunning():
            try:
                self.processador.parar()
            except Exception:
                pass
        self._interface_captura = ""
        self._cidr_captura      = ""
        self.em_captura         = False
        self.botao_captura.setText("Iniciar Captura")
        self.botao_captura.setObjectName("botao_captura")
        self._repolir(self.botao_captura)
        self.acao_captura.setText("Iniciar Captura")

    def _iniciar_captura(self):
        descricao_selecionada = self.combo_interface.currentText()
        if not descricao_selecionada or "nenhuma" in descricao_selecionada.lower():
            QMessageBox.warning(
                self, "Interface Inválida",
                "Selecione uma interface de rede válida.\n\n"
                "Execute o programa como Administrador e verifique a instalação do Npcap."
            )
            return

        nome_dispositivo = self._mapa_interface_nome.get(descricao_selecionada,
                                                         descricao_selecionada)
        try:
            self._validar_pre_captura(nome_dispositivo)
        except Exception as exc:
            mensagem = str(exc)
            self._status(f"Falha ao iniciar: {mensagem}")
            QMessageBox.critical(self, "Captura não iniciada", mensagem)
            self._limpar_pos_falha()
            return

        self._interface_captura = nome_dispositivo
        self._cidr_captura      = self._cidr_da_interface(descricao_selecionada)
        self.painel_topologia.definir_rede_local(self._cidr_captura)

        # Limpa buffers e estado
        fila_pacotes_global.limpar()
        self.estado_rede.resetar()
        self.fila_eventos_ui.clear()
        self.eventos_mostrados_recentemente.clear()
        self._snapshot_atual = {
            "total_bytes": 0, "total_pacotes": 0,
            "estatisticas": [], "top_dispositivos": [],
            "dispositivos_ativos": 0, "top_dns": [], "historias": [],
        }
        self._bytes_total_anterior = 0
        self._instante_anterior    = time.perf_counter()
        self.sessao_id             = self.banco.iniciar_sessao()

        # Inicia thread de processamento
        self.processador = _ProcessadorThread()
        self.processador.resetar()
        self.processador.snapshot_pronto.connect(self._ao_receber_snapshot)
        self.processador.batch_conexoes.connect(self._ao_receber_conexoes)
        self.processador.batch_eventos.connect(self._ao_receber_eventos)
        self.processador.batch_banco.connect(self._ao_salvar_banco)

        # Inicia thread de captura
        try:
            self.capturador = _CapturadorPacotesThread(interface=nome_dispositivo)
            self.capturador.erro_ocorrido.connect(self._ao_ocorrer_erro)
            self.capturador.sem_pacotes.connect(self._ao_ocorrer_erro)
            self.capturador.start()
        except Exception as exc:
            mensagem = f"Não foi possível iniciar o sniffer: {exc}"
            self._status(mensagem)
            QMessageBox.critical(self, "Captura não iniciada", mensagem)
            self._limpar_pos_falha()
            return

        # Inicia thread de processamento após sniffer ativo
        self.processador.start()

        # Ativa timers de UI
        self.timer_ui.start(1_000)
        self.timer_insights.start()
        self.timer_descoberta.start(30_000)

        self.em_captura = True
        self.botao_captura.setText("Parar Captura")
        self.botao_captura.setObjectName("botao_parar")
        self._repolir(self.botao_captura)
        self.acao_captura.setText("Parar Captura")
        rede_info = f" · rede {self._cidr_captura}" if self._cidr_captura else ""
        self._status(
            f"Capturando em: {descricao_selecionada} "
            f"(dispositivo: {nome_dispositivo}){rede_info}"
        )

    def _parar_captura(self):
        # Para timers antes das threads para evitar callbacks durante shutdown
        self.timer_ui.stop()
        self.timer_insights.stop()
        self.timer_descoberta.stop()

        # Para captura de pacotes
        if self.capturador:
            self.capturador.parar()
            self.capturador = None

        # Para processamento e aguarda flush final
        if self.processador and self.processador.isRunning():
            self.processador.parar()

        # Salva sessão com totais finais
        if self.sessao_id and self.processador:
            total_pacotes, total_bytes = self.processador.obter_totais()
            self.banco.finalizar_sessao(self.sessao_id, total_pacotes, total_bytes)

        self._interface_captura = ""
        self._cidr_captura      = ""
        self.em_captura         = False
        self.botao_captura.setText("Iniciar Captura")
        self.botao_captura.setObjectName("botao_captura")
        self._repolir(self.botao_captura)
        self.acao_captura.setText("Iniciar Captura")
        self._status("Captura encerrada.")

    @staticmethod
    def _repolir(botao: QPushButton):
        botao.style().unpolish(botao)
        botao.style().polish(botao)

    # ──────────────────────────────────────────────────────────────────────
    # Receptores de sinais do ProcessadorThread
    # ──────────────────────────────────────────────────────────────────────

    @pyqtSlot(dict)
    def _ao_receber_snapshot(self, snap: dict):
        """Atualiza o snapshot atual com os dados processados na thread."""
        snap["historias"] = self._gerar_historias_de(snap.get("top_dns", []))
        self._snapshot_atual = snap

    @pyqtSlot(list)
    def _ao_receber_conexoes(self, conexoes: list):
        """Atualiza topologia e banco com pares (ip_src, ip_dst, mac_src)."""
        for ip_origem, ip_destino, mac_origem in conexoes:
            if ip_origem:
                self.painel_topologia.adicionar_dispositivo(ip_origem, mac_origem)
                self.banco.salvar_dispositivo(ip_origem, mac_origem)
            if ip_origem and ip_destino:
                self.painel_topologia.adicionar_conexao(ip_origem, ip_destino)

    @pyqtSlot(list)
    def _ao_receber_eventos(self, eventos: list):
        """Aplica cooldown e enfileira eventos para exibição na UI."""
        for evento in eventos:
            if evento["tipo"] == "NOVO_DISPOSITIVO":
                ip = evento.get("ip_origem")
                if ip:
                    status = self.estado_rede.registrar_dispositivo(
                        ip, evento.get("mac_origem", "")
                    )
                    if (status == "NOVO"
                            and self.estado_rede.deve_emitir_evento(
                                f"novo_{ip}", cooldown=30)):
                        self.fila_eventos_ui.append(evento)
            else:
                _disc = (
                    evento.get("dominio", "")
                    or f"{evento.get('metodo', '')}:{evento.get('recurso', '')}"
                )
                chave = f"{evento['tipo']}_{evento.get('ip_origem')}_{_disc}"
                if self.estado_rede.deve_emitir_evento(chave, cooldown=5):
                    self.fila_eventos_ui.append(evento)

    @pyqtSlot(list)
    def _ao_salvar_banco(self, pacotes: list):
        """Persiste lote de pacotes no banco de dados (main thread)."""
        for dados in pacotes:
            self.banco.salvar_pacote(
                ip_origem     = dados.get("ip_origem",    ""),
                ip_destino    = dados.get("ip_destino",   ""),
                mac_origem    = dados.get("mac_origem",   ""),
                mac_destino   = dados.get("mac_destino",  ""),
                protocolo     = dados.get("protocolo",    ""),
                tamanho_bytes = dados.get("tamanho",      0),
                porta_origem  = dados.get("porta_origem"),
                porta_destino = dados.get("porta_destino"),
                sessao_id     = self.sessao_id,
            )

    # ──────────────────────────────────────────────────────────────────────
    # Atualização da UI (1 segundo) — apenas gráfico + status bar
    # ──────────────────────────────────────────────────────────────────────

    @pyqtSlot()
    def _atualizar_ui_por_segundo(self):
        snap          = self._snapshot_atual
        total_bytes   = snap.get("total_bytes",   0)
        total_pacotes = snap.get("total_pacotes", 0)

        agora         = time.perf_counter()
        delta_t       = max(agora - self._instante_anterior, 0.001)
        delta_bytes   = total_bytes - self._bytes_total_anterior
        kb_por_segundo = (delta_bytes / 1024.0) / delta_t

        self._bytes_total_anterior = total_bytes
        self._instante_anterior    = agora

        self.painel_trafego.adicionar_ponto_grafico(kb_por_segundo)
        self.painel_trafego.atualizar_tabelas(
            estatisticas_protocolos = snap.get("estatisticas",     []),
            top_dispositivos        = snap.get("top_dispositivos", []),
            total_pacotes           = total_pacotes,
            total_bytes             = total_bytes,
            total_topologia         = self.painel_topologia.total_dispositivos(),
            total_ativos            = self.painel_topologia.total_dispositivos(),
        )
        self.painel_topologia.atualizar()

        kb = total_bytes / 1024
        self.lbl_pacotes.setText(f"Pacotes: {total_pacotes:,}")
        self.lbl_dados.setText(
            f"  Dados: {kb/1024:.2f} MB  " if kb > 1024
            else f"  Dados: {kb:.1f} KB  "
        )

    # ──────────────────────────────────────────────────────────────────────
    # Atualização de Insights (30 segundos) — apenas passa dados; render
    # está dentro do PainelEventos com seu próprio timer de diff.
    # ──────────────────────────────────────────────────────────────────────

    @pyqtSlot()
    def _atualizar_insights_periodico(self):
        snap = self._snapshot_atual
        self.painel_eventos.atualizar_insights(
            top_dns          = snap.get("top_dns",          []),
            historias        = snap.get("historias",        []),
            top_dispositivos = snap.get("top_dispositivos", []),
        )

    # ──────────────────────────────────────────────────────────────────────
    # Descarregamento de eventos na UI (2 segundos)
    # ──────────────────────────────────────────────────────────────────────

    @pyqtSlot()
    def _descarregar_eventos_ui(self):
        if not self.fila_eventos_ui:
            return
        # Drena atomicamente o deque para processamento
        lote = []
        while self.fila_eventos_ui:
            try:
                lote.append(self.fila_eventos_ui.popleft())
            except IndexError:
                break

        agregados = self._agregar_eventos(lote)
        for ev in agregados:
            _disc_visual = (
                ev.get("dominio", "")
                or f"{ev.get('metodo', '')}:{ev.get('recurso', '')}"
            )
            chave_visual = (
                ev.get("tipo"), ev.get("ip_origem"),
                ev.get("ip_destino"), _disc_visual
            )
            if chave_visual in self.eventos_mostrados_recentemente:
                continue
            self.eventos_mostrados_recentemente.append(chave_visual)
            self._exibir_evento_pedagogico(ev)

    @staticmethod
    def _agregar_eventos(eventos: list) -> list:
        agregados = {}
        for ev in eventos:
            chave = (ev.get("tipo"), ev.get("ip_origem"), ev.get("dominio", ""))
            if chave not in agregados:
                agregados[chave] = ev.copy()
                agregados[chave]["contagem"] = 1
            else:
                agregados[chave]["contagem"] += 1
        return list(agregados.values())

    # ──────────────────────────────────────────────────────────────────────
    # Exibição de evento pedagógico
    # ──────────────────────────────────────────────────────────────────────

    def _exibir_evento_pedagogico(self, evento: dict):
        evento["sessao_id"] = self.sessao_id
        explicacao = self.motor_pedagogico.gerar_explicacao(evento)
        if explicacao is None:
            explicacao = {
                "nivel1": f"Evento: {evento.get('tipo', 'Desconhecido')}",
                "nivel2": f"Origem: {evento.get('ip_origem', '?')} → Destino: {evento.get('ip_destino', '?')}",
                "nivel3": f"Dados: {evento}",
                "icone":  "🔍",
                "nivel":  "INFO",
                "alerta": "Evento detectado.",
            }
        explicacao["sessao_id"] = self.sessao_id
        self.painel_eventos.adicionar_evento(explicacao)
        self.banco.salvar_evento(
            tipo_evento  = evento.get("tipo", ""),
            descricao    = explicacao.get("nivel1", "")[:500],
            ip_envolvido = evento.get("ip_origem"),
            sessao_id    = self.sessao_id,
        )

    # ──────────────────────────────────────────────────────────────────────
    # Descoberta periódica de dispositivos
    # ──────────────────────────────────────────────────────────────────────

    def _descoberta_periodica(self):
        if not self.em_captura:
            return
        if self.descoberta_rodando or (self.descobridor and self.descobridor.isRunning()):
            return
        self.descoberta_rodando = True
        self._status("Varrendo a rede local em busca de dispositivos...")
        if not self._interface_captura:
            self.descoberta_rodando = False
            return
        self.descobridor = _DescobrirDispositivosThread(
            interface     = self._interface_captura,
            cidr          = self._cidr_captura,
            habilitar_ping = True,
        )
        self.descobridor.dispositivo_encontrado.connect(self._ao_encontrar_dispositivo)
        self.descobridor.varredura_concluida.connect(self._ao_concluir_varredura)
        self.descobridor.progresso_atualizado.connect(self._status)
        self.descobridor.erro_ocorrido.connect(self._ao_ocorrer_erro)
        self.descobridor.start()

    @pyqtSlot(str, str, str)
    def _ao_encontrar_dispositivo(self, ip: str, mac: str, hostname: str):
        self.painel_topologia.adicionar_dispositivo_manual(ip, mac, hostname)
        self.banco.salvar_dispositivo(ip, mac, hostname)
        evento = {
            "tipo":       "NOVO_DISPOSITIVO",
            "ip_origem":  ip,
            "ip_destino": "",
            "mac_origem": mac,
            "protocolo":  "ARP/DHCP",
            "tamanho":    0,
        }
        self.fila_eventos_ui.append(evento)

    @pyqtSlot(list)
    def _ao_concluir_varredura(self, dispositivos: list):
        self._status(f"Varredura concluída — {len(dispositivos)} dispositivo(s).")
        self.descoberta_rodando = False

    # ──────────────────────────────────────────────────────────────────────
    # Auxiliares
    # ──────────────────────────────────────────────────────────────────────

    @staticmethod
    def _gerar_historias_de(top_dns: list) -> list:
        historias = []
        for dom in top_dns[:5]:
            hist = (
                f"Domínio {dom['dominio']} acessado {dom['acessos']}x "
                f"({dom['bytes']/1024:.1f} KB via DNS/SNI)."
            )
            historias.append(hist)
        return historias

    @pyqtSlot(str)
    def _ao_ocorrer_erro(self, mensagem: str):
        self._status(f"Erro: {mensagem[:80]}")
        QMessageBox.warning(self, "Erro", mensagem)
        if self.em_captura:
            self._parar_captura()
        self.descoberta_rodando = False

    def _nova_sessao(self):
        if self.em_captura:
            self._parar_captura()
        if self.processador:
            self.processador.resetar()
        self.estado_rede.resetar()
        self.painel_topologia.limpar()
        self.painel_topologia.definir_rede_local(self._cidr_captura)
        self.painel_trafego.limpar()
        self.painel_eventos.limpar()
        self._snapshot_atual = {
            "total_bytes": 0, "total_pacotes": 0,
            "estatisticas": [], "top_dispositivos": [],
            "dispositivos_ativos": 0, "top_dns": [], "historias": [],
        }
        self._bytes_total_anterior = 0
        self._instante_anterior    = time.perf_counter()
        self._status("Nova sessão iniciada. Pronto para capturar.")

    def _status(self, msg: str):
        self.lbl_status.setText(msg)

    def _exibir_sobre(self):
        QMessageBox.about(
            self, "Sobre o NetLab Educacional",
            "<h2>NetLab Educacional v3.0</h2>"
            "<p>Software educacional para análise de redes locais.</p>"
            "<hr>"
            "<p><b>TCC — Curso Técnico em Informática</b></p>"
            "<p><b>Tecnologias:</b> Python · PyQt6 · Scapy · SQLite · PyQtGraph</p>"
            "<p><b>Pipeline desacoplada:</b> Captura → ProcessadorThread → UI</p>"
        )

    def closeEvent(self, evento):
        if self.em_captura:
            self._parar_captura()
        self.banco.fechar()
        evento.accept()
