# interface/janela_principal.py
# Janela principal do NetLab Educacional - VERSAO AUTOSSUFICIENTE E CORRIGIDA
# Inclui a classe EstadoRede internamente para garantir funcionamento.

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

# ImportaÃ§Ãµes dos mÃ³dulos originais do projeto
from analisador_pacotes import AnalisadorPacotes
from motor_pedagogico import MotorPedagogico
from banco_dados import BancoDados
from interface.painel_topologia import PainelTopologia
from interface.painel_trafego import PainelTrafego
from interface.painel_eventos import PainelEventos
from painel_servidor import PainelServidor

# ============================================================================
# CLASSE EstadoRede (gerencia cooldown e dispositivos)
# ============================================================================
class EstadoRede:
    """Gerencia estado da rede, cooldown de eventos e descoberta de dispositivos."""
    def __init__(self):
        self.ultimos_eventos = {}      # chave -> timestamp
        self.dispositivos = {}         # ip -> (mac, hostname, primeiro_visto)
        self._lock = threading.Lock()

    def deve_emitir_evento(self, chave: str, cooldown: int = 5) -> bool:
        """Retorna True se o evento ainda nao foi emitido dentro do periodo de cooldown."""
        agora = time.time()
        with self._lock:
            if chave in self.ultimos_eventos:
                if agora - self.ultimos_eventos[chave] < cooldown:
                    return False
            self.ultimos_eventos[chave] = agora
            return True

    def registrar_dispositivo(self, ip: str, mac: str = "", hostname: str = "") -> str:
        """Registra um dispositivo na rede. Retorna 'NOVO' se for a primeira vez."""
        with self._lock:
            if ip not in self.dispositivos:
                self.dispositivos[ip] = (mac, hostname, time.time())
                return "NOVO"
            return "EXISTENTE"

    def obter_dispositivo(self, ip: str):
        """Retorna tupla (mac, hostname, timestamp) ou None."""
        return self.dispositivos.get(ip)

# ============================================================================
# IMPLEMENTACAO INTERNA DAS FUNCIONALIDADES QUE ANTES ESTAVAM EM capturador_rede.py
# ============================================================================

# ----- Fila global de pacotes (thread-safe) -----
class _FilaPacotesGlobal:
    def __init__(self):
        self._fila = deque()
        self._lock = threading.Lock()

    def adicionar(self, pacote):
        with self._lock:
            self._fila.append(pacote)

    def consumir_todos(self):
        with self._lock:
            pacotes = list(self._fila)
            self._fila.clear()
            return pacotes

    def limpar(self):
        with self._lock:
            self._fila.clear()

fila_pacotes_global = _FilaPacotesGlobal()

# ----- Funcoes auxiliares de rede -----
def obter_ip_local() -> str:
    """Retorna o IP local da maquina (primeira interface nao-loopback)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"

def obter_interfaces_disponiveis() -> list:
    """Retorna uma lista com as descricoes das interfaces de rede (para exibicao)."""
    try:
        from scapy.arch.windows import get_windows_if_list
        interfaces = get_windows_if_list()
        descricoes = []
        for iface in interfaces:
            desc = iface.get('description', iface.get('name', ''))
            if desc and 'loopback' not in desc.lower():
                descricoes.append(desc)
        return descricoes
    except Exception:
        return []

# ----- Thread de captura de pacotes (usa AsyncSniffer para nÃ£o travar a GUI) -----
class _CapturadorPacotesThread(QThread):
    """Thread que captura pacotes usando AsyncSniffer do Scapy."""
    erro_ocorrido = pyqtSignal(str)
    sem_pacotes = pyqtSignal(str)   # mantido por compatibilidade

    def __init__(self, interface: str):
        super().__init__()
        self.interface = interface
        self._running = False
        self.sniffer = None

    def run(self):
        self._running = True
        try:
            from scapy.all import AsyncSniffer, IP, TCP, UDP, ARP, DNS, Ether, Raw

            self.sniffer = AsyncSniffer(
                iface=self.interface,
                prn=self._processar_pacote,
                store=False,
                filter="ip"
            )
            self.sniffer.start()

            # MantÃ©m a thread viva enquanto a captura estiver ativa
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

        dados = {
            "tamanho": len(packet),
            "ip_origem": None,
            "ip_destino": None,
            "mac_origem": None,
            "mac_destino": None,
            "protocolo": "Outro",
            "porta_origem": None,
            "porta_destino": None,
        }

        from scapy.all import Ether, IP, TCP, UDP, ARP, DNS, Raw

        if packet.haslayer(Ether):
            dados["mac_origem"] = packet[Ether].src
            dados["mac_destino"] = packet[Ether].dst

        if packet.haslayer(IP):
            dados["ip_origem"] = packet[IP].src
            dados["ip_destino"] = packet[IP].dst

            if packet.haslayer(TCP):
                dados["protocolo"] = "TCP"
                dados["porta_origem"] = packet[TCP].sport
                dados["porta_destino"] = packet[TCP].dport
                # Captura flags TCP (para SYN, FIN, RST)
                flags = packet[TCP].flags
                if flags & 0x02:
                    dados["flags"] = "SYN"
                elif flags & 0x01:
                    dados["flags"] = "FIN"
                elif flags & 0x04:
                    dados["flags"] = "RST"
            elif packet.haslayer(UDP):
                dados["protocolo"] = "UDP"
                dados["porta_origem"] = packet[UDP].sport
                dados["porta_destino"] = packet[UDP].dport
                if packet.haslayer(DNS):
                    dados["protocolo"] = "DNS"
                    if packet[DNS].qr == 0:  # query
                        qname = packet[DNS].qd.qname.decode('utf-8', errors='ignore') if packet[DNS].qd else ''
                        dados["dominio"] = qname.rstrip('.')
        elif packet.haslayer(ARP):
            dados["protocolo"] = "ARP"
            dados["ip_origem"] = packet[ARP].psrc
            dados["ip_destino"] = packet[ARP].pdst
            if not dados["mac_origem"]:
                dados["mac_origem"] = packet[ARP].hwsrc
            if not dados["mac_destino"]:
                dados["mac_destino"] = packet[ARP].hwdst
            dados["arp_op"] = "request" if packet[ARP].op == 1 else "reply"

        # Captura payload para HTTP (porta 80) e armazena como bytes
        if dados.get("porta_destino") == 80 and packet.haslayer(Raw):
            dados["payload"] = packet[Raw].load

        fila_pacotes_global.adicionar(dados)

    def parar(self):
        self._running = False
        if self.sniffer:
            self.sniffer.stop()
        self.wait(3000)

# ----- Thread de descoberta de dispositivos (ping + ARP) -----
class _DescobrirDispositivosThread(QThread):
    dispositivo_encontrado = pyqtSignal(str, str, str)  # ip, mac, hostname
    varredura_concluida = pyqtSignal(list)
    progresso_atualizado = pyqtSignal(str)
    erro_ocorrido = pyqtSignal(str)

    def __init__(self, interface: str, cidr: str = "", habilitar_ping: bool = True):
        super().__init__()
        self.interface = interface
        self.cidr = cidr
        self.habilitar_ping = habilitar_ping

    def run(self):
        try:
            rede = self.cidr or self._cidr_por_interface() or self._cidr_por_ip_local()
            if not rede:
                self.erro_ocorrido.emit("Nao foi possivel determinar a sub-rede da interface selecionada.")
                return

            dispositivos = []
            self.progresso_atualizado.emit(f"Varredura ARP em andamento ({rede})...")

            from scapy.all import arping
            resultado = arping(rede, iface=self.interface, timeout=2, verbose=False)

            def _ip_util(ip: str) -> bool:
                """Ignora multicast, broadcast, loopback e enderecos vazios/locais indesejados."""
                if not ip:
                    return False
                try:
                    partes = [int(p) for p in ip.split(".")]
                    if len(partes) != 4:
                        return False
                    if partes[0] == 127 or partes[0] == 0:
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

            vistos = set()
            for sent, received in resultado[0]:
                ip = received.psrc
                mac = received.hwsrc
                if not _ip_util(ip):
                    continue
                chave = (ip, mac)
                if chave in vistos:
                    continue
                vistos.add(chave)
                hostname = ""  # Pode-se adicionar reverse DNS se desejado
                dispositivos.append((ip, mac, hostname))
                self.dispositivo_encontrado.emit(ip, mac, hostname)

            self.progresso_atualizado.emit(f"Varredura concluida: {len(dispositivos)} dispositivo(s).")
            self.varredura_concluida.emit(dispositivos)
        except Exception as e:
            self.erro_ocorrido.emit(f"Erro na descoberta: {str(e)}")

    def _cidr_por_interface(self) -> str:
        try:
            from scapy.all import get_if_addr, get_if_netmask
            ip_iface = get_if_addr(self.interface)
            mascara = get_if_netmask(self.interface)
            if ip_iface and mascara:
                bits = sum(bin(int(p)).count('1') for p in mascara.split('.'))
                return f"{ip_iface}/{bits}"
        except Exception:
            return ""
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
    """Janela principal do NetLab Educacional - versao autossuficiente."""

    def __init__(self, banco: BancoDados):
        super().__init__()
        self.banco            = banco
        self.analisador       = AnalisadorPacotes()
        self.motor_pedagogico = MotorPedagogico()

        self.capturador:  _CapturadorPacotesThread      = None
        self.descobridor: _DescobrirDispositivosThread  = None
        self.descoberta_rodando: bool = False

        self.sessao_id:  int  = None
        self.em_captura: bool = False

        # Mapeamento: descriÃ§Ã£o amigÃ¡vel -> nome real da interface (formato \\Device\\NPF_...)
        self._mapa_interface_nome = {}
        self._mapa_interface_ip = {}
        self._mapa_interface_mascara = {}
        self._interface_captura = ""
        self._cidr_captura = ""

        # Snapshot Ãºnico para sincronizar grÃ¡fico, velocidade e tabelas
        self._snapshot_atual = {
            "total_bytes": 0,
            "total_pacotes": 0,
            "estatisticas": [],
            "top_dispositivos": [],
            "dispositivos_ativos": 0,
            "top_dns": [],
        }
        self._bytes_total_anterior = 0
        self._instante_anterior = time.perf_counter()

        # Estado da rede (cooldown e dispositivos)
        self.estado_rede = EstadoRede()
        self.fila_eventos_ui = []                     # eventos acumulados para exibiÃ§Ã£o
        self.eventos_mostrados_recentemente = deque(maxlen=200)  # para deduplicaÃ§Ã£o visual

        # Timers
        self.timer_consumir = QTimer()
        self.timer_consumir.timeout.connect(self._consumir_fila)

        self.timer_ui = QTimer()
        self.timer_ui.timeout.connect(self._atualizar_ui_por_segundo)

        self.timer_descoberta = QTimer()
        self.timer_descoberta.timeout.connect(self._descoberta_periodica)

        self.timer_eventos = QTimer()
        self.timer_eventos.timeout.connect(self._descarregar_eventos_ui)
        self.timer_eventos.start(2000)   # a cada 2 segundos

        self._configurar_janela()
        self._criar_menu()
        self._criar_barra_status()
        self._criar_barra_ferramentas()
        self._criar_area_central()

    # â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    # ConfiguraÃ§Ã£o da janela
    # â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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
        a_nova = QAction("&Nova Sessao", self)
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
        self.combo_interface.setToolTip(
            "Interface de rede a ser monitorada.\n"
            "A interface ativa e selecionada automaticamente."
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
        self.abas.addTab(self.painel_eventos,   " Modo Analise")
        self.abas.addTab(self.painel_servidor,  "Servidor")

    def _criar_barra_status(self):
        b = self.statusBar()
        self.lbl_status  = QLabel("Pronto. Clique em 'Iniciar Captura' para comecar.")
        self.lbl_pacotes = QLabel("Pacotes: 0")
        self.lbl_dados   = QLabel("  Dados: 0 KB  ")
        b.addWidget(self.lbl_status)
        b.addPermanentWidget(self.lbl_pacotes)
        b.addPermanentWidget(self.lbl_dados)

    # â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    # DetecÃ§Ã£o de interfaces
    # â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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
            descricoes = obter_interfaces_disponiveis()
            for desc in descricoes:
                self.combo_interface.addItem(desc)
                self._mapa_interface_nome[desc] = desc
            self._selecionar_interface_fallback()
            return

        for iface in interfaces_raw:
            desc = iface.get('description', iface.get('name', 'Desconhecida'))
            name = iface.get('name', '')
            if desc and name:
                self.combo_interface.addItem(desc)
                self._mapa_interface_nome[desc] = name
                ips = iface.get('ips', []) or []
                mascaras = iface.get('netmasks', []) or []
                ip_v4 = next((ip for ip in ips if ip and ip.count('.') == 3 and not ip.startswith("169.254") and not ip.startswith("127.")), "")
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
                ips = iface.get('ips', [])
                if ip_local in ips:
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
            ip_local = obter_ip_local()
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
        mascara = self._mapa_interface_mascara.get(descricao_iface, "")
        if not ip_iface:
            return ""
        if mascara:
            prefixo = self._mascara_para_prefixo(mascara)
            return f"{ip_iface}/{prefixo}"
        return f"{ip_iface}/24"

    def _gerar_historias(self) -> list:
        """Gera narrativas simples baseadas nos dominios mais acessados (DNS/SNI)."""
        historias = []
        top_dns = self.analisador.obter_top_dns() if hasattr(self.analisador, "obter_top_dns") else []
        for dom in top_dns[:5]:
            hist = (
                f"Dominio {dom['dominio']} acessado {dom['acessos']}x "
                f"({dom['bytes']/1024:.1f} KB via DNS/SNI)."
            )
            historias.append(hist)
        return historias

    # â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    # Controle de captura
    # â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    @pyqtSlot()
    def _alternar_captura(self):
        if self.em_captura:
            self._parar_captura()
        else:
            self._iniciar_captura()

    def _validar_pre_captura(self, nome_dispositivo: str):
        """Valida dependencias e privilegios antes de iniciar o sniffer."""
        try:
            import ctypes
            if hasattr(ctypes, "windll") and not ctypes.windll.shell32.IsUserAnAdmin():
                raise PermissionError(
                    "Execute o NetLab como Administrador para que o Npcap permita a captura de pacotes."
                )
        except Exception:
            # Se a verificacao falhar, seguimos adiante para tentar capturar mesmo assim
            pass

        try:
            from scapy.arch.windows import get_windows_if_list
            adaptadores = get_windows_if_list()
            nomes_validos = {a.get("name") for a in adaptadores} | {a.get("description") for a in adaptadores}
            if nome_dispositivo not in nomes_validos:
                raise RuntimeError(
                    "Adaptador nao reconhecido pelo Npcap/Scapy. Reinstale o Npcap ou escolha outra interface."
                )
        except ImportError as exc:
            raise RuntimeError(
                "Biblioteca Scapy ausente. Instale-a com 'pip install scapy' ou inclua no build do executavel."
            ) from exc
        except Exception as exc:
            raise RuntimeError(f"Falha ao acessar o Npcap/Scapy: {exc}") from exc

    def _limpar_pos_falha(self):
        """Reinicia o estado da UI quando a captura falha ao iniciar."""
        self.timer_consumir.stop()
        self.timer_ui.stop()
        self.timer_descoberta.stop()
        if self.capturador:
            try:
                self.capturador.parar()
            except Exception:
                pass
            self.capturador = None
        self._interface_captura = ""
        self._cidr_captura = ""
        self.em_captura = False
        self.botao_captura.setText("Iniciar Captura")
        self.botao_captura.setObjectName("botao_captura")
        self._repolir(self.botao_captura)
        self.acao_captura.setText("Iniciar Captura")

    def _iniciar_captura(self):
        descricao_selecionada = self.combo_interface.currentText()
        if not descricao_selecionada or "nenhuma" in descricao_selecionada.lower():
            QMessageBox.warning(
                self, "Interface Invalida",
                "Selecione uma interface de rede valida.\n\n"
                "Execute o programa como Administrador e verifique a instalacao do Npcap."
            )
            return

        nome_dispositivo = self._mapa_interface_nome.get(descricao_selecionada)
        if not nome_dispositivo:
            nome_dispositivo = descricao_selecionada
            self._status(f"Aviso: usando nome direto '{nome_dispositivo}'")

        try:
            self._validar_pre_captura(nome_dispositivo)
        except Exception as exc:
            mensagem = str(exc)
            self._status(f"Falha ao iniciar: {mensagem}")
            QMessageBox.critical(self, "Captura nao iniciada", mensagem)
            self._limpar_pos_falha()
            return

        self._interface_captura = nome_dispositivo
        self._cidr_captura = self._cidr_da_interface(descricao_selecionada)
        # Informa rede local ao painel de topologia para filtrar IPs externos
        self.painel_topologia.definir_rede_local(self._cidr_captura)

        fila_pacotes_global.limpar()
        self.analisador.resetar()
        self._snapshot_atual = {
            "total_bytes": 0,
            "total_pacotes": 0,
            "estatisticas": [],
            "top_dispositivos": [],
            "dispositivos_ativos": 0,
            "top_dns": [],
            "historias": [],
        }
        self._bytes_total_anterior = 0
        self._instante_anterior = time.perf_counter()
        self.sessao_id = self.banco.iniciar_sessao()

        try:
            self.capturador = _CapturadorPacotesThread(interface=nome_dispositivo)
            self.capturador.erro_ocorrido.connect(self._ao_ocorrer_erro)
            self.capturador.sem_pacotes.connect(self._ao_ocorrer_erro)
            self.capturador.start()
        except Exception as exc:
            mensagem = f"Nao foi possivel iniciar o sniffer: {exc}"
            self._status(mensagem)
            QMessageBox.critical(self, "Captura nao iniciada", mensagem)
            self._limpar_pos_falha()
            return

        self.timer_consumir.start(100)
        self.timer_ui.start(1000)
        self.timer_descoberta.start(30000)

        self.em_captura = True
        self.botao_captura.setText("Parar Captura")
        self.botao_captura.setObjectName("botao_parar")
        self._repolir(self.botao_captura)
        self.acao_captura.setText("Parar Captura")
        rede_info = f" · rede {self._cidr_captura}" if self._cidr_captura else ""
        self._status(f"Capturando em: {descricao_selecionada} (dispositivo: {nome_dispositivo}){rede_info}")

    def _parar_captura(self):
        self.timer_consumir.stop()
        self.timer_ui.stop()
        self.timer_descoberta.stop()

        if self.capturador:
            self.capturador.parar()
            self.capturador = None

        self._consumir_fila()

        if self.sessao_id:
            self.banco.finalizar_sessao(
                self.sessao_id,
                self.analisador.total_pacotes,
                self.analisador.total_bytes,
            )

        self._interface_captura = ""
        self._cidr_captura = ""

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

    # â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    # Processamento da fila de pacotes (COM GERAÃ‡ÃƒO DE EVENTOS)
    # â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    @pyqtSlot()
    def _consumir_fila(self):
        pacotes = fila_pacotes_global.consumir_todos()
        if not pacotes:
            return

        MAX_POR_CICLO = 100
        for i, dados in enumerate(pacotes):
            if i >= MAX_POR_CICLO:
                for restante in pacotes[i:]:
                    fila_pacotes_global.adicionar(restante)
                break

            evento = self.analisador.processar_pacote(dados)

            ip_origem  = dados.get("ip_origem", "")
            ip_destino = dados.get("ip_destino", "")
            mac_origem = dados.get("mac_origem", "")

            if ip_origem:
                self.painel_topologia.adicionar_dispositivo(ip_origem, mac_origem)
                self.banco.salvar_dispositivo(ip_origem, mac_origem)

            if ip_origem and ip_destino:
                self.painel_topologia.adicionar_conexao(ip_origem, ip_destino)

            # Se o analisador retornou um evento, enfileira para exibiÃ§Ã£o
            if evento and evento.get("tipo"):
                if evento["tipo"] == "NOVO_DISPOSITIVO":
                    ip = evento.get("ip_origem")
                    if ip:
                        status = self.estado_rede.registrar_dispositivo(ip, evento.get("mac_origem"))
                        if status == "NOVO" and self.estado_rede.deve_emitir_evento(f"novo_{ip}", cooldown=30):
                            self.fila_eventos_ui.append(evento)
                else:
                    chave = f"{evento['tipo']}_{evento.get('ip_origem')}_{evento.get('dominio', '')}"
                    if self.estado_rede.deve_emitir_evento(chave, cooldown=5):
                        self.fila_eventos_ui.append(evento)

            # Amostragem para banco de dados
            if self.analisador.total_pacotes % 5 == 0:
                self.banco.salvar_pacote(
                    ip_origem=ip_origem,
                    ip_destino=ip_destino,
                    mac_origem=mac_origem,
                    mac_destino=dados.get("mac_destino", ""),
                    protocolo=dados.get("protocolo", ""),
                    tamanho_bytes=dados.get("tamanho", 0),
                    porta_origem=dados.get("porta_origem"),
                    porta_destino=dados.get("porta_destino"),
                    sessao_id=self.sessao_id,
                )

        # Atualiza snapshot Ãºnico para toda a UI
        self._snapshot_atual = {
            "total_bytes": self.analisador.total_bytes,
            "total_pacotes": self.analisador.total_pacotes,
            "estatisticas": self.analisador.obter_estatisticas_protocolos(),
            "top_dispositivos": self.analisador.obter_top_dispositivos(),
            "dispositivos_ativos": len(self.analisador.trafego_dispositivos),
            "top_dns": self.analisador.obter_top_dns(),
            "historias": self._gerar_historias(),
        }

    # â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    # AgregaÃ§Ã£o e descarregamento de eventos
    # â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def _agregar_eventos(self, eventos):
        agregados = {}
        for ev in eventos:
            chave = (ev.get("tipo"), ev.get("ip_origem"), ev.get("dominio", ""))
            if chave not in agregados:
                agregados[chave] = ev.copy()
                agregados[chave]["contagem"] = 1
            else:
                agregados[chave]["contagem"] += 1
        return list(agregados.values())

    @pyqtSlot()
    def _descarregar_eventos_ui(self):
        if not self.fila_eventos_ui:
            return
        lote = self.fila_eventos_ui[:]
        self.fila_eventos_ui.clear()
        agregados = self._agregar_eventos(lote)
        for ev in agregados:
            chave_visual = (ev.get("tipo"), ev.get("ip_origem"), ev.get("ip_destino"), ev.get("dominio", ""))
            if chave_visual in self.eventos_mostrados_recentemente:
                continue
            self.eventos_mostrados_recentemente.append(chave_visual)
            self._exibir_evento_pedagogico(ev)

    # â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    # AtualizaÃ§Ã£o da UI (1 segundo)
    # â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    @pyqtSlot()
    def _atualizar_ui_por_segundo(self):
        snap = self._snapshot_atual
        total_bytes = snap.get("total_bytes", 0)
        total_pacotes = snap.get("total_pacotes", 0)

        # CÃ¡lculo real de velocidade usando delta de bytes e delta de tempo
        agora = time.perf_counter()
        delta_t = max(agora - self._instante_anterior, 0.001)
        delta_bytes = total_bytes - self._bytes_total_anterior
        kb_por_segundo = (delta_bytes / 1024.0) / delta_t

        self._bytes_total_anterior = total_bytes
        self._instante_anterior = agora

        self.painel_trafego.adicionar_ponto_grafico(kb_por_segundo)
        self.painel_trafego.atualizar_tabelas(
            estatisticas_protocolos=snap.get("estatisticas", []),
            top_dispositivos=snap.get("top_dispositivos", []),
            total_pacotes=total_pacotes,
            total_bytes=total_bytes,
            total_topologia=self.painel_topologia.total_dispositivos(),
            total_ativos=self.painel_topologia.total_dispositivos(),
        )
        self.painel_topologia.atualizar()
        self.painel_eventos.atualizar_insights(
            snap.get("top_dns", []),
            snap.get("historias", []),
        )

        kb = total_bytes / 1024
        self.lbl_pacotes.setText(f"Pacotes: {total_pacotes:,}")
        self.lbl_dados.setText(
            f"  Dados: {kb/1024:.2f} MB  " if kb > 1024
            else f"  Dados: {kb:.1f} KB  "
        )

    # â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    # ExibiÃ§Ã£o de evento pedagÃ³gico
    # â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def _exibir_evento_pedagogico(self, evento: dict):
        evento["sessao_id"] = self.sessao_id
        explicacao = self.motor_pedagogico.gerar_explicacao(evento)
        if explicacao is None:
            explicacao = {
                "nivel1": f"Evento: {evento.get('tipo', 'Desconhecido')}",
                "nivel2": f"Origem: {evento.get('ip_origem', '?')} -> Destino: {evento.get('ip_destino', '?')}",
                "nivel3": f"Dados: {evento}",
                "icone": "🔍",
                "nivel": "INFO",
                "alerta": "Evento detectado."
            }
        explicacao["sessao_id"] = self.sessao_id
        self.painel_eventos.adicionar_evento(explicacao)
        self.banco.salvar_evento(
            tipo_evento=evento.get("tipo", ""),
            descricao=explicacao.get("nivel1", "")[:500],
            ip_envolvido=evento.get("ip_origem"),
            sessao_id=self.sessao_id,
        )

    # â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    # Descoberta periÃ³dica de dispositivos
    # â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def _descoberta_periodica(self):
        if not self.em_captura:
            return
        if self.descoberta_rodando or (self.descobridor and self.descobridor.isRunning()):
            return
        self.descoberta_rodando = True
        self._status("Varrendo a rede local em busca de dispositivos...")
        if not self._interface_captura:
            self._status("Varredura ignorada: interface de captura nao definida.")
            self.descoberta_rodando = False
            return
        self.descobridor = _DescobrirDispositivosThread(
            interface=self._interface_captura,
            cidr=self._cidr_captura,
            habilitar_ping=True
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
        self._status(f"Varredura concluida - {len(dispositivos)} dispositivo(s) encontrado(s).")
        self.descoberta_rodando = False

    # â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    # Tratamento de erros
    # â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    @pyqtSlot(str)
    def _ao_ocorrer_erro(self, mensagem: str):
        self._status(f"Erro: {mensagem[:80]}")
        QMessageBox.warning(self, "Erro", mensagem)
        if self.em_captura:
            self._parar_captura()
        self.descoberta_rodando = False

    # â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    # AÃ§Ãµes gerais
    # â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def _nova_sessao(self):
        if self.em_captura:
            self._parar_captura()
        self.analisador.resetar()
        self.painel_topologia.limpar()
        self.painel_topologia.definir_rede_local(self._cidr_captura)
        self.painel_trafego.limpar()
        self.painel_eventos.limpar()
        self._snapshot_atual = {
            "total_bytes": 0,
            "total_pacotes": 0,
            "estatisticas": [],
            "top_dispositivos": [],
            "dispositivos_ativos": 0,
        }
        self._bytes_total_anterior = 0
        self._instante_anterior = time.perf_counter()
        self._status("Nova sessao iniciada. Pronto para capturar.")

    def _status(self, msg: str):
        self.lbl_status.setText(msg)

    def _exibir_sobre(self):
        QMessageBox.about(
            self, "Sobre o NetLab Educacional",
            "<h2>NetLab Educacional v2.0</h2>"
            "<p>Software educacional para analise de redes locais.</p>"
            "<hr>"
            "<p><b>TCC - Curso Tecnico em Informatica</b></p>"
            "<p><b>Tecnologias:</b> Python · PyQt6 · Scapy · SQLite · PyQtGraph</p>"
            "<p><b>Versao autossuficiente</b> - nao requer modulos externos.</p>"
        )

    def closeEvent(self, evento):
        if self.em_captura:
            self._parar_captura()
        self.banco.fechar()
        evento.accept()

