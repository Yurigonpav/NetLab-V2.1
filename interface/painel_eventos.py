# interface/painel_eventos.py
# Painel do Modo Análise — três níveis de explicação (Simples, Técnico, Pacote Bruto).
# Aba Insights reformulada: domínios DNS, ações GET/POST, hierarquia de protocolos e Top Talkers.

from collections import defaultdict
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QScrollArea, QFrame, QPushButton, QTextEdit,
    QSplitter, QTabWidget, QLineEdit, QComboBox,
    QTableWidget, QTableWidgetItem, QHeaderView,
    QProgressBar, QGridLayout
)
from PyQt6.QtCore import Qt, pyqtSlot, QTimer
from PyQt6.QtGui import QFont, QColor, QPainter, QPen, QBrush, QPainterPath

# ─────────────────────────────────────────────────────────────
# Constantes visuais
# ─────────────────────────────────────────────────────────────

ESTILOS_NIVEL = {
    "INFO":    {"borda": "#3498DB", "fundo": "#0d1a2a", "badge": "#1a4a6b"},
    "AVISO":   {"borda": "#E67E22", "fundo": "#1f1200", "badge": "#5a3000"},
    "CRITICO": {"borda": "#E74C3C", "fundo": "#200a0a", "badge": "#5a0000"},
}

ROTULOS_NIVEL = [
    ("", "Simples",      "Linguagem do dia a dia"),
    ("", "Técnico",      "Detalhes do protocolo"),
    ("", "Pacote Bruto", "Conteúdo exato como trafegou na rede"),
]

# Mapeamento de domínios conhecidos para nomes amigáveis
DOMINIOS_CONHECIDOS = {
    "google.com": "Google",       "googleapis.com": "Google APIs",
    "gstatic.com": "Google Static","youtube.com": "YouTube",
    "youtu.be": "YouTube",         "googlevideo.com": "YouTube Vídeo",
    "facebook.com": "Facebook",    "instagram.com": "Instagram",
    "fbcdn.net": "Facebook CDN",   "whatsapp.com": "WhatsApp",
    "whatsapp.net": "WhatsApp",    "twitter.com": "Twitter/X",
    "twimg.com": "Twitter CDN",    "x.com": "X (Twitter)",
    "netflix.com": "Netflix",      "nflxvideo.net": "Netflix Vídeo",
    "amazon.com": "Amazon",        "amazonaws.com": "Amazon AWS",
    "microsoft.com": "Microsoft",  "office.com": "Microsoft Office",
    "live.com": "Microsoft Live",  "outlook.com": "Outlook",
    "windows.com": "Windows Update","windowsupdate.com": "Windows Update",
    "apple.com": "Apple",          "icloud.com": "iCloud",
    "spotify.com": "Spotify",      "twitch.tv": "Twitch",
    "tiktok.com": "TikTok",        "reddit.com": "Reddit",
    "wikipedia.org": "Wikipedia",  "github.com": "GitHub",
    "steamcontent.com": "Steam",   "steampowered.com": "Steam",
    "discord.com": "Discord",      "discordapp.com": "Discord CDN",
    "cloudflare.com": "Cloudflare","akamai.net": "Akamai CDN",
    "akamaized.net": "Akamai CDN", "globo.com": "Globo",
    "uol.com.br": "UOL",           "terra.com.br": "Terra",
}

# Cores por categoria de protocolo
CORES_PROTOCOLO = {
    "HTTP":      "#E74C3C",
    "HTTPS":     "#2ECC71",
    "DNS":       "#3498DB",
    "TCP_SYN":   "#9B59B6",
    "UDP":       "#F39C12",
    "ICMP":      "#1ABC9C",
    "ARP":       "#E67E22",
    "SSH":       "#2980B9",
    "FTP":       "#E91E63",
    "SMB":       "#795548",
    "RDP":       "#FF5722",
    "DHCP":      "#16A085",
    "Outro":     "#7f8c8d",
}


# ─────────────────────────────────────────────────────────────
# Cartão de evento (lista lateral)
# ─────────────────────────────────────────────────────────────

class CartaoEvento(QFrame):
    """Cartão compacto para a lista lateral de eventos capturados."""

    def __init__(self, dados: dict, parent=None):
        super().__init__(parent)
        nivel  = dados.get("nivel", "INFO")
        estilo = ESTILOS_NIVEL.get(nivel, ESTILOS_NIVEL["INFO"])

        self.setStyleSheet(f"""
            QFrame {{
                background-color: {estilo['fundo']};
                border-left: 4px solid {estilo['borda']};
                border-radius: 3px;
                margin: 1px 2px;
            }}
            QFrame:hover {{ background-color: #1a2540; }}
        """)
        self.setCursor(Qt.CursorShape.PointingHandCursor)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 5, 10, 5)
        layout.setSpacing(2)

        cabecalho = QHBoxLayout()
        icone_titulo = QLabel(
            f"{dados.get('icone', '')} {dados.get('titulo', 'Evento')}".strip()
        )
        icone_titulo.setStyleSheet(
            f"color:{estilo['borda']};font-weight:bold;"
            f"font-size:10px;border:none;"
        )
        icone_titulo.setWordWrap(False)

        hora = QLabel(dados.get("timestamp", ""))
        hora.setStyleSheet("color:#7f8c8d;font-size:9px;border:none;")

        cabecalho.addWidget(icone_titulo, 1)
        cabecalho.addWidget(hora)
        layout.addLayout(cabecalho)

        ip_src   = dados.get("ip_envolvido", "")
        ip_dst   = dados.get("ip_destino", "")
        ip_texto = ip_src
        if ip_dst and ip_dst != ip_src:
            ip_texto += f" → {ip_dst}"

        lbl_ip = QLabel(ip_texto)
        lbl_ip.setStyleSheet(
            "color:#95a5a6;font-size:9px;font-family:Consolas;border:none;"
        )
        layout.addWidget(lbl_ip)

        if dados.get("alerta_seguranca"):
            badge = QLabel("Risco de segurança")
            badge.setStyleSheet(
                f"color:#E74C3C;font-size:8px;font-weight:bold;"
                f"background:{estilo['badge']};border-radius:2px;"
                f"padding:1px 4px;border:none;"
            )
            layout.addWidget(badge)


# ─────────────────────────────────────────────────────────────
# Barra de contadores por tipo de evento
# ─────────────────────────────────────────────────────────────

class PainelContadores(QWidget):
    """Barra horizontal com contadores por tipo de evento."""

    TIPOS_MONITORADOS = [
        ("DNS",    "", "#3498DB"),
        ("HTTP",   "", "#E74C3C"),
        ("HTTPS",  "", "#2ECC71"),
        ("TCP_SYN","", "#9B59B6"),
        ("ICMP",   "", "#1ABC9C"),
        ("ARP",    "", "#E67E22"),
        ("DHCP",   "", "#16A085"),
    ]

    def __init__(self, parent=None):
        super().__init__(parent)
        self._contadores: dict = defaultdict(int)
        self._labels: dict     = {}

        layout = QHBoxLayout(self)
        layout.setContentsMargins(4, 2, 4, 2)
        layout.setSpacing(8)

        titulo = QLabel("Eventos nesta sessão:")
        titulo.setStyleSheet("color:#7f8c8d;font-size:9px;")
        layout.addWidget(titulo)

        tipos_vistos = set()
        for tipo, icone, cor in self.TIPOS_MONITORADOS:
            if tipo in tipos_vistos:
                continue
            tipos_vistos.add(tipo)
            lbl = QLabel(f"{icone} {tipo}: 0")
            lbl.setStyleSheet(
                f"color:{cor};font-size:9px;font-family:Consolas;"
                f"background:#0d1a2a;border:1px solid {cor}33;"
                f"border-radius:3px;padding:1px 6px;"
            )
            self._labels[tipo] = lbl
            layout.addWidget(lbl)

        layout.addStretch()

    def incrementar(self, tipo: str):
        self._contadores[tipo] += 1
        if tipo in self._labels:
            icone = next(
                (ic for t, ic, _ in self.TIPOS_MONITORADOS if t == tipo), "•"
            )
            self._labels[tipo].setText(
                f"{icone} {tipo}: {self._contadores[tipo]}"
            )

    def resetar(self):
        self._contadores.clear()
        for tipo, icone, _ in self.TIPOS_MONITORADOS:
            if tipo in self._labels:
                self._labels[tipo].setText(f"{icone} {tipo}: 0")


# ─────────────────────────────────────────────────────────────
# Widget de barra de progresso personalizada
# ─────────────────────────────────────────────────────────────

class BarraProgresso(QWidget):
    """Barra de progresso estilizada para o painel de insights."""

    def __init__(self, rotulo: str, valor: float, maximo: float,
                 cor: str = "#3498DB", sufixo: str = "", parent=None):
        super().__init__(parent)
        self.setFixedHeight(28)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 2, 0, 2)
        layout.setSpacing(8)

        # Rótulo
        lbl = QLabel(rotulo)
        lbl.setFixedWidth(140)
        lbl.setStyleSheet(
            "color:#bdc3c7;font-size:10px;font-family:Consolas;"
            "background:transparent;border:none;"
        )
        lbl.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        layout.addWidget(lbl)

        # Barra
        barra = QProgressBar()
        barra.setMaximum(max(int(maximo * 10), 1))
        barra.setValue(int(valor * 10))
        barra.setTextVisible(False)
        barra.setFixedHeight(10)
        barra.setStyleSheet(f"""
            QProgressBar {{
                background: #0d1a2a;
                border: 1px solid #1e2d40;
                border-radius: 4px;
            }}
            QProgressBar::chunk {{
                background: {cor};
                border-radius: 3px;
            }}
        """)
        layout.addWidget(barra, 1)

        # Valor
        percentual = (valor / maximo * 100) if maximo > 0 else 0
        lbl_valor = QLabel(f"{percentual:.0f}% {sufixo}")
        lbl_valor.setFixedWidth(55)
        lbl_valor.setStyleSheet(
            f"color:{cor};font-size:10px;font-family:Consolas;"
            "background:transparent;border:none;"
        )
        layout.addWidget(lbl_valor)


# ─────────────────────────────────────────────────────────────
# Motor de Insights Local
# ─────────────────────────────────────────────────────────────

class _MotorInsightsLocal:
    """
    Agrega e classifica eventos de rede para geração de insights didáticos.
    Identifica domínios via DNS, traduz ações HTTP e mede Top Talkers.
    """

    CAMPOS_SENSIVEIS = frozenset({
        "senha", "password", "pass", "pwd", "user", "usuario",
        "login", "email", "token", "auth", "credential", "cpf",
        "pin", "ssn", "username", "nome",
    })

    def __init__(self):
        self.resetar()

    def resetar(self):
        # DNS: domínio → contagem de consultas
        self._contagem_dominios:  defaultdict = defaultdict(int)

        # HTTP: por método
        self._acoes_http: dict = {
            "GET":   0,  # Navegação / leitura
            "POST":  0,  # Envio de dados
            "PUT":   0,  # Atualização
            "DELETE":0,  # Remoção
            "OUTRO": 0,  # Demais
        }

        # Protocolos: tipo → contagem de pacotes
        self._contagem_protocolo: defaultdict = defaultdict(int)
        self._bytes_protocolo:    defaultdict = defaultdict(int)

        # Top Talkers: ip → bytes enviados/recebidos
        self._bytes_por_ip:   defaultdict = defaultdict(int)
        self._eventos_por_ip: defaultdict = defaultdict(int)

        # Credenciais expostas
        self._credenciais_expostas: list = []

        # Contadores gerais
        self._total_alimentados: int = 0
        self._total_http:        int = 0
        self._total_dns:         int = 0
        self._versao:            int = 0

    def alimentar(self, evento: dict):
        """
        Processa um evento do motor pedagógico e atualiza as agregações.
        Nunca lança exceção — fail-safe por design.
        """
        try:
            self._total_alimentados += 1
            self._versao += 1
            tipo = evento.get("tipo", "")
            ip   = evento.get("ip_envolvido") or evento.get("ip_origem") or ""
            tamanho = evento.get("tamanho", 0) or 0

            # Contagem de protocolo
            proto_exibido = tipo if tipo in CORES_PROTOCOLO else "Outro"
            self._contagem_protocolo[proto_exibido] += 1
            self._bytes_protocolo[proto_exibido] += tamanho

            # Bytes por IP (Top Talkers)
            if ip:
                self._bytes_por_ip[ip] += tamanho
                self._eventos_por_ip[ip] += 1

            # ── DNS ──────────────────────────────────────────
            if tipo == "DNS":
                self._total_dns += 1
                dominio = self._extrair_dominio(evento)
                if dominio:
                    # Normaliza para domínio raiz (ex: sub.google.com → google.com)
                    raiz = self._dominio_raiz(dominio)
                    self._contagem_dominios[raiz] += 1

            # ── HTTP ─────────────────────────────────────────
            elif tipo == "HTTP":
                self._total_http += 1
                metodo = (
                    evento.get("metodo") or
                    evento.get("http_metodo") or ""
                ).upper()

                if metodo == "GET":
                    self._acoes_http["GET"] += 1
                elif metodo == "POST":
                    self._acoes_http["POST"] += 1
                elif metodo == "PUT":
                    self._acoes_http["PUT"] += 1
                elif metodo == "DELETE":
                    self._acoes_http["DELETE"] += 1
                else:
                    self._acoes_http["OUTRO"] += 1

                # Detecta credenciais expostas
                alerta = (evento.get("alerta_seguranca") or "").lower()
                if any(s in alerta for s in ("credencial", "senha", "password", "exposta")):
                    ts = evento.get("timestamp", "")
                    campos = [c for c in self.CAMPOS_SENSIVEIS if c in alerta]
                    if ip and len(self._credenciais_expostas) < 50:
                        self._credenciais_expostas.append(
                            (ts, ip, campos or ["dados sensíveis"])
                        )

        except Exception:
            pass

    def _extrair_dominio(self, evento: dict) -> str:
        """Extrai o nome de domínio de um evento DNS."""
        dominio = evento.get("dominio", "")
        if not dominio:
            titulo = evento.get("titulo", "")
            if "—" in titulo:
                dominio = titulo.split("—")[-1].strip()
        return dominio.strip().rstrip(".")

    @staticmethod
    def _dominio_raiz(dominio: str) -> str:
        """Retorna o domínio de segundo nível (ex: sub.google.com → google.com)."""
        partes = dominio.lower().split(".")
        # Domínios com TLD composto (ex: .com.br)
        if len(partes) >= 3 and partes[-2] in ("com", "org", "net", "edu", "gov"):
            return ".".join(partes[-3:])
        if len(partes) >= 2:
            return ".".join(partes[-2:])
        return dominio

    def obter_top_dominios(self, top_n: int = 10) -> list:
        """Retorna os domínios mais consultados com nome amigável."""
        ordenados = sorted(
            self._contagem_dominios.items(),
            key=lambda x: x[1], reverse=True
        )[:top_n]
        resultado = []
        for dominio, contagem in ordenados:
            nome_amigavel = DOMINIOS_CONHECIDOS.get(dominio, dominio)
            resultado.append({
                "dominio": dominio,
                "nome":    nome_amigavel,
                "consultas": contagem,
            })
        return resultado

    def obter_hierarquia_protocolos(self) -> list:
        """Retorna protocolos ordenados por volume de pacotes."""
        total = sum(self._contagem_protocolo.values()) or 1
        ordenados = sorted(
            self._contagem_protocolo.items(),
            key=lambda x: x[1], reverse=True
        )
        return [
            {
                "protocolo":  proto,
                "pacotes":    qtd,
                "percentual": qtd / total * 100,
                "bytes":      self._bytes_protocolo.get(proto, 0),
                "cor":        CORES_PROTOCOLO.get(proto, "#7f8c8d"),
            }
            for proto, qtd in ordenados
        ]

    def obter_top_talkers(self, top_n: int = 8) -> list:
        """Retorna os IPs com maior volume de tráfego."""
        ordenados = sorted(
            self._bytes_por_ip.items(),
            key=lambda x: x[1], reverse=True
        )[:top_n]
        return [
            {
                "ip":     ip,
                "bytes":  b,
                "eventos": self._eventos_por_ip.get(ip, 0),
            }
            for ip, b in ordenados
        ]

    def obter_resumo_acoes(self) -> dict:
        """Retorna contagem de ações HTTP com tradução em linguagem natural."""
        return dict(self._acoes_http)


# ─────────────────────────────────────────────────────────────
# Painel principal de Eventos
# ─────────────────────────────────────────────────────────────

class PainelEventos(QWidget):
    """
    Painel completo do Modo Análise com três níveis de explicação.
    Aba Insights reformulada com análise comportamental da rede.
    """

    LIMITE_EVENTOS = 300

    def __init__(self, parent=None):
        super().__init__(parent)
        self._todos_eventos:     list = []
        self._eventos_filtrados: list = []
        self._evento_atual:      dict = {}
        self._nivel_atual:       int  = 0
        self._filtro_protocolo:  str  = "Todos"
        self._filtro_texto:      str  = ""
        self._contagem_sessao:   dict = defaultdict(lambda: defaultdict(int))

        # Motor de insights — agrega dados sem estado externo
        self._motor_insights             = _MotorInsightsLocal()
        self._versao_insights_renderizada: int = -1

        self._montar_layout()

    # ──────────────────────────────────────────────
    # Montagem da interface
    # ──────────────────────────────────────────────

    def _montar_layout(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 4)
        layout.setSpacing(4)

        # Cabeçalho
        cab = QHBoxLayout()
        fonte_titulo = QFont("Arial", 12)
        fonte_titulo.setBold(True)
        titulo = QLabel("  Modo Análise - Eventos de Rede em Tempo Real")
        titulo.setFont(fonte_titulo)
        cab.addWidget(titulo)
        cab.addStretch()
        layout.addLayout(cab)

        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet("color:#2c3e50;")
        layout.addWidget(sep)

        layout.addLayout(self._criar_barra_filtros())

        self.painel_contadores = PainelContadores()
        layout.addWidget(self.painel_contadores)

        self.abas = QTabWidget()
        layout.addWidget(self.abas)

        self.abas.addTab(self._criar_aba_eventos(),  "Eventos ao Vivo")
        self.abas.addTab(self._criar_aba_insights(), "Insights")

        self.lbl_rodape = QLabel("Nenhum evento registrado.")
        self.lbl_rodape.setStyleSheet(
            "color:#7f8c8d;font-size:10px;padding:2px;"
        )
        layout.addWidget(self.lbl_rodape)

        self._trocar_nivel(0)
        self._exibir_boas_vindas()

    # ──────────────────────────────────────────────
    # Aba de Eventos ao Vivo
    # ──────────────────────────────────────────────

    def _criar_barra_filtros(self) -> QHBoxLayout:
        row = QHBoxLayout()
        row.setSpacing(6)

        lbl = QLabel("Filtrar:")
        lbl.setStyleSheet("color:#7f8c8d;font-size:10px;")
        row.addWidget(lbl)

        self.combo_protocolo = QComboBox()
        self.combo_protocolo.setMaximumWidth(140)
        self.combo_protocolo.addItems([
            "Todos", "DNS", "HTTP", "HTTPS", "TCP_SYN", "TCP_FIN",
            "TCP_RST", "ICMP", "ARP", "DHCP", "SSH", "FTP",
            "SMB", "RDP", "NOVO_DISPOSITIVO",
        ])
        self.combo_protocolo.currentTextChanged.connect(
            self._ao_mudar_filtro_protocolo
        )
        row.addWidget(self.combo_protocolo)

        self.campo_busca = QLineEdit()
        self.campo_busca.setPlaceholderText("Buscar por IP, domínio ou palavra-chave")
        self.campo_busca.setMaximumWidth(280)
        self.campo_busca.textChanged.connect(self._ao_mudar_filtro_texto)
        row.addWidget(self.campo_busca)

        row.addStretch()
        return row

    def _criar_aba_eventos(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 4, 0, 0)
        layout.setSpacing(0)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        layout.addWidget(splitter)

        # ── Lista lateral de eventos ──────────────
        w_lista = QWidget()
        l_lista = QVBoxLayout(w_lista)
        l_lista.setContentsMargins(0, 0, 4, 0)
        l_lista.setSpacing(2)

        fonte_label = QFont("Arial", 10)
        fonte_label.setBold(True)
        lbl_lista = QLabel("Eventos Capturados")
        lbl_lista.setStyleSheet("color:#7f8c8d;padding-bottom:4px;")
        lbl_lista.setFont(fonte_label)
        l_lista.addWidget(lbl_lista)

        self._scroll = QScrollArea()
        self._scroll.setWidgetResizable(True)
        self._scroll.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff
        )

        self._container = QWidget()
        self._layout_cartoes = QVBoxLayout(self._container)
        self._layout_cartoes.setContentsMargins(2, 2, 2, 2)
        self._layout_cartoes.setSpacing(3)
        self._layout_cartoes.addStretch()

        self._scroll.setWidget(self._container)
        l_lista.addWidget(self._scroll)
        splitter.addWidget(w_lista)

        # ── Painel de explicação ──────────────────
        w_expl = QWidget()
        l_expl = QVBoxLayout(w_expl)
        l_expl.setContentsMargins(4, 0, 0, 0)
        l_expl.setSpacing(4)

        lbl_expl = QLabel("📖  Explicação Didática")
        lbl_expl.setStyleSheet(
            "font-weight:bold;font-size:11px;color:#bdc3c7;"
        )
        l_expl.addWidget(lbl_expl)

        row_niveis = QHBoxLayout()
        self.botoes_nivel = []
        for icone, rotulo, dica in ROTULOS_NIVEL:
            btn = QPushButton(f"{icone} {rotulo}")
            btn.setCheckable(True)
            btn.setMaximumHeight(26)
            btn.setToolTip(dica)
            idx = len(self.botoes_nivel)
            btn.clicked.connect(lambda _, n=idx: self._trocar_nivel(n))
            self.botoes_nivel.append(btn)
            row_niveis.addWidget(btn)
        row_niveis.addStretch()
        l_expl.addLayout(row_niveis)

        self.texto_explicacao = QTextEdit()
        self.texto_explicacao.setReadOnly(True)
        self.texto_explicacao.setStyleSheet("""
            QTextEdit {
                background-color: #0f1423;
                color: #ecf0f1;
                border: 1px solid #1e2d40;
                border-radius: 6px;
                padding: 14px;
                font-size: 11px;
            }
        """)
        l_expl.addWidget(self.texto_explicacao)

        splitter.addWidget(w_expl)
        splitter.setSizes([400, 580])

        return widget

    # ──────────────────────────────────────────────
    # Aba Insights reformulada
    # ──────────────────────────────────────────────

    def _criar_aba_insights(self) -> QWidget:
        """
        Aba de Insights com análise comportamental em 4 seções:
          1. Panorama geral (ação predominante + intensidade)
          2. Sites mais acessados (Top domínios DNS)
          3. Ações detectadas na rede (GET/POST)
          4. Hierarquia de protocolos + Top Talkers
        """
        widget = QWidget()
        layout_externo = QVBoxLayout(widget)
        layout_externo.setContentsMargins(0, 0, 0, 0)
        layout_externo.setSpacing(0)

        # Área rolável
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setStyleSheet(
            "QScrollArea { border: none; background: transparent; }"
        )

        self._container_insights = QWidget()
        self._layout_insights = QVBoxLayout(self._container_insights)
        self._layout_insights.setContentsMargins(8, 6, 8, 8)
        self._layout_insights.setSpacing(8)

        # Placeholder inicial
        self._lbl_insights_vazio = QLabel(
            "Os insights aparecerão aqui durante a captura.\n\n"
            "Inicie a captura e navegue pela internet para\n"
            "ver a análise comportamental da rede."
        )
        self._lbl_insights_vazio.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._lbl_insights_vazio.setStyleSheet(
            "color:#4a5a6b;font-size:12px;padding:50px;"
        )
        self._layout_insights.addWidget(self._lbl_insights_vazio)
        self._layout_insights.addStretch()

        scroll.setWidget(self._container_insights)
        layout_externo.addWidget(scroll)

        # Rodapé com resumo
        frame_rodape = QFrame()
        frame_rodape.setFixedHeight(28)
        frame_rodape.setStyleSheet(
            "QFrame { background:#0a0f1a; border-top:1px solid #1e2d40; }"
        )
        layout_rodape = QHBoxLayout(frame_rodape)
        layout_rodape.setContentsMargins(8, 4, 8, 4)

        self._lbl_resumo_insights = QLabel("Aguardando dados de captura...")
        self._lbl_resumo_insights.setStyleSheet(
            "color:#7f8c8d;font-size:9px;border:none;"
        )
        layout_rodape.addWidget(self._lbl_resumo_insights)
        layout_rodape.addStretch()

        self._lbl_total_insights = QLabel("")
        self._lbl_total_insights.setStyleSheet(
            "color:#3498DB;font-size:9px;font-family:Consolas;border:none;"
        )
        layout_rodape.addWidget(self._lbl_total_insights)

        layout_externo.addWidget(frame_rodape)
        return widget

    # ──────────────────────────────────────────────
    # Renderização dos cards de Insights
    # ──────────────────────────────────────────────

    def _renderizar_insights(self):
        """
        Reconstrói todos os cards de insights com base nos dados agregados
        pelo _MotorInsightsLocal. Só executa quando há novos dados.
        """
        versao_atual = self._motor_insights._versao
        if versao_atual == self._versao_insights_renderizada:
            return
        self._versao_insights_renderizada = versao_atual

        # Limpa layout anterior
        while self._layout_insights.count() > 0:
            item = self._layout_insights.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        dominios   = self._motor_insights.obter_top_dominios()
        protocolos = self._motor_insights.obter_hierarquia_protocolos()
        talkers    = self._motor_insights.obter_top_talkers()
        acoes      = self._motor_insights.obter_resumo_acoes()
        credenciais= self._motor_insights._credenciais_expostas
        total_ev   = self._motor_insights._total_alimentados

        if total_ev == 0:
            self._layout_insights.addWidget(self._lbl_insights_vazio)
            self._layout_insights.addStretch()
            return

        # ── Seção 1: Panorama geral ──────────────
        self._layout_insights.addWidget(
            self._card_panorama_geral(protocolos, acoes)
        )

        # ── Alerta crítico (credenciais expostas) ─
        if credenciais:
            self._layout_insights.addWidget(
                self._card_credenciais_expostas(credenciais)
            )

        # Layout em 2 colunas para as seções 2 e 3
        linha_dupla = QHBoxLayout()
        linha_dupla.setSpacing(8)

        # ── Seção 2: Top domínios DNS ────────────
        linha_dupla.addWidget(self._card_top_dominios(dominios))

        # ── Seção 3: Ações detectadas ────────────
        linha_dupla.addWidget(self._card_acoes_http(acoes))

        container_linha = QWidget()
        container_linha.setLayout(linha_dupla)
        self._layout_insights.addWidget(container_linha)

        # ── Seção 4: Hierarquia de protocolos ────
        self._layout_insights.addWidget(
            self._card_hierarquia_protocolos(protocolos)
        )

        # ── Seção 5: Top Talkers ─────────────────
        if talkers:
            self._layout_insights.addWidget(
                self._card_top_talkers(talkers)
            )

        self._layout_insights.addStretch()

        # Atualiza rodapé
        n_dns  = self._motor_insights._total_dns
        n_http = self._motor_insights._total_http
        n_cred = len(credenciais)
        resumo = f"{total_ev} eventos · {n_dns} DNS · {n_http} HTTP"
        if n_cred:
            resumo += f" · ⚠ {n_cred} credencial(is) exposta(s)"
        self._lbl_resumo_insights.setText(resumo)
        self._lbl_total_insights.setText(f"{total_ev:,} eventos analisados")

    def _base_card(self, cor_borda: str = "#1e3a5f",
                   cor_fundo: str = "#0d1a2a") -> QFrame:
        """Cria um frame base estilizado para um card de insight."""
        frame = QFrame()
        frame.setStyleSheet(
            f"QFrame {{ background:{cor_fundo}; border:1px solid {cor_borda}; "
            f"border-radius:8px; }}"
            f"QLabel {{ border:none; background:transparent; }}"
        )
        return frame

    def _titulo_secao(self, icone: str, texto: str, cor: str = "#3498DB") -> QLabel:
        """Cria um rótulo de título padronizado para seções de card."""
        lbl = QLabel(f"{icone}  {texto}")
        lbl.setStyleSheet(
            f"color:{cor};font-weight:bold;font-size:11px;"
            "border:none;padding-bottom:4px;"
        )
        return lbl

    def _card_panorama_geral(self, protocolos: list, acoes: dict) -> QFrame:
        """
        Card de panorama: ação predominante + intensidade de uso + distribuição.
        """
        frame = self._base_card("#2a4a70")
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(10)

        cab = QHBoxLayout()
        cab.addWidget(self._titulo_secao("", "PANORAMA GERAL DA REDE", "#5a9eff"))
        cab.addStretch()

        lbl_atualizado = QLabel("Atualizado agora")
        lbl_atualizado.setStyleSheet(
            "color:#4a6a8a;font-size:9px;border:none;"
        )
        cab.addWidget(lbl_atualizado)
        layout.addLayout(cab)

        # Determina ação e intensidade predominante
        acao_texto, acao_desc = self._classificar_acao_predominante(acoes, protocolos)
        total_bytes = sum(p["bytes"] for p in protocolos)
        intensidade, cor_int = self._classificar_intensidade(total_bytes)

        # Dois blocos de destaque lado a lado
        linha_blocos = QHBoxLayout()
        linha_blocos.setSpacing(8)

        bloco_acao = self._bloco_destaque("Ação Predominante", acao_texto, acao_desc, "#1a3a5c")
        bloco_int  = self._bloco_destaque(
            "Intensidade de Uso",
            intensidade,
            self._formatar_bytes(total_bytes),
            "#1a2a3c",
            cor_int
        )
        linha_blocos.addWidget(bloco_acao, 1)
        linha_blocos.addWidget(bloco_int, 1)
        layout.addLayout(linha_blocos)

        return frame

    def _bloco_destaque(self, rotulo: str, valor: str,
                        sub: str, fundo: str,
                        cor_valor: str = "#ecf0f1") -> QFrame:
        """Bloco visual de destaque com rótulo, valor grande e sub-texto."""
        bloco = QFrame()
        bloco.setStyleSheet(
            f"QFrame {{ background:{fundo}; border:1px solid #1e3a5f; "
            "border-radius:6px; }"
            "QLabel { border:none; background:transparent; }"
        )
        layout = QVBoxLayout(bloco)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(2)

        lbl_r = QLabel(rotulo)
        lbl_r.setStyleSheet("color:#6a8aaa;font-size:9px;font-weight:bold;")
        layout.addWidget(lbl_r)

        lbl_v = QLabel(valor)
        lbl_v.setStyleSheet(
            f"color:{cor_valor};font-size:16px;font-weight:bold;"
        )
        layout.addWidget(lbl_v)

        lbl_s = QLabel(sub)
        lbl_s.setStyleSheet("color:#7f8c8d;font-size:9px;")
        layout.addWidget(lbl_s)

        return bloco

    def _card_top_dominios(self, dominios: list) -> QFrame:
        """Card com ranking dos domínios mais consultados via DNS."""
        frame = self._base_card("#1e4a6b")
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(6)

        n_unicos = len(dominios)
        n_total  = self._motor_insights._total_dns
        layout.addWidget(
            self._titulo_secao(
                "", f"Top Domínios DNS — {n_unicos} únicos", "#3498DB"
            )
        )

        sub = QLabel(f"Baseado em {n_total} consultas DNS capturadas")
        sub.setStyleSheet("color:#6a8aaa;font-size:9px;")
        layout.addWidget(sub)

        if not dominios:
            lbl_vazio = QLabel("Nenhuma consulta DNS capturada ainda.")
            lbl_vazio.setStyleSheet("color:#4a5a6b;font-size:10px;padding:10px;")
            lbl_vazio.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.addWidget(lbl_vazio)
            return frame

        maximo = dominios[0]["consultas"] if dominios else 1

        for i, dado in enumerate(dominios[:8]):
            nome = dado["nome"]
            dom  = dado["dominio"]
            cnt  = dado["consultas"]
            pct  = cnt / maximo * 100

            linha = QHBoxLayout()
            linha.setSpacing(6)

            # Rank
            lbl_rank = QLabel(f"{i+1}.")
            lbl_rank.setFixedWidth(16)
            lbl_rank.setStyleSheet("color:#4a6a8a;font-size:9px;")
            linha.addWidget(lbl_rank)

            # Nome do domínio
            lbl_nome = QLabel(nome if nome != dom else dom)
            lbl_nome.setFixedWidth(120)
            lbl_nome.setStyleSheet(
                "color:#ecf0f1;font-size:10px;font-family:Consolas;"
            )
            lbl_nome.setToolTip(dom)
            linha.addWidget(lbl_nome)

            # Barra proporcional
            barra = QProgressBar()
            barra.setMaximum(100)
            barra.setValue(int(pct))
            barra.setTextVisible(False)
            barra.setFixedHeight(8)
            barra.setStyleSheet("""
                QProgressBar { background:#0a1520; border:none; border-radius:3px; }
                QProgressBar::chunk { background:#3498DB; border-radius:3px; }
            """)
            linha.addWidget(barra, 1)

            # Contagem
            lbl_cnt = QLabel(f"{cnt}×")
            lbl_cnt.setFixedWidth(32)
            lbl_cnt.setStyleSheet(
                "color:#3498DB;font-size:10px;font-family:Consolas;"
            )
            lbl_cnt.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            linha.addWidget(lbl_cnt)

            container = QWidget()
            container.setLayout(linha)
            layout.addWidget(container)

        return frame

    def _card_acoes_http(self, acoes: dict) -> QFrame:
        """
        Card com as ações HTTP detectadas traduzidas para linguagem humana.
        GET = Navegação, POST = Envio de dados, etc.
        """
        frame = self._base_card("#4a2a10")
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(6)

        total_http = sum(acoes.values())
        layout.addWidget(
            self._titulo_secao(
                "", f"Ações Detectadas na Rede — {total_http} req.", "#E67E22"
            )
        )

        sub = QLabel("Tradução das ações HTTP em comportamento humano")
        sub.setStyleSheet("color:#7a5a3a;font-size:9px;")
        layout.addWidget(sub)

        if total_http == 0:
            lbl_vazio = QLabel("Nenhuma requisição HTTP capturada ainda.")
            lbl_vazio.setStyleSheet("color:#4a5a6b;font-size:10px;padding:10px;")
            lbl_vazio.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.addWidget(lbl_vazio)
            return frame

        # Definição de cada ação com tradução humana
        definicoes = [
            ("GET",    "Navegando / Visualizando conteúdo",  "#3498DB", acoes.get("GET", 0)),
            ("POST",   "Enviando dados / Interagindo",       "#E74C3C", acoes.get("POST", 0)),
            ("PUT",    "Atualizando recurso no servidor",    "#E67E22", acoes.get("PUT", 0)),
            ("DELETE", "Removendo recurso do servidor",      "#9B59B6", acoes.get("DELETE", 0)),
            ("OUTRO",  "Outros métodos (HEAD, OPTIONS...)",  "#7f8c8d", acoes.get("OUTRO", 0)),
        ]

        for metodo, traducao, cor, qtd in definicoes:
            if qtd == 0:
                continue
            pct = qtd / total_http * 100

            bloco = QFrame()
            bloco.setStyleSheet(
                f"QFrame {{ background:#0d1a2a; border-left:3px solid {cor}; "
                "border-radius:0 4px 4px 0; margin:1px 0; }"
                "QLabel { border:none; background:transparent; }"
            )
            l_bloco = QVBoxLayout(bloco)
            l_bloco.setContentsMargins(8, 4, 8, 4)
            l_bloco.setSpacing(2)

            linha_topo = QHBoxLayout()
            lbl_metodo = QLabel(f"<b>{metodo}</b>")
            lbl_metodo.setStyleSheet(f"color:{cor};font-size:10px;font-family:Consolas;")
            linha_topo.addWidget(lbl_metodo)

            lbl_pct = QLabel(f"{pct:.0f}%  ({qtd}×)")
            lbl_pct.setStyleSheet(f"color:{cor};font-size:10px;font-family:Consolas;")
            lbl_pct.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            linha_topo.addWidget(lbl_pct)
            l_bloco.addLayout(linha_topo)

            lbl_trad = QLabel(traducao)
            lbl_trad.setStyleSheet("color:#9fb2c8;font-size:9px;")
            l_bloco.addWidget(lbl_trad)

            barra = QProgressBar()
            barra.setMaximum(100)
            barra.setValue(int(pct))
            barra.setTextVisible(False)
            barra.setFixedHeight(4)
            barra.setStyleSheet(f"""
                QProgressBar {{ background:#0a1520; border:none; border-radius:2px; }}
                QProgressBar::chunk {{ background:{cor}; border-radius:2px; }}
            """)
            l_bloco.addWidget(barra)

            layout.addWidget(bloco)

        # Aviso se POST detectado
        if acoes.get("POST", 0) > 0:
            aviso = QFrame()
            aviso.setStyleSheet(
                "QFrame { background:#2a0a00; border:1px solid #E74C3C; "
                "border-radius:4px; }"
                "QLabel { border:none; background:transparent; }"
            )
            l_av = QHBoxLayout(aviso)
            l_av.setContentsMargins(8, 6, 8, 6)
            lbl_av = QLabel(
                f"⚠ {acoes['POST']} envio(s) de dados via HTTP detectado(s). "
                "Dados podem ter sido transmitidos sem criptografia."
            )
            lbl_av.setStyleSheet("color:#E74C3C;font-size:9px;")
            lbl_av.setWordWrap(True)
            l_av.addWidget(lbl_av)
            layout.addWidget(aviso)

        return frame

    def _card_hierarquia_protocolos(self, protocolos: list) -> QFrame:
        """
        Card com hierarquia visual dos protocolos detectados.
        Exibe percentual, volume e barras proporcionais.
        """
        frame = self._base_card("#1a2a1a")
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(8)

        total_pacotes = sum(p["pacotes"] for p in protocolos) or 1
        layout.addWidget(
            self._titulo_secao(
                "", "Hierarquia de Protocolos", "#2ECC71"
            )
        )

        sub = QLabel(
            f"{total_pacotes:,} eventos classificados · "
            "ordenados por volume de atividade"
        )
        sub.setStyleSheet("color:#5a8a5a;font-size:9px;")
        layout.addWidget(sub)

        if not protocolos:
            lbl_vazio = QLabel("Nenhum protocolo detectado ainda.")
            lbl_vazio.setStyleSheet("color:#4a5a6b;font-size:10px;padding:10px;")
            lbl_vazio.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.addWidget(lbl_vazio)
            return frame

        # Grade de barras horizontais
        grade = QWidget()
        layout_grade = QGridLayout(grade)
        layout_grade.setContentsMargins(0, 0, 0, 0)
        layout_grade.setHorizontalSpacing(10)
        layout_grade.setVerticalSpacing(6)

        for linha_idx, proto in enumerate(protocolos[:10]):
            nome    = proto["protocolo"]
            pacotes = proto["pacotes"]
            pct     = proto["percentual"]
            bytes_  = proto["bytes"]
            cor     = proto["cor"]

            # Nome do protocolo
            lbl_nome = QLabel(nome)
            lbl_nome.setFixedWidth(65)
            lbl_nome.setStyleSheet(
                f"color:{cor};font-size:10px;font-family:Consolas;font-weight:bold;"
            )
            layout_grade.addWidget(lbl_nome, linha_idx, 0)

            # Barra
            barra = QProgressBar()
            barra.setMaximum(1000)
            barra.setValue(int(pct * 10))
            barra.setTextVisible(False)
            barra.setFixedHeight(12)
            barra.setStyleSheet(f"""
                QProgressBar {{
                    background: #0a1520;
                    border: 1px solid #1a2a1a;
                    border-radius: 5px;
                }}
                QProgressBar::chunk {{
                    background: {cor};
                    border-radius: 4px;
                }}
            """)
            layout_grade.addWidget(barra, linha_idx, 1)

            # Percentual
            lbl_pct = QLabel(f"{pct:.1f}%")
            lbl_pct.setFixedWidth(42)
            lbl_pct.setStyleSheet(
                f"color:{cor};font-size:10px;font-family:Consolas;"
            )
            lbl_pct.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            layout_grade.addWidget(lbl_pct, linha_idx, 2)

            # Volume
            lbl_vol = QLabel(f"{pacotes:,} evt")
            lbl_vol.setFixedWidth(60)
            lbl_vol.setStyleSheet("color:#7f8c8d;font-size:9px;")
            lbl_vol.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            layout_grade.addWidget(lbl_vol, linha_idx, 3)

            # Bytes
            lbl_bytes = QLabel(self._formatar_bytes(bytes_))
            lbl_bytes.setFixedWidth(65)
            lbl_bytes.setStyleSheet("color:#4a6a8a;font-size:9px;font-family:Consolas;")
            lbl_bytes.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            layout_grade.addWidget(lbl_bytes, linha_idx, 4)

        layout_grade.setColumnStretch(1, 1)
        layout.addWidget(grade)

        return frame

    def _card_top_talkers(self, talkers: list) -> QFrame:
        """
        Card com os dispositivos / IPs que geraram mais tráfego (Top Talkers).
        """
        frame = self._base_card("#2a1a3a")
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(6)

        layout.addWidget(
            self._titulo_secao("", "Top Talkers — Maior Volume de Tráfego", "#9B59B6")
        )

        sub = QLabel("Dispositivos e IPs com mais dados transmitidos nesta sessão")
        sub.setStyleSheet("color:#6a4a8a;font-size:9px;")
        layout.addWidget(sub)

        if not talkers:
            lbl_vazio = QLabel("Nenhum dado de volume disponível.")
            lbl_vazio.setStyleSheet("color:#4a5a6b;font-size:10px;padding:10px;")
            lbl_vazio.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.addWidget(lbl_vazio)
            return frame

        maximo_bytes = talkers[0]["bytes"] if talkers else 1

        tabela = QTableWidget(min(len(talkers), 8), 4)
        tabela.setHorizontalHeaderLabels(["IP / Endereço", "Volume", "Eventos", "Participação"])
        tabela.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        tabela.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        tabela.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        tabela.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        tabela.verticalHeader().setVisible(False)
        tabela.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        tabela.setAlternatingRowColors(True)
        tabela.setStyleSheet("""
            QTableWidget {
                background: #0d1a2a;
                color: #ecf0f1;
                border: none;
                gridline-color: #1e2d40;
                font-size: 10px;
            }
            QTableWidget::item:alternate { background: #0a1520; }
            QTableWidget::item:selected { background: #1e3a5f; }
            QHeaderView::section {
                background: #0a1520;
                color: #7f8c8d;
                border: 1px solid #1e2d40;
                padding: 4px;
                font-size: 9px;
            }
        """)

        total_bytes_geral = sum(t["bytes"] for t in talkers) or 1

        for i, talker in enumerate(talkers[:8]):
            ip_item = QTableWidgetItem(talker["ip"])
            ip_item.setForeground(QColor("#9B59B6"))
            tabela.setItem(i, 0, ip_item)

            vol_item = QTableWidgetItem(self._formatar_bytes(talker["bytes"]))
            vol_item.setForeground(QColor("#2ECC71"))
            vol_item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            tabela.setItem(i, 1, vol_item)

            evt_item = QTableWidgetItem(str(talker["eventos"]))
            evt_item.setForeground(QColor("#3498DB"))
            evt_item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            tabela.setItem(i, 2, evt_item)

            pct = talker["bytes"] / total_bytes_geral * 100
            pct_item = QTableWidgetItem(f"{pct:.1f}%")
            pct_item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            if pct > 50:
                pct_item.setForeground(QColor("#E74C3C"))
            elif pct > 25:
                pct_item.setForeground(QColor("#E67E22"))
            else:
                pct_item.setForeground(QColor("#7f8c8d"))
            tabela.setItem(i, 3, pct_item)

        tabela.setFixedHeight(min(len(talkers), 8) * 26 + 30)
        layout.addWidget(tabela)

        return frame

    def _card_credenciais_expostas(self, credenciais: list) -> QFrame:
        """Card de alerta crítico para credenciais capturadas em texto puro."""
        frame = self._base_card("#5a0000", "#200a0a")
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(6)

        cab = QHBoxLayout()
        lbl_titulo = QLabel(f"⚠  RISCO CRÍTICO — {len(credenciais)} credencial(is) exposta(s)")
        lbl_titulo.setStyleSheet(
            "color:#E74C3C;font-weight:bold;font-size:12px;border:none;"
        )
        cab.addWidget(lbl_titulo)
        layout.addLayout(cab)

        descricao = QLabel(
            "Credenciais transmitidas via HTTP em texto puro.\n"
            "Qualquer dispositivo na mesma rede pode capturar estas informações (ataque MITM)."
        )
        descricao.setStyleSheet("color:#ff9a9a;font-size:10px;border:none;")
        descricao.setWordWrap(True)
        layout.addWidget(descricao)

        tabela = QTableWidget(min(len(credenciais), 5), 3)
        tabela.setHorizontalHeaderLabels(["Hora", "IP Origem", "Campos detectados"])
        tabela.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        tabela.verticalHeader().setVisible(False)
        tabela.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        tabela.setStyleSheet("""
            QTableWidget { background:#1a0000; color:#ecf0f1;
                           border:none; font-size:10px; }
            QHeaderView::section { background:#2a0000; color:#E74C3C;
                                   border:1px solid #5a0000; padding:3px; }
        """)
        tabela.setFixedHeight(min(len(credenciais), 5) * 26 + 30)

        for i, (ts, ip, campos) in enumerate(credenciais[-5:]):
            tabela.setItem(i, 0, QTableWidgetItem(ts))
            ip_item = QTableWidgetItem(ip)
            ip_item.setForeground(QColor("#E74C3C"))
            tabela.setItem(i, 1, ip_item)
            campos_item = QTableWidgetItem(", ".join(campos))
            campos_item.setForeground(QColor("#E67E22"))
            tabela.setItem(i, 2, campos_item)

        layout.addWidget(tabela)
        return frame

    # ──────────────────────────────────────────────
    # Métodos de classificação
    # ──────────────────────────────────────────────

    def _classificar_acao_predominante(self, acoes: dict,
                                        protocolos: list) -> tuple:
        """
        Determina a ação predominante na sessão em linguagem natural.
        Retorna (texto_principal, descricao).
        """
        total_http = sum(acoes.values())
        total_ev   = self._motor_insights._total_alimentados

        # Analisa protocolos com maior volume
        proto_map = {p["protocolo"]: p["pacotes"] for p in protocolos}

        # Verifica se há streaming (muitos HTTPS + grandes volumes)
        total_bytes = sum(p["bytes"] for p in protocolos)
        https_bytes = next(
            (p["bytes"] for p in protocolos if p["protocolo"] == "HTTPS"), 0
        )
        pct_https = https_bytes / total_bytes * 100 if total_bytes else 0

        # Avalia POST vs GET
        posts = acoes.get("POST", 0)
        gets  = acoes.get("GET", 0)

        if total_ev == 0:
            return "Sem atividade", "Nenhum evento capturado."

        if posts > 0 and posts >= gets:
            n_acoes = f"{posts} envio(s) registrado(s)"
            return "Enviando Dados", n_acoes

        if pct_https > 70 and total_bytes > 500_000:
            return "Streaming / Download", f"{pct_https:.0f}% via HTTPS"

        dns_count = proto_map.get("DNS", 0)
        if dns_count > total_ev * 0.4:
            return "Descoberta de Rede", f"{dns_count} consultas DNS"

        if gets > 0:
            n_acoes = f"{gets} requisição(ões) GET"
            return "Navegação Web", n_acoes

        arp_count = proto_map.get("ARP", 0)
        if arp_count > total_ev * 0.5:
            return "Varredura / ARP", f"{arp_count} pacotes ARP"

        return "Navegação Web", f"{total_ev} ação(ões) registrada(s)"

    @staticmethod
    def _classificar_intensidade(total_bytes: int) -> tuple:
        """
        Classifica a intensidade de uso com base no volume total de bytes.
        Retorna (texto, cor).
        """
        kb = total_bytes / 1024
        if kb < 100:
            return "Leve", "#2ECC71"
        if kb < 1024:
            return "Moderado", "#3498DB"
        if kb < 10 * 1024:
            return "Intenso", "#E67E22"
        return "Muito Intenso", "#E74C3C"

    @staticmethod
    def _formatar_bytes(b: int) -> str:
        """Formata bytes para exibição legível."""
        if b == 0:
            return "0 KB"
        kb = b / 1024
        if kb < 1024:
            return f"{kb:.1f} KB"
        return f"{kb/1024:.2f} MB"

    # ──────────────────────────────────────────────
    # Métodos públicos de atualização (compatíveis com janela_principal)
    # ──────────────────────────────────────────────

    def atualizar_insights(self, top_dns: list, historias: list):
        """
        Atualiza a aba Insights com dados do motor local.
        Chamado a cada segundo pela janela principal.
        """
        self._renderizar_insights()

    def atualizar_insights_correlacionados(self, insights: list, estatisticas: dict,
                                            top_dominios: list, narrativas: list):
        """
        Compatibilidade com MotorCorrelacao externo.
        Delega para a renderização local quando dados externos não estão disponíveis.
        """
        self._renderizar_insights()

    def adicionar_evento(self, dados: dict):
        """Recebe um evento do motor pedagógico e exibe na interface."""
        def _corrigir_encoding(txt: str) -> str:
            if not isinstance(txt, str):
                return txt
            for enc in ("cp1252", "latin1"):
                try:
                    return txt.encode(enc, errors="ignore").decode("utf-8")
                except Exception:
                    continue
            return txt

        if len(self._todos_eventos) >= self.LIMITE_EVENTOS:
            self._todos_eventos.pop(0)

        sessao = dados.get("sessao_id", "sessao_default")
        tipo   = dados.get("tipo", "")
        self._contagem_sessao[sessao][tipo] += 1
        dados["contador_sessao"] = self._contagem_sessao[sessao][tipo]

        for campo in ("titulo", "nivel1", "nivel2", "nivel3", "nivel4",
                      "alerta_seguranca", "fluxo_visual"):
            if campo in dados:
                dados[campo] = _corrigir_encoding(dados[campo])

        self._todos_eventos.append(dados)
        self.painel_contadores.incrementar(tipo)

        if self._passa_filtro(dados):
            self._adicionar_cartao(dados)
            self._eventos_filtrados.append(dados)

        self._evento_atual = dados
        self._renderizar_explicacao()
        self._atualizar_rodape()

        # Alimenta o motor de insights
        try:
            self._motor_insights.alimentar(dados)
        except Exception:
            pass

    def limpar(self):
        """Limpa todos os eventos e reinicia a interface."""
        self._todos_eventos.clear()
        self._eventos_filtrados.clear()
        self._evento_atual = {}
        self._contagem_sessao.clear()
        self.painel_contadores.resetar()

        while self._layout_cartoes.count() > 1:
            item = self._layout_cartoes.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        # Limpa aba de insights
        while self._layout_insights.count() > 0:
            item = self._layout_insights.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        self._layout_insights.addWidget(self._lbl_insights_vazio)
        self._layout_insights.addStretch()
        self._lbl_resumo_insights.setText("Aguardando dados de captura...")
        self._lbl_total_insights.setText("")

        self.lbl_rodape.setText("Nenhum evento registrado.")
        self._exibir_boas_vindas()

        # Reseta motor
        try:
            self._motor_insights.resetar()
            self._versao_insights_renderizada = -1
        except Exception:
            pass

    # ──────────────────────────────────────────────
    # Filtros
    # ──────────────────────────────────────────────

    @pyqtSlot(str)
    def _ao_mudar_filtro_protocolo(self, valor: str):
        self._filtro_protocolo = valor
        self._reaplicar_filtros()

    @pyqtSlot(str)
    def _ao_mudar_filtro_texto(self, texto: str):
        self._filtro_texto = texto.lower().strip()
        self._reaplicar_filtros()

    def _passa_filtro(self, dados: dict) -> bool:
        """Verifica se um evento passa pelos filtros ativos."""
        if (self._filtro_protocolo and
                self._filtro_protocolo != "Todos" and
                dados.get("tipo", "").upper() != self._filtro_protocolo.upper()):
            return False
        if self._filtro_texto:
            campos = " ".join([
                dados.get("ip_envolvido", ""),
                dados.get("ip_destino",   ""),
                dados.get("titulo",       ""),
                dados.get("nivel1",       ""),
                dados.get("tipo",         ""),
            ]).lower()
            if self._filtro_texto not in campos:
                return False
        return True

    def _reaplicar_filtros(self):
        """Reconstrói a lista de cartões com os filtros ativos."""
        while self._layout_cartoes.count() > 1:
            item = self._layout_cartoes.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        self._eventos_filtrados = [
            e for e in self._todos_eventos if self._passa_filtro(e)
        ]
        for evento in self._eventos_filtrados:
            self._adicionar_cartao(evento)
        self._atualizar_rodape()

        if self._eventos_filtrados:
            self._evento_atual = self._eventos_filtrados[-1]
            self._renderizar_explicacao()
        else:
            self._evento_atual = {}
            self._exibir_boas_vindas()

    def _atualizar_rodape(self):
        """Atualiza o texto do rodapé com contagens da sessão."""
        total    = len(self._todos_eventos)
        visiveis = len(self._eventos_filtrados)
        sessao   = self._evento_atual.get("sessao_id", "sessao_default") if self._evento_atual else None
        extra    = ""
        if sessao and sessao in self._contagem_sessao:
            resumo = ", ".join(
                f"{k}:{v}"
                for k, v in sorted(self._contagem_sessao[sessao].items())
            )
            extra = f" | Sessão {sessao}: {resumo}"

        if total == visiveis:
            self.lbl_rodape.setText(f"{total} evento(s) registrado(s).{extra}")
        else:
            self.lbl_rodape.setText(
                f"{visiveis} exibido(s) de {total} total (filtro ativo).{extra}"
            )

    # ──────────────────────────────────────────────
    # Cartões e renderização de explicações
    # ──────────────────────────────────────────────

    def _adicionar_cartao(self, dados: dict):
        """Insere um cartão de evento na lista lateral."""
        cartao = CartaoEvento(dados)
        dados_ref = dados
        cartao.mousePressEvent = lambda _: self._ao_clicar_cartao(dados_ref)

        pos = self._layout_cartoes.count() - 1
        self._layout_cartoes.insertWidget(pos, cartao)

        barra = self._scroll.verticalScrollBar()
        barra.setValue(barra.maximum())

    def _ao_clicar_cartao(self, dados: dict):
        self._evento_atual = dados
        self._renderizar_explicacao()

    def _trocar_nivel(self, nivel: int):
        """Troca o nível de explicação exibido (Simples / Técnico / Pacote Bruto)."""
        self._nivel_atual = nivel
        for i, btn in enumerate(self.botoes_nivel):
            btn.setChecked(i == nivel)
        if self._evento_atual:
            self._renderizar_explicacao()

    def _renderizar_explicacao(self):
        """Constrói o HTML da explicação para o evento atual no nível selecionado."""
        if not self._evento_atual or not self._evento_atual.get("titulo"):
            return

        e      = self._evento_atual
        titulo = e.get("titulo", "Evento")
        nivel  = e.get("nivel", "INFO")
        hora   = e.get("timestamp", "")
        ip_src = e.get("ip_envolvido", "")
        ip_dst = e.get("ip_destino", "")
        cont   = e.get("contador", 1)
        cont_s = e.get("contador_sessao", cont)
        fluxo  = e.get("fluxo_visual", "")
        alerta = e.get("alerta_seguranca", "")

        estilo = ESTILOS_NIVEL.get(nivel, ESTILOS_NIVEL["INFO"])
        cor    = estilo["borda"]

        chaves_nivel = ["nivel1", "nivel2", "nivel4"]
        rotulo       = ROTULOS_NIVEL[self._nivel_atual]

        if self._nivel_atual == 2:
            conteudo = e.get("nivel4", "")
            if not conteudo:
                conteudo = (
                    "<div style='text-align:center;padding:40px;color:#7f8c8d;'>"
                    "<b>Pacote Bruto</b> está disponível apenas para eventos HTTP.<br><br>"
                    "Acesse um site HTTP (porta 80) e envie um formulário para "
                    "visualizar o conteúdo exato do pacote como trafegou na rede."
                    "</div>"
                )
        else:
            conteudo = e.get(chaves_nivel[self._nivel_atual], "Indisponível.")

        ip_linha = ip_src
        if ip_dst and ip_dst != ip_src:
            ip_linha += f" → {ip_dst}"

        bloco_fluxo = ""
        if fluxo:
            bloco_fluxo = (
                f"<div style='font-family:Consolas;font-size:11px;"
                f"background:#0d1520;padding:8px 14px;"
                f"border-radius:5px;color:#ecf0f1;margin:8px 0;"
                f"border-left:3px solid {cor};'>"
                f"{fluxo}</div>"
            )

        bloco_alerta = ""
        if alerta:
            bloco_alerta = (
                f"<div style='background:#2a0a00;border:1px solid #E74C3C;"
                f"border-radius:5px;padding:10px 14px;margin:8px 0;'>"
                f"<b style='color:#E74C3C;'>ALERTA DE SEGURANÇA:</b><br>"
                f"<span style='color:#ecf0f1;'>{alerta}</span>"
                f"</div>"
            )

        html = f"""
        <div style="font-family:Arial,sans-serif;font-size:11px;
                    line-height:1.7;color:#ecf0f1;">
          <h3 style="color:{cor};margin:0 0 4px 0;">{titulo}</h3>
          <p style="color:#7f8c8d;font-size:10px;margin:0 0 10px 0;">
            🕐 {hora} &nbsp;·&nbsp;
            <code style="color:#3498DB;">{ip_linha}</code>
            &nbsp;·&nbsp; Ocorrências: <b>{cont}</b>
            &nbsp;·&nbsp; Nesta sessão: <b>{cont_s}</b>
          </p>
          {bloco_fluxo}
          {bloco_alerta}
          <div style="background:#0d1520;border-left:3px solid {cor};
                      border-radius:4px;padding:12px 16px;margin:8px 0;">
            <b style="color:{cor};font-size:10px;">
              {rotulo[0]} {rotulo[1]} — {rotulo[2]}
            </b><br><br>
            {conteudo}
          </div>
        </div>
        """
        self.texto_explicacao.setHtml(html)

    def _exibir_boas_vindas(self):
        """Exibe mensagem inicial de boas-vindas no painel de explicação."""
        self.texto_explicacao.setHtml("""
        <div style="font-family:Arial,sans-serif;font-size:11px;
                    line-height:1.7;color:#ecf0f1;padding:4px;">
          <h3 style="color:#3498DB;margin:0 0 10px 0;">
            👋 Bem-vindo ao Modo Análise
          </h3>
          <p>Este painel transforma pacotes reais capturados da rede em
          <b>explicações didáticas automáticas</b> em três níveis de
          profundidade.</p>
          <p><b>Como usar:</b><br>
          1. Clique em <b>Iniciar Captura</b> na barra superior<br>
          2. Acesse sites no navegador para gerar tráfego<br>
          3. Os eventos aparecerão aqui automaticamente<br>
          4. Clique em qualquer evento para ver a explicação<br>
          5. Use os botões abaixo para trocar o nível de detalhe</p>
          <p><b>Os três níveis de explicação:</b><br>
          <b>Simples</b> — linguagem do dia a dia, sem jargão técnico<br>
          <b>Técnico</b> — protocolos, portas, vulnerabilidades<br>
          <b>Pacote Bruto</b> — conteúdo exato como trafegou na rede
          (exclusivo para HTTP), com destaques de campos e riscos</p>
          <p style="color:#7f8c8d;font-size:10px;">
            Acesse a aba <b>Insights</b> para ver análise comportamental da rede:
            sites mais acessados, ações detectadas, hierarquia de protocolos
            e os dispositivos com maior volume de tráfego (Top Talkers).
          </p>
        </div>
        """)