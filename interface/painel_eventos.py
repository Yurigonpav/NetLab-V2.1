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
# Agregador de Insights — leve, O(1) por evento, 100% em memória
# ─────────────────────────────────────────────────────────────

from collections import Counter

class _AgregadorInsights:
    """
    Agrega eventos de rede para Top Talkers e Top Domínios.
    Complexidade O(1) por evento. Sem I/O. Sem banco de dados.
    """

    # Limite de entradas mantidas em memória
    _MAX_ENTRADAS = 500

    def __init__(self):
        self.resetar()

    def resetar(self):
        self._bytes_por_ip:      Counter = Counter()
        self._eventos_por_ip:    Counter = Counter()
        self._contagem_dominios: Counter = Counter()
        self._total_dns:  int = 0
        self._versao:     int = 0

    # ----------------------------------------------------------

    def alimentar(self, evento: dict):
        """
        Processa um evento e atualiza os agregadores.
        Nunca lança exceção — fail-safe por design.
        """
        try:
            self._versao += 1
            tipo    = evento.get("tipo", "")
            ip      = evento.get("ip_envolvido") or evento.get("ip_origem") or ""
            tamanho = evento.get("tamanho", 0) or 0

            # ── Top Talkers ───────────────────────────────────
            if ip:
                self._bytes_por_ip[ip]   += tamanho
                self._eventos_por_ip[ip] += 1
                # Mantém só os _MAX_ENTRADAS mais ativos
                if len(self._bytes_por_ip) > self._MAX_ENTRADAS:
                    menor = min(self._bytes_por_ip, key=self._bytes_por_ip.__getitem__)
                    del self._bytes_por_ip[menor]
                    self._eventos_por_ip.pop(menor, None)

            # ── Top Domínios (DNS + inferência de Host) ───────
            if tipo == "DNS":
                self._total_dns += 1
                dominio = self._extrair_dominio(evento)
                if dominio:
                    raiz = self._dominio_raiz(dominio)
                    self._contagem_dominios[raiz] += 1
                    if len(self._contagem_dominios) > self._MAX_ENTRADAS:
                        menor = min(self._contagem_dominios,
                                    key=self._contagem_dominios.__getitem__)
                        del self._contagem_dominios[menor]

            elif tipo in ("HTTP", "HTTPS"):
                # Infere domínio a partir do campo host ou título
                host = (evento.get("host") or
                        evento.get("http_host") or
                        evento.get("dominio") or "")
                if not host and "—" in (evento.get("titulo") or ""):
                    host = evento["titulo"].split("—")[-1].strip()
                if host:
                    raiz = self._dominio_raiz(host.strip().rstrip("."))
                    self._contagem_dominios[raiz] += 1

        except Exception:
            pass

    # ----------------------------------------------------------

    def top_talkers(self, n: int = 8) -> list[tuple]:
        """Retorna lista de (ip, bytes, eventos) ordenada por bytes."""
        return [
            (ip, b, self._eventos_por_ip.get(ip, 0))
            for ip, b in self._bytes_por_ip.most_common(n)
        ]

    def top_dominios(self, n: int = 10) -> list[tuple]:
        """Retorna lista de (dominio, nome_amigavel, consultas) ordenada por frequência."""
        return [
            (dom, DOMINIOS_CONHECIDOS.get(dom, dom), cnt)
            for dom, cnt in self._contagem_dominios.most_common(n)
        ]

    # ----------------------------------------------------------

    @staticmethod
    def _extrair_dominio(evento: dict) -> str:
        dominio = evento.get("dominio", "")
        if not dominio:
            titulo = evento.get("titulo", "")
            if "—" in titulo:
                dominio = titulo.split("—")[-1].strip()
        return dominio.strip().rstrip(".")

    @staticmethod
    def _dominio_raiz(dominio: str) -> str:
        partes = dominio.lower().split(".")
        if len(partes) >= 3 and partes[-2] in ("com", "org", "net", "edu", "gov"):
            return ".".join(partes[-3:])
        if len(partes) >= 2:
            return ".".join(partes[-2:])
        return dominio


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

        # Agregador de insights — leve, sem estado externo
        self._agregador                  = _AgregadorInsights()
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

    # ──────────────────────────────────────────────
    # Aba Insights — enxuta e estável
    # ──────────────────────────────────────────────

    def _criar_aba_insights(self) -> QWidget:
        """
        Aba de Insights com dois painéis:
          1. Top Talkers — IPs com maior volume de tráfego
          2. Top Domínios — destinos mais acessados na rede
        """
        widget = QWidget()
        layout_externo = QVBoxLayout(widget)
        layout_externo.setContentsMargins(0, 0, 0, 0)
        layout_externo.setSpacing(0)

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
        self._layout_insights.addStretch()

        scroll.setWidget(self._container_insights)
        layout_externo.addWidget(scroll)

        # Rodapé
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
        Reconstrói os dois cards de insights quando há novos dados.
        Todos os widgets são criados frescos — sem risco de objeto C++ deletado.
        """
        versao_atual = self._agregador._versao
        if versao_atual == self._versao_insights_renderizada:
            return
        self._versao_insights_renderizada = versao_atual

        # Limpa layout de forma segura (sem guardar referência de placeholder)
        while self._layout_insights.count() > 0:
            item = self._layout_insights.takeAt(0)
            w = item.widget()
            if w:
                w.deleteLater()

        total_ev = len(self._todos_eventos)

        if total_ev == 0:
            lbl = QLabel(
                "Os insights aparecerão aqui durante a captura.\n\n"
                "Inicie a captura e navegue pela internet para\n"
                "ver os dados de tráfego em tempo real."
            )
            lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            lbl.setStyleSheet("color:#4a5a6b;font-size:12px;padding:50px;")
            self._layout_insights.addWidget(lbl)
            self._layout_insights.addStretch()
            self._lbl_resumo_insights.setText("Aguardando dados de captura...")
            self._lbl_total_insights.setText("")
            return

        talkers  = self._agregador.top_talkers(8)
        dominios = self._agregador.top_dominios(10)

        self._layout_insights.addWidget(self._card_talkers(talkers, total_ev))
        self._layout_insights.addWidget(self._card_dominios(dominios))
        self._layout_insights.addStretch()

        n_dns = self._agregador._total_dns
        self._lbl_resumo_insights.setText(
            f"{total_ev} eventos · {n_dns} consultas DNS"
        )
        self._lbl_total_insights.setText(f"{total_ev:,} eventos analisados")

    # ──────────────────────────────────────────────
    # Card 1 — Top Talkers
    # ──────────────────────────────────────────────

    def _card_talkers(self, talkers: list, total_ev: int) -> QFrame:
        """Card com os IPs de maior movimentação de rede."""
        frame = QFrame()
        frame.setStyleSheet(
            "QFrame { background:#0d1a2a; border:1px solid #2a1a3a; border-radius:8px; }"
            "QLabel { border:none; background:transparent; }"
        )
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(6)

        # Cabeçalho
        cab = QHBoxLayout()
        titulo = QLabel("  Top Talkers — Maior Volume de Tráfego")
        titulo.setStyleSheet(
            "color:#9B59B6;font-weight:bold;font-size:11px;padding-bottom:4px;"
        )
        cab.addWidget(titulo)
        cab.addStretch()
        lbl_n = QLabel(f"{len(talkers)} IP(s) ativos · {total_ev} eventos totais")
        lbl_n.setStyleSheet("color:#4a3a6a;font-size:9px;")
        cab.addWidget(lbl_n)
        layout.addLayout(cab)

        sub = QLabel("IPs com maior movimentação de dados nesta sessão")
        sub.setStyleSheet("color:#6a4a8a;font-size:9px;")
        layout.addWidget(sub)

        if not talkers:
            lbl_v = QLabel("Nenhum dado de tráfego disponível ainda.")
            lbl_v.setStyleSheet("color:#4a5a6b;font-size:10px;padding:10px;")
            lbl_v.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.addWidget(lbl_v)
            return frame

        # Tabela
        n_rows = len(talkers)
        tabela = QTableWidget(n_rows, 3)
        tabela.setHorizontalHeaderLabels(["IP / Endereço", "Volume", "Eventos"])
        tabela.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.Stretch
        )
        tabela.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.ResizeToContents
        )
        tabela.horizontalHeader().setSectionResizeMode(
            2, QHeaderView.ResizeMode.ResizeToContents
        )
        tabela.verticalHeader().setVisible(False)
        tabela.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        tabela.setAlternatingRowColors(True)
        tabela.setSelectionMode(QTableWidget.SelectionMode.NoSelection)
        tabela.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        tabela.setStyleSheet("""
            QTableWidget {
                background:#0d1a2a; color:#ecf0f1;
                border:none; gridline-color:#1e2d40; font-size:10px;
            }
            QTableWidget::item:alternate { background:#0a1520; }
            QHeaderView::section {
                background:#0a1520; color:#7f8c8d;
                border:1px solid #1e2d40; padding:4px; font-size:9px;
            }
        """)

        for i, (ip, bytes_, eventos) in enumerate(talkers):
            ip_item = QTableWidgetItem(ip)
            ip_item.setForeground(QColor("#9B59B6"))
            tabela.setItem(i, 0, ip_item)

            vol_item = QTableWidgetItem(self._formatar_bytes(bytes_))
            vol_item.setForeground(QColor("#2ECC71"))
            vol_item.setTextAlignment(
                Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
            )
            tabela.setItem(i, 1, vol_item)

            evt_item = QTableWidgetItem(str(eventos))
            evt_item.setForeground(QColor("#3498DB"))
            evt_item.setTextAlignment(
                Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
            )
            tabela.setItem(i, 2, evt_item)

        tabela.setFixedHeight(n_rows * 26 + 30)
        layout.addWidget(tabela)
        return frame

    # ──────────────────────────────────────────────
    # Card 2 — Top Domínios / Serviços
    # ──────────────────────────────────────────────

    def _card_dominios(self, dominios: list) -> QFrame:
        """Card com ranking dos domínios/serviços mais acessados."""
        frame = QFrame()
        frame.setStyleSheet(
            "QFrame { background:#0d1a2a; border:1px solid #1e4a6b; border-radius:8px; }"
            "QLabel { border:none; background:transparent; }"
        )
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(6)

        # Cabeçalho
        cab = QHBoxLayout()
        titulo = QLabel("  Top Domínios / Serviços")
        titulo.setStyleSheet(
            "color:#3498DB;font-weight:bold;font-size:11px;padding-bottom:4px;"
        )
        cab.addWidget(titulo)
        cab.addStretch()
        lbl_n = QLabel(f"{len(dominios)} domínio(s) único(s)")
        lbl_n.setStyleSheet("color:#2a4a6a;font-size:9px;")
        cab.addWidget(lbl_n)
        layout.addLayout(cab)

        n_dns = self._agregador._total_dns
        sub = QLabel(
            f"Baseado em {n_dns} consultas DNS · "
            "inclui inferência via HTTP/HTTPS Host"
        )
        sub.setStyleSheet("color:#6a8aaa;font-size:9px;")
        layout.addWidget(sub)

        if not dominios:
            if n_dns > 0:
                msg = (f"{n_dns} consulta(s) capturada(s), "
                       "mas domínios não foram identificados.")
            else:
                msg = "Nenhum domínio capturado ainda."
            lbl_v = QLabel(msg)
            lbl_v.setStyleSheet("color:#4a5a6b;font-size:10px;padding:10px;")
            lbl_v.setAlignment(Qt.AlignmentFlag.AlignCenter)
            lbl_v.setWordWrap(True)
            layout.addWidget(lbl_v)
            return frame

        maximo = dominios[0][2] if dominios else 1

        for i, (dom, nome, cnt) in enumerate(dominios[:10]):
            pct = cnt / maximo * 100

            linha = QHBoxLayout()
            linha.setSpacing(6)

            lbl_rank = QLabel(f"{i + 1}.")
            lbl_rank.setFixedWidth(18)
            lbl_rank.setStyleSheet("color:#4a6a8a;font-size:9px;")
            linha.addWidget(lbl_rank)

            lbl_nome = QLabel(nome if nome != dom else dom)
            lbl_nome.setFixedWidth(130)
            lbl_nome.setStyleSheet(
                "color:#ecf0f1;font-size:10px;font-family:Consolas;"
            )
            lbl_nome.setToolTip(dom)
            linha.addWidget(lbl_nome)

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

            lbl_cnt = QLabel(f"{cnt}×")
            lbl_cnt.setFixedWidth(36)
            lbl_cnt.setStyleSheet(
                "color:#3498DB;font-size:10px;font-family:Consolas;"
            )
            lbl_cnt.setAlignment(
                Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
            )
            linha.addWidget(lbl_cnt)

            row_w = QWidget()
            row_w.setLayout(linha)
            layout.addWidget(row_w)

        return frame

    # ──────────────────────────────────────────────
    # Utilitário
    # ──────────────────────────────────────────────

    @staticmethod
    def _formatar_bytes(b: int) -> str:
        """Formata bytes para exibição legível."""
        if b == 0:
            return "—"
        kb = b / 1024
        if kb < 1024:
            return f"{kb:.1f} KB"
        return f"{kb / 1024:.2f} MB"

    # ──────────────────────────────────────────────
    # Métodos públicos de atualização (compatíveis com janela_principal)
    # ──────────────────────────────────────────────

    def atualizar_insights(self, top_dns: list, historias: list):
        """
        Chamado a cada segundo pela janela principal.
        Apenas dispara a re-renderização se houver novos dados.
        """
        self._renderizar_insights()

    def atualizar_insights_correlacionados(self, insights: list, estatisticas: dict,
                                            top_dominios: list, narrativas: list):
        """Compatibilidade com MotorCorrelacao externo."""
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

        # Alimenta o agregador de insights
        try:
            self._agregador.alimentar(dados)
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

        # Reseta agregador
        try:
            self._agregador.resetar()
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