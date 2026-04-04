# interface/painel_eventos.py
# Painel do Modo Analise — três níveis de explicação (Simples, Técnico, Pacote Bruto).
# O nível Pacote Bruto é exclusivo para HTTP e mostra o tráfego exatamente como capturado.
# Aba de Insights refatorada para usar dados do MotorCorrelacao.

from collections import defaultdict
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QScrollArea, QFrame, QPushButton, QTextEdit,
    QSplitter, QTabWidget, QLineEdit, QComboBox,
    QTableWidget, QTableWidgetItem, QHeaderView
)
from PyQt6.QtCore import Qt, pyqtSlot
from PyQt6.QtGui import QFont

ESTILOS_NIVEL = {
    "INFO":   {"borda": "#3498DB", "fundo": "#0d1a2a", "badge": "#1a4a6b"},
    "AVISO":  {"borda": "#E67E22", "fundo": "#1f1200", "badge": "#5a3000"},
    "CRITICO":{"borda": "#E74C3C", "fundo": "#200a0a", "badge": "#5a0000"},
}

ROTULOS_NIVEL = [
    ("", "Simples",      "Linguagem do dia a dia"),
    ("", "Técnico",      "Detalhes do protocolo"),
    ("", "Pacote Bruto", "Conteúdo exato como trafegou na rede"),
]


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

        header = QHBoxLayout()
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

        header.addWidget(icone_titulo, 1)
        header.addWidget(hora)
        layout.addLayout(header)

        ip_src   = dados.get("ip_envolvido", "")
        ip_dst   = dados.get("ip_destino", "")
        ip_texto = ip_src
        if ip_dst and ip_dst != ip_src:
            ip_texto += f" -> {ip_dst}"

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


class PainelEventos(QWidget):
    """
    Painel completo do Modo Análise com três níveis de explicação.

    O nível Pacote Bruto exibe o conteúdo HTTP exatamente como
    trafegou na rede — disponível apenas para eventos HTTP.
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
        self.abas.setTabBarAutoHide(True)
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

        # Lista lateral de eventos
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

        # Painel de explicação
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
    # Aba de Insights (refatorada com MotorCorrelacao)
    # ──────────────────────────────────────────────

    def _criar_aba_insights(self) -> QWidget:
        """
        Aba de Insights com dados reais correlacionados pelo MotorCorrelacao.
        Exibe cards de: top destinos, categorias, dispositivos, segurança,
        HTTP inseguro e atividade temporal.
        """
        widget = QWidget()
        layout_externo = QVBoxLayout(widget)
        layout_externo.setContentsMargins(0, 0, 0, 0)
        layout_externo.setSpacing(0)

        # Área rolável para os cards
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setStyleSheet("QScrollArea { border: none; background: transparent; }")

        self._container_insights = QWidget()
        self._layout_insights = QVBoxLayout(self._container_insights)
        self._layout_insights.setContentsMargins(6, 4, 6, 4)
        self._layout_insights.setSpacing(6)

        # Mensagem de estado vazio
        self._lbl_insights_vazio = QLabel(
            "Os insights aparecerão aqui durante a captura.\n\n"
            "Os dados são correlacionados automaticamente entre\n"
            "DNS, TCP, TLS/SNI e volume de tráfego."
        )
        self._lbl_insights_vazio.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._lbl_insights_vazio.setStyleSheet(
            "color:#7f8c8d;font-size:10px;padding:30px;"
        )
        self._layout_insights.addWidget(self._lbl_insights_vazio)
        self._layout_insights.addStretch()

        scroll.setWidget(self._container_insights)
        layout_externo.addWidget(scroll)

        # Rodapé com estatísticas resumidas
        frame_rodape = QFrame()
        frame_rodape.setStyleSheet(
            "QFrame { background:#0a0f1a; border-top:1px solid #1e2d40; }"
        )
        layout_rodape = QHBoxLayout(frame_rodape)
        layout_rodape.setContentsMargins(8, 4, 8, 4)

        self._lbl_resumo_correlacao = QLabel("Nenhum dado correlacionado ainda.")
        self._lbl_resumo_correlacao.setStyleSheet(
            "color:#7f8c8d;font-size:9px;border:none;"
        )
        layout_rodape.addWidget(self._lbl_resumo_correlacao)
        layout_rodape.addStretch()

        self._lbl_total_eventos_correlacionados = QLabel("")
        self._lbl_total_eventos_correlacionados.setStyleSheet(
            "color:#3498DB;font-size:9px;font-family:Consolas;border:none;"
        )
        layout_rodape.addWidget(self._lbl_total_eventos_correlacionados)

        layout_externo.addWidget(frame_rodape)

        return widget

    def _criar_card_insight(self, insight: dict) -> QFrame:
        """Cria um card visual para um insight do MotorCorrelacao."""
        CORES_NIVEL = {
            "critico": "#E74C3C",
            "aviso":   "#E67E22",
            "info":    "#3498DB",
        }
        nivel     = insight.get("nivel_urgencia", "info")
        cor       = CORES_NIVEL.get(nivel, "#3498DB")
        titulo    = insight.get("titulo", "Insight")
        descricao = insight.get("descricao", "")
        html_conteudo = insight.get("html", "")

        frame = QFrame()
        frame.setStyleSheet(
            f"QFrame {{ background:#0d1a2a; border-left:3px solid {cor}; "
            f"border-radius:4px; }}"
            f"QLabel {{ border:none; }}"
        )
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(10, 8, 10, 8)
        layout.setSpacing(4)

        # Título do card
        lbl_titulo = QLabel(titulo)
        lbl_titulo.setStyleSheet(
            f"color:{cor};font-weight:bold;font-size:11px;"
        )
        layout.addWidget(lbl_titulo)

        # Descrição do método de correlação
        if descricao:
            lbl_desc = QLabel(descricao)
            lbl_desc.setWordWrap(True)
            lbl_desc.setStyleSheet(
                "color:#7f8c8d;font-size:9px;padding-bottom:4px;"
            )
            layout.addWidget(lbl_desc)

        # Conteúdo HTML via QTextEdit
        if html_conteudo:
            txt = QTextEdit()
            txt.setReadOnly(True)
            txt.setHtml(
                f"<html><body style='background:#0d1a2a;color:#ecf0f1;"
                f"font-family:Arial,sans-serif;font-size:10px;margin:0;padding:0;'>"
                f"{html_conteudo}</body></html>"
            )
            # Calcula altura proporcional ao conteúdo
            num_elementos = (
                html_conteudo.count("<tr>")
                + html_conteudo.count("<div")
                + 3
            )
            altura = min(max(60, num_elementos * 22), 280)
            txt.setFixedHeight(altura)
            txt.setStyleSheet(
                "QTextEdit { background:#0d1a2a; border:none; }"
            )
            layout.addWidget(txt)

        return frame

    # ──────────────────────────────────────────────
    # Métodos públicos de atualização
    # ──────────────────────────────────────────────

    def atualizar_insights_correlacionados(self, insights: list, estatisticas: dict,
                                            top_dominios: list, narrativas: list):
        """
        Atualiza a aba de Insights com dados do MotorCorrelacao.

        Parâmetros:
          insights     : lista de dicts gerados por MotorCorrelacao.gerar_insights()
          estatisticas : dict de MotorCorrelacao.obter_estatisticas_resumo()
          top_dominios : lista de MotorCorrelacao.obter_top_dominios()
          narrativas   : lista de strings de MotorCorrelacao.obter_narrativas()
        """
        # Limpa cards antigos
        while self._layout_insights.count() > 0:
            item = self._layout_insights.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        if not insights and not top_dominios:
            self._layout_insights.addWidget(self._lbl_insights_vazio)
            self._layout_insights.addStretch()
            return

        # Renderiza cada insight como card
        for insight in insights:
            card = self._criar_card_insight(insight)
            self._layout_insights.addWidget(card)

        # Narrativas comportamentais
        if narrativas:
            frame_narrativas = QFrame()
            frame_narrativas.setStyleSheet(
                "QFrame { background:#0d1a2a; border:1px solid #1e3a5f; border-radius:5px; }"
            )
            layout_n = QVBoxLayout(frame_narrativas)
            layout_n.setContentsMargins(10, 8, 10, 8)
            layout_n.setSpacing(4)

            titulo_n = QLabel("📖 Narrativas de comportamento")
            titulo_n.setStyleSheet(
                "color:#bdc3c7;font-weight:bold;font-size:10px;border:none;"
            )
            layout_n.addWidget(titulo_n)

            for narrativa in narrativas:
                lbl = QLabel(f"• {narrativa}")
                lbl.setWordWrap(True)
                lbl.setStyleSheet(
                    "color:#ecf0f1;font-size:10px;border:none;padding:2px 0;"
                )
                layout_n.addWidget(lbl)

            self._layout_insights.addWidget(frame_narrativas)

        self._layout_insights.addStretch()

        # Atualiza rodapé
        total_fluxos     = estatisticas.get("total_fluxos", 0)
        total_bytes      = estatisticas.get("total_bytes", 0)
        dominios_unicos  = estatisticas.get("dominios_unicos", 0)
        total_eventos    = estatisticas.get("total_eventos", 0)
        fluxos_sensiveis = estatisticas.get("fluxos_sensiveis", 0)

        kb = total_bytes / 1024
        vol = f"{kb/1024:.1f} MB" if kb > 1024 else f"{kb:.0f} KB"
        texto_resumo = f"{total_fluxos} fluxo(s) · {dominios_unicos} domínio(s) · {vol}"
        if fluxos_sensiveis:
            texto_resumo += f" · ⚠ {fluxos_sensiveis} com dados sensíveis"

        self._lbl_resumo_correlacao.setText(texto_resumo)
        self._lbl_total_eventos_correlacionados.setText(
            f"{total_eventos:,} eventos correlacionados"
        )

    def atualizar_insights(self, top_dns: list, historias: list):
        """
        Compatibilidade com o código legado — usado como fallback
        quando o MotorCorrelacao não estiver disponível.
        """
        if hasattr(self, "tabela_dns"):
            self.tabela_dns.setRowCount(len(top_dns))
            for i, dom in enumerate(top_dns):
                self.tabela_dns.setItem(i, 0, QTableWidgetItem(dom.get("dominio", "")))
                self.tabela_dns.setItem(i, 1, QTableWidgetItem(str(dom.get("acessos", 0))))
                kb = dom.get("bytes", 0) / 1024
                self.tabela_dns.setItem(i, 2, QTableWidgetItem(f"{kb:.1f}"))
        if hasattr(self, "lista_hist"):
            texto = "\n".join(f"• {h}" for h in historias) if historias else "Nenhuma história gerada ainda."
            self.lista_hist.setPlainText(texto)

    def adicionar_evento(self, dados: dict):
        """Recebe um evento do motor pedagógico e exibe na interface."""
        def _fix_mojibake(txt: str) -> str:
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
        for k in ("titulo", "nivel1", "nivel2", "nivel3", "nivel4",
                  "alerta_seguranca", "fluxo_visual"):
            if k in dados:
                dados[k] = _fix_mojibake(dados[k])

        self._todos_eventos.append(dados)
        self.painel_contadores.incrementar(dados.get("tipo", ""))

        if self._passa_filtro(dados):
            self._adicionar_cartao(dados)
            self._eventos_filtrados.append(dados)

        self._evento_atual = dados
        self._renderizar_explicacao()
        self._atualizar_rodape()

    def limpar(self):
        self._todos_eventos.clear()
        self._eventos_filtrados.clear()
        self._evento_atual = {}
        self._contagem_sessao.clear()
        self.painel_contadores.resetar()

        while self._layout_cartoes.count() > 1:
            item = self._layout_cartoes.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        # Limpa também os insights
        while self._layout_insights.count() > 0:
            item = self._layout_insights.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        self._layout_insights.addWidget(self._lbl_insights_vazio)
        self._layout_insights.addStretch()
        self._lbl_resumo_correlacao.setText("Nenhum dado correlacionado ainda.")
        self._lbl_total_eventos_correlacionados.setText("")

        self.lbl_rodape.setText("Nenhum evento registrado.")
        self._exibir_boas_vindas()

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
        if (self._filtro_protocolo and
                self._filtro_protocolo != "Todos" and
                dados.get("tipo", "").upper() != self._filtro_protocolo.upper()):
            return False
        if self._filtro_texto:
            campos = " ".join([
                dados.get("ip_envolvido", ""),
                dados.get("ip_destino", ""),
                dados.get("titulo", ""),
                dados.get("nivel1", ""),
                dados.get("tipo", ""),
            ]).lower()
            if self._filtro_texto not in campos:
                return False
        return True

    def _reaplicar_filtros(self):
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
        total    = len(self._todos_eventos)
        visiveis = len(self._eventos_filtrados)
        sessao   = self._evento_atual.get("sessao_id", "sessao_default") if self._evento_atual else None
        extra    = ""
        if sessao and sessao in self._contagem_sessao:
            resumo = ", ".join(
                f"{k}:{v}" for k, v in sorted(self._contagem_sessao[sessao].items())
            )
            extra = f" | Sessão {sessao}: {resumo}"
        if total == visiveis:
            self.lbl_rodape.setText(f"{total} evento(s) registrado(s).{extra}")
        else:
            self.lbl_rodape.setText(
                f"{visiveis} exibido(s) de {total} total (filtro ativo).{extra}"
            )

    # ──────────────────────────────────────────────
    # Cartões e renderização
    # ──────────────────────────────────────────────

    def _adicionar_cartao(self, dados: dict):
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
        """Troca o nível de explicação exibido."""
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
          <b>Simples</b> — linguagem do dia a dia, sem jargão<br>
          <b>Técnico</b> — protocolos, portas, vulnerabilidades<br>
          <b>Pacote Bruto</b> — conteúdo exato como trafegou na rede
          (exclusivo para HTTP), com destaques de campos e riscos</p>
          <p><b>Demonstração em sala de aula:</b><br>
          Execute o <code>servidor_teste_http.py</code>, acesse de outro
          dispositivo, envie o formulário de login e observe as credenciais
          aparecendo em texto puro no nível "Pacote Bruto".</p>
          <p style="color:#7f8c8d;font-size:10px;">
            Acesse a aba <b>Insights</b> para ver correlações DNS+TCP+TLS
            e o perfil de uso dos dispositivos na rede.
          </p>
        </div>
        """)