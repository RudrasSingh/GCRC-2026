import streamlit as st
import requests
import time
import plotly.graph_objects as go

API = "http://127.0.0.1:8000"

# ── Page config ──────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="GCRC Cryptanalysis Lab",
    page_icon="🔐",
    layout="wide",
)

# ── Global styles ─────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@400;700;900&display=swap');

/* ── Reset / base ── */
html, body, [data-testid="stAppViewContainer"] {
    background-color: #080b0f !important;
    color: #c8d8e8;
    font-family: 'Share Tech Mono', monospace;
}

[data-testid="stHeader"] { background: transparent !important; }
[data-testid="stSidebar"] { display: none; }
.block-container { padding: 2rem 3rem 4rem !important; max-width: 1400px; }

/* ── Scanline overlay ── */
body::before {
    content: "";
    position: fixed; inset: 0; z-index: 9999;
    pointer-events: none;
    background: repeating-linear-gradient(
        0deg,
        transparent,
        transparent 2px,
        rgba(0,255,170,0.015) 2px,
        rgba(0,255,170,0.015) 4px
    );
}

/* ── Title ── */
.lab-title {
    font-family: 'Orbitron', monospace;
    font-size: 2.2rem;
    font-weight: 900;
    letter-spacing: .15em;
    color: #00ffaa;
    text-shadow: 0 0 20px rgba(0,255,170,0.6), 0 0 60px rgba(0,255,170,0.2);
    margin-bottom: 0;
    line-height: 1;
}
.lab-subtitle {
    font-size: .75rem;
    letter-spacing: .4em;
    color: #3a6655;
    text-transform: uppercase;
    margin-top: .35rem;
    margin-bottom: 2.5rem;
}

/* ── Status badge ── */
.status-badge {
    display: inline-flex; align-items: center; gap: .5rem;
    padding: .3rem .8rem;
    border: 1px solid #1e4d3a;
    border-radius: 2px;
    font-size: .7rem;
    letter-spacing: .2em;
    text-transform: uppercase;
    color: #00ffaa;
    background: rgba(0,255,170,0.05);
}
.status-dot {
    width: 6px; height: 6px; border-radius: 50%;
    background: #00ffaa;
    box-shadow: 0 0 6px #00ffaa;
    animation: blink 1s infinite;
}
@keyframes blink { 50% { opacity: .2; } }

/* ── Metric cards ── */
.metric-grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 1px;
    border: 1px solid #1a2e28;
    background: #1a2e28;
    margin-bottom: 1.5rem;
}
.metric-card {
    background: #0c1117;
    padding: 1.2rem 1.5rem;
    position: relative;
    overflow: hidden;
}
.metric-card::before {
    content: "";
    position: absolute; top: 0; left: 0; right: 0;
    height: 2px;
    background: linear-gradient(90deg, transparent, #00ffaa, transparent);
    opacity: .4;
}
.metric-label {
    font-size: .65rem;
    letter-spacing: .25em;
    text-transform: uppercase;
    color: #3a6655;
    margin-bottom: .5rem;
}
.metric-value {
    font-family: 'Orbitron', monospace;
    font-size: 1.6rem;
    font-weight: 700;
    color: #00ffaa;
    text-shadow: 0 0 12px rgba(0,255,170,0.4);
    line-height: 1;
}
.metric-unit {
    font-size: .6rem;
    color: #3a6655;
    margin-top: .3rem;
    letter-spacing: .15em;
}

/* ── Chart container ── */
.chart-wrapper {
    border: 1px solid #1a2e28;
    background: #0c1117;
    padding: .25rem;
    position: relative;
}
.chart-label {
    font-size: .65rem;
    letter-spacing: .3em;
    text-transform: uppercase;
    color: #3a6655;
    padding: .6rem 1rem .2rem;
}

/* ── Start button ── */
div[data-testid="stButton"] > button {
    font-family: 'Orbitron', monospace !important;
    font-size: .75rem !important;
    font-weight: 700 !important;
    letter-spacing: .2em !important;
    text-transform: uppercase !important;
    color: #080b0f !important;
    background: #00ffaa !important;
    border: none !important;
    border-radius: 2px !important;
    padding: .65rem 2rem !important;
    box-shadow: 0 0 20px rgba(0,255,170,0.4) !important;
    transition: all .2s ease !important;
}
div[data-testid="stButton"] > button:hover {
    background: #00ccaa !important;
    box-shadow: 0 0 35px rgba(0,255,170,0.6) !important;
    transform: translateY(-1px) !important;
}

/* ── Success / error ── */
[data-testid="stAlert"] {
    font-family: 'Share Tech Mono', monospace;
    font-size: .8rem;
    letter-spacing: .1em;
    background: #0a1a14 !important;
    border-color: #00ffaa !important;
    color: #00ffaa !important;
    border-radius: 2px !important;
}

/* ── Divider ── */
hr { border-color: #1a2e28 !important; }

/* ── Plotly background fix ── */
.js-plotly-plot { border: none !important; }
</style>
""", unsafe_allow_html=True)


# ── Header ────────────────────────────────────────────────────────────────────
col_title, col_status = st.columns([3, 1])
with col_title:
    st.markdown('<div class="lab-title">GCRC CRYPTANALYSIS</div>', unsafe_allow_html=True)
    st.markdown('<div class="lab-subtitle">Statistical Cipher Analysis Terminal · v2.4.1</div>', unsafe_allow_html=True)
with col_status:
    st.markdown("<br>", unsafe_allow_html=True)
    start = st.button("▶  Initiate Analysis")

st.markdown('<hr>', unsafe_allow_html=True)

# ── Session state ─────────────────────────────────────────────────────────────
if "history" not in st.session_state:
    st.session_state.history = []

# ── Placeholders ─────────────────────────────────────────────────────────────
placeholder_status  = st.empty()
placeholder_metrics = st.empty()
placeholder_chart   = st.empty()
placeholder_log     = st.empty()

# ── Start trigger ─────────────────────────────────────────────────────────────
if start:
    st.session_state.history = []
    try:
        requests.post(API + "/start-analysis")
    except:
        pass

# ── Live loop ─────────────────────────────────────────────────────────────────
while True:
    try:
        r = requests.get(API + "/status").json()
    except:
        st.error("⚠  UPLINK FAILURE — API unreachable at " + API)
        break

    running = r.get("running", False)
    metrics = r.get("metrics")

    # Status badge
    if running:
        placeholder_status.markdown(
            '<div class="status-badge"><span class="status-dot"></span>ANALYSIS RUNNING</div>',
            unsafe_allow_html=True
        )
    else:
        placeholder_status.empty()

    if metrics:
        data = metrics
        st.session_state.history.append(data["avalanche"])

        # Metric cards
        placeholder_metrics.markdown(f"""
        <div class="metric-grid">
            <div class="metric-card">
                <div class="metric-label">Avalanche Effect</div>
                <div class="metric-value">{data['avalanche']:.4f}</div>
                <div class="metric-unit">bit-flip propagation ratio</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Shannon Entropy</div>
                <div class="metric-value">{data['entropy']:.4f}</div>
                <div class="metric-unit">bits per symbol</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Chi² Statistic</div>
                <div class="metric-value">{data['chi_square']:.4f}</div>
                <div class="metric-unit">distribution uniformity</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Serial Correlation</div>
                <div class="metric-value">{data['serial_corr']:.4f}</div>
                <div class="metric-unit">byte-pair dependency</div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        # Chart
        iters = list(range(len(st.session_state.history)))
        fig = go.Figure()

        # Ideal reference line at 0.5
        fig.add_hline(
            y=0.5,
            line_dash="dot",
            line_color="rgba(0,255,170,0.15)",
            annotation_text="IDEAL  0.5000",
            annotation_font_color="rgba(0,255,170,0.35)",
            annotation_font_size=10,
        )

        # Fill area
        fig.add_trace(go.Scatter(
            x=iters, y=st.session_state.history,
            mode="none",
            fill="tozeroy",
            fillcolor="rgba(0,255,170,0.04)",
            showlegend=False,
            hoverinfo="skip",
        ))

        # Main line
        fig.add_trace(go.Scatter(
            x=iters,
            y=st.session_state.history,
            mode="lines",
            name="Avalanche",
            line=dict(color="#00ffaa", width=2),
            hovertemplate="Iter %{x}<br>%{y:.5f}<extra></extra>",
        ))

        # Latest point
        if st.session_state.history:
            fig.add_trace(go.Scatter(
                x=[iters[-1]],
                y=[st.session_state.history[-1]],
                mode="markers",
                marker=dict(color="#00ffaa", size=8,
                            line=dict(color="#080b0f", width=2)),
                showlegend=False,
                hoverinfo="skip",
            ))

        fig.update_layout(
            height=320,
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(family="Share Tech Mono", color="#3a6655", size=10),
            margin=dict(l=50, r=20, t=20, b=40),
            xaxis=dict(
                title="ITERATION",
                title_font=dict(size=9, color="#3a6655"),
                tickfont=dict(size=9),
                gridcolor="rgba(26,46,40,0.6)",
                showline=True, linecolor="#1a2e28",
                zeroline=False,
            ),
            yaxis=dict(
                title="AVALANCHE COEFFICIENT",
                title_font=dict(size=9, color="#3a6655"),
                tickfont=dict(size=9),
                gridcolor="rgba(26,46,40,0.6)",
                showline=True, linecolor="#1a2e28",
                zeroline=False,
            ),
            showlegend=False,
        )

        with placeholder_chart.container():
            st.markdown('<div class="chart-label">▸ AVALANCHE CONVERGENCE MONITOR</div>', unsafe_allow_html=True)
            st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})

    if not running:
        if st.session_state.history:
            st.success("✓  ANALYSIS COMPLETE — " + str(len(st.session_state.history)) + " iterations processed")
        break

    time.sleep(1)