"""
Network Intrusion Detection — Streamlit front-end for IBM watsonx.ai classifier.

Session-state key namespaces
  Internal  : token, token_expiry, last_preset, last_source, result
  Widget    : input_protocol_type, input_service, input_flag,
              input_src_bytes, input_dst_bytes, input_num_failed_logins
"""

import json
import time

import altair as alt
import pandas as pd
import requests
import streamlit as st

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

FEATURE_COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root",
    "num_file_creations", "num_shells", "num_access_files", "is_host_login",
    "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate",
    "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
    "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
]

# Verified empirically: each index confirmed by running all 5 presets and
# observing which bar position carried the highest probability for each known class.
CLASS_LABELS = ["DoS", "Probe", "R2L", "U2R", "normal"]

# Display order for the probability bar chart only — Normal first, title-cased.
# CLASS_LABELS must not be changed; this constant is used solely for chart rendering.
DISPLAY_ORDER = ["Normal", "DoS", "Probe", "R2L", "U2R"]

IAM_URL = "https://iam.cloud.ibm.com/identity/token"

# Hardcoded example rows — label strings for categoricals, raw numbers for the rest.
PRESETS: dict[str, dict] = {
    "Normal": {
        "duration": 0, "protocol_type": "udp", "service": "other", "flag": "SF",
        "src_bytes": 146, "dst_bytes": 0, "land": 0, "wrong_fragment": 0,
        "urgent": 0, "hot": 0, "num_failed_logins": 0, "logged_in": 0,
        "num_compromised": 0, "root_shell": 0, "su_attempted": 0, "num_root": 0,
        "num_file_creations": 0, "num_shells": 0, "num_access_files": 0,
        "is_host_login": 0, "is_guest_login": 0, "count": 13, "srv_count": 1,
        "serror_rate": 0.0, "srv_serror_rate": 0.0, "rerror_rate": 0.0,
        "srv_rerror_rate": 0.0, "same_srv_rate": 0.08, "diff_srv_rate": 0.15,
        "srv_diff_host_rate": 0.0, "dst_host_count": 255, "dst_host_srv_count": 1,
        "dst_host_same_srv_rate": 0.0, "dst_host_diff_srv_rate": 0.6,
        "dst_host_same_src_port_rate": 0.88, "dst_host_srv_diff_host_rate": 0.0,
        "dst_host_serror_rate": 0.0, "dst_host_srv_serror_rate": 0.0,
        "dst_host_rerror_rate": 0.0, "dst_host_srv_rerror_rate": 0.0,
    },
    "DoS": {
        "duration": 0, "protocol_type": "tcp", "service": "private", "flag": "S0",
        "src_bytes": 0, "dst_bytes": 0, "land": 0, "wrong_fragment": 0,
        "urgent": 0, "hot": 0, "num_failed_logins": 0, "logged_in": 0,
        "num_compromised": 0, "root_shell": 0, "su_attempted": 0, "num_root": 0,
        "num_file_creations": 0, "num_shells": 0, "num_access_files": 0,
        "is_host_login": 0, "is_guest_login": 0, "count": 123, "srv_count": 6,
        "serror_rate": 1.0, "srv_serror_rate": 1.0, "rerror_rate": 0.0,
        "srv_rerror_rate": 0.0, "same_srv_rate": 0.05, "diff_srv_rate": 0.07,
        "srv_diff_host_rate": 0.0, "dst_host_count": 255, "dst_host_srv_count": 26,
        "dst_host_same_srv_rate": 0.1, "dst_host_diff_srv_rate": 0.05,
        "dst_host_same_src_port_rate": 0.0, "dst_host_srv_diff_host_rate": 0.0,
        "dst_host_serror_rate": 1.0, "dst_host_srv_serror_rate": 1.0,
        "dst_host_rerror_rate": 0.0, "dst_host_srv_rerror_rate": 0.0,
    },
    "Probe": {
        "duration": 0, "protocol_type": "icmp", "service": "eco_i", "flag": "SF",
        "src_bytes": 18, "dst_bytes": 0, "land": 0, "wrong_fragment": 0,
        "urgent": 0, "hot": 0, "num_failed_logins": 0, "logged_in": 0,
        "num_compromised": 0, "root_shell": 0, "su_attempted": 0, "num_root": 0,
        "num_file_creations": 0, "num_shells": 0, "num_access_files": 0,
        "is_host_login": 0, "is_guest_login": 0, "count": 1, "srv_count": 1,
        "serror_rate": 0.0, "srv_serror_rate": 0.0, "rerror_rate": 0.0,
        "srv_rerror_rate": 0.0, "same_srv_rate": 1.0, "diff_srv_rate": 0.0,
        "srv_diff_host_rate": 0.0, "dst_host_count": 1, "dst_host_srv_count": 16,
        "dst_host_same_srv_rate": 1.0, "dst_host_diff_srv_rate": 0.0,
        "dst_host_same_src_port_rate": 1.0, "dst_host_srv_diff_host_rate": 1.0,
        "dst_host_serror_rate": 0.0, "dst_host_srv_serror_rate": 0.0,
        "dst_host_rerror_rate": 0.0, "dst_host_srv_rerror_rate": 0.0,
    },
    "R2L": {
        "duration": 0, "protocol_type": "tcp", "service": "ftp_data", "flag": "SF",
        "src_bytes": 334, "dst_bytes": 0, "land": 0, "wrong_fragment": 0,
        "urgent": 0, "hot": 0, "num_failed_logins": 0, "logged_in": 1,
        "num_compromised": 0, "root_shell": 0, "su_attempted": 0, "num_root": 0,
        "num_file_creations": 0, "num_shells": 0, "num_access_files": 0,
        "is_host_login": 0, "is_guest_login": 0, "count": 2, "srv_count": 2,
        "serror_rate": 0.0, "srv_serror_rate": 0.0, "rerror_rate": 0.0,
        "srv_rerror_rate": 0.0, "same_srv_rate": 1.0, "diff_srv_rate": 0.0,
        "srv_diff_host_rate": 0.0, "dst_host_count": 2, "dst_host_srv_count": 20,
        "dst_host_same_srv_rate": 1.0, "dst_host_diff_srv_rate": 0.0,
        "dst_host_same_src_port_rate": 1.0, "dst_host_srv_diff_host_rate": 0.2,
        "dst_host_serror_rate": 0.0, "dst_host_srv_serror_rate": 0.0,
        "dst_host_rerror_rate": 0.0, "dst_host_srv_rerror_rate": 0.0,
    },
    "U2R": {
        "duration": 98, "protocol_type": "tcp", "service": "telnet", "flag": "SF",
        "src_bytes": 621, "dst_bytes": 8356, "land": 0, "wrong_fragment": 0,
        "urgent": 1, "hot": 1, "num_failed_logins": 0, "logged_in": 1,
        "num_compromised": 5, "root_shell": 1, "su_attempted": 0, "num_root": 14,
        "num_file_creations": 1, "num_shells": 0, "num_access_files": 0,
        "is_host_login": 0, "is_guest_login": 0, "count": 1, "srv_count": 1,
        "serror_rate": 0.0, "srv_serror_rate": 0.0, "rerror_rate": 0.0,
        "srv_rerror_rate": 0.0, "same_srv_rate": 1.0, "diff_srv_rate": 0.0,
        "srv_diff_host_rate": 0.0, "dst_host_count": 255, "dst_host_srv_count": 4,
        "dst_host_same_srv_rate": 0.02, "dst_host_diff_srv_rate": 0.02,
        "dst_host_same_src_port_rate": 0.0, "dst_host_srv_diff_host_rate": 0.0,
        "dst_host_serror_rate": 0.0, "dst_host_srv_serror_rate": 0.0,
        "dst_host_rerror_rate": 0.0, "dst_host_srv_rerror_rate": 0.0,
    },
}

ZERO_ROW: dict = {col: 0 for col in FEATURE_COLUMNS}

# ---------------------------------------------------------------------------
# Startup — cached resource loader
# ---------------------------------------------------------------------------

@st.cache_resource
def load_label_encoders() -> dict:
    """Load label_encoders.json once per process lifetime."""
    with open("label_encoders.json", "r") as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# Session-state initialisation (runs once per browser session)
# ---------------------------------------------------------------------------

def _init_session_state(encoders: dict) -> tuple[list, list, list]:
    """Initialise session state and return the three sorted dropdown option lists."""
    # Internal state
    if "token" not in st.session_state:
        st.session_state.token = None
    if "token_expiry" not in st.session_state:
        st.session_state.token_expiry = 0.0
    if "last_preset" not in st.session_state:
        st.session_state.last_preset = None
    if "last_source" not in st.session_state:
        st.session_state.last_source = None
    if "result" not in st.session_state:
        st.session_state.result = None
    if "error_message" not in st.session_state:
        st.session_state.error_message = None
    if "notice_dismissed" not in st.session_state:
        st.session_state.notice_dismissed = False

    # Widget state (input_ prefix)
    proto_options = sorted(encoders["protocol_type"].keys())
    if "input_protocol_type" not in st.session_state:
        st.session_state.input_protocol_type = proto_options[0]
    service_options = sorted(encoders["service"].keys())
    if "input_service" not in st.session_state:
        st.session_state.input_service = service_options[0]
    flag_options = sorted(encoders["flag"].keys())
    if "input_flag" not in st.session_state:
        st.session_state.input_flag = flag_options[0]
    if "input_src_bytes" not in st.session_state:
        st.session_state.input_src_bytes = 0
    if "input_dst_bytes" not in st.session_state:
        st.session_state.input_dst_bytes = 0
    if "input_num_failed_logins" not in st.session_state:
        st.session_state.input_num_failed_logins = 0

    return proto_options, service_options, flag_options


# ---------------------------------------------------------------------------
# Sub-Task 3 — IAM Token Helper
# ---------------------------------------------------------------------------

def get_access_token(force: bool = False) -> str:
    """Return a valid IBM IAM bearer token, refreshing only when necessary."""
    now = time.time()
    if (
        not force
        and st.session_state.token is not None
        and now < st.session_state.token_expiry
    ):
        return st.session_state.token

    api_key = st.secrets["WATSONX_API_KEY"]
    try:
        resp = requests.post(
            IAM_URL,
            data={
                "grant_type": "urn:ibm:params:oauth:grant-type:apikey",
                "apikey": api_key,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=30,
        )
    except requests.exceptions.RequestException as exc:
        raise RuntimeError(f"IAM network error: {exc}") from exc

    if resp.status_code != 200:
        raise RuntimeError(f"IAM token error {resp.status_code}: {resp.text}")

    try:
        body = resp.json()
    except ValueError as exc:
        raise RuntimeError(f"IAM returned non-JSON response: {resp.text}") from exc

    st.session_state.token = body["access_token"]
    # Subtract 60 s buffer so we refresh before the token actually expires.
    st.session_state.token_expiry = now + body.get("expires_in", 3600) - 60
    return st.session_state.token


# ---------------------------------------------------------------------------
# Sub-Task 4 — Scoring API Helper
# ---------------------------------------------------------------------------

def encode_features(row: dict, encoders: dict) -> list:
    """Convert the feature dict to an ordered flat list, encoding categoricals."""
    categorical = {"protocol_type", "service", "flag"}
    values = []
    for col in FEATURE_COLUMNS:
        if col in categorical:
            try:
                values.append(encoders[col][row[col]])
            except KeyError:
                raise RuntimeError(
                    f"Unknown value '{row[col]}' for feature '{col}' "
                    f"— not present in label_encoders.json"
                )
        else:
            values.append(row[col])
    return values


def call_scoring_api(feature_row: dict, encoders: dict) -> dict:
    """
    Call the watsonx.ai scoring endpoint and return
    {"label": str, "probabilities": list[float] | None}.
    """
    values = encode_features(feature_row, encoders)
    payload = {
        "input_data": [{"fields": FEATURE_COLUMNS, "values": [values]}]
    }

    def _post(token: str) -> requests.Response:
        try:
            return requests.post(
                st.secrets["WATSONX_SCORING_URL"],
                json=payload,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                },
                timeout=30,
            )
        except requests.exceptions.RequestException as exc:
            raise RuntimeError(f"Scoring network error: {exc}") from exc

    token = get_access_token()
    resp = _post(token)

    if resp.status_code == 401:
        # Token may have just expired — force a refresh and retry once.
        token = get_access_token(force=True)
        resp = _post(token)

    if resp.status_code != 200:
        raise RuntimeError(
            f"Scoring API error {resp.status_code}: {resp.text}"
        )

    # --- Defensive response parsing ---
    try:
        body = resp.json()
    except ValueError as exc:
        raise RuntimeError(
            f"Scoring API returned non-JSON response: {resp.text}"
        ) from exc

    try:
        prediction = body["predictions"][0]["values"][0]
    except (KeyError, IndexError, TypeError) as exc:
        raise RuntimeError(
            f"Unexpected response shape — could not parse predictions.\n"
            f"Raw response: {body}"
        ) from exc

    # prediction may be [label] or [label, [p0, p1, ...]]
    label = str(prediction[0])
    probabilities = None
    if len(prediction) >= 2 and isinstance(prediction[1], list):
        probabilities = [float(p) for p in prediction[1]]

    return {"label": label, "probabilities": probabilities}


# ---------------------------------------------------------------------------
# Sub-Task 7 — Result display helper
# ---------------------------------------------------------------------------

def render_result(result: dict | None, source: str | None) -> None:
    """Render the color-coded result box and optional probability bar chart."""
    if result is None:
        st.info("Submit a traffic sample to see the prediction.")
        return

    label = result["label"]
    is_normal = label.strip().lower() == "normal"

    if is_normal:
        box_color = "#0B2D16"
        border_color = "#28a745"
        icon = "🟢"
        text = "Normal traffic"
    else:
        box_color = "#281114"
        border_color = "#dc3545"
        icon = "⚠️"
        text = f"Attack detected: <strong>{label}</strong>"

    st.markdown(
        f"""
        <div style="
            background-color:{box_color};
            border-radius:8px;
            padding:16px 20px;
            font-size:1.3rem;
            font-weight:600;
        ">
            {icon}&nbsp;{text}
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Source label
    if source:
        if source.startswith("preset:"):
            class_name = source.split(":", 1)[1]
            st.caption(f"Source: Quick-test ({class_name})")
        else:
            st.caption("Source: Manual input")

    # Probability bar chart (only when probabilities were returned).
    # Uses Altair with an explicit sort= so bars always render in DISPLAY_ORDER
    # regardless of Altair/Vega's default alphabetical axis sorting.
    probs = result.get("probabilities")
    if probs is not None and len(probs) == len(CLASS_LABELS):
        st.markdown("**Prediction confidence**")
        prob_map = {lbl.lower(): p for lbl, p in zip(CLASS_LABELS, probs)}
        chart_df = pd.DataFrame({
            "Class": DISPLAY_ORDER,
            "Probability": [prob_map[lbl.lower()] for lbl in DISPLAY_ORDER],
        })
        chart = (
            alt.Chart(chart_df)
            .mark_bar()
            .encode(
                x=alt.X("Class:N", sort=DISPLAY_ORDER, axis=alt.Axis(labelAngle=0)),
                y=alt.Y("Probability:Q", scale=alt.Scale(domain=[0, 1])),
                color=alt.condition(
                    # Build a display-cased lookup so mixed-case labels like
                    # "DoS", "R2L", "U2R" aren't mangled by .capitalize().
                    alt.datum.Class == {lbl.lower(): lbl for lbl in DISPLAY_ORDER}[label.lower()],
                    alt.value("#6c8ebf"),
                    alt.value("#6c8ebf"),
                ),
                tooltip=["Class:N", alt.Tooltip("Probability:Q", format=".4f")],
            )
            .properties(height=265)
        )
        st.altair_chart(chart, use_container_width=True)
    elif probs is not None:
        # Probabilities returned but count doesn't match CLASS_LABELS —
        # show raw values with generic indices so nothing is silently dropped.
        st.markdown("**Prediction confidence** *(class order not yet verified)*")
        n = len(probs)
        fallback_labels = [f"class_{i}" for i in range(n)]
        chart_df = pd.DataFrame({"Class": fallback_labels, "Probability": probs})
        chart = (
            alt.Chart(chart_df)
            .mark_bar()
            .encode(
                x=alt.X("Class:N", sort=fallback_labels, axis=alt.Axis(labelAngle=0)),
                y=alt.Y("Probability:Q", scale=alt.Scale(domain=[0, 1])),
                tooltip=["Class:N", alt.Tooltip("Probability:Q", format=".4f")],
            )
            .properties(height=265)
        )
        st.altair_chart(chart, use_container_width=True)


# ---------------------------------------------------------------------------
# Page config
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title="Network Intrusion Detector",
    page_icon="🛡️",
    layout="wide",
)

# ---------------------------------------------------------------------------
# Sidebar visual overrides — purely cosmetic, layered on top of config.toml.
# ---------------------------------------------------------------------------
st.markdown(
    """
    <style>
    /* 1. Remove padding from all possible outer sidebar containers */
    [data-testid="stSidebar"] > div {
        padding-top: 0rem !important;
    }
    [data-testid="stSidebarUserContent"] {
        padding-top: 0rem !important;
    }
    
    /* 2. FORCE the vertical layout block to start at the absolute top */
    [data-testid="stSidebar"] [data-testid="stVerticalBlock"] {
        padding-top: 2rem !important;
        margin-top: -3.5rem !important;
        gap: 0.2rem !important;
    }


    /* 3. Force Sidebar Width */
    [data-testid="stSidebar"][aria-expanded="true"] {
        min-width: 18rem !important;
        max-width: 18rem !important;
    }

    /* 4. Compact spacing for widgets */
    [data-testid="stSidebar"] .stSelectbox, 
    [data-testid="stSidebar"] .stNumberInput {
        margin-bottom: 0.2rem !important;
    }

    /* 5. Style the manual Check Traffic button prominently */
    [data-testid="stSidebar"] button[kind="primary"] {
        width: 100% !important;
        padding: 0.75rem 1rem !important;
        font-size: 1.1rem !important;
        font-weight: bold !important;
        background-color: #FF4B4B !important;
        color: white !important;
        border-radius: 8px !important;
        border: none !important;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# ---------------------------------------------------------------------------
# Load resources & initialise state
# ---------------------------------------------------------------------------

try:
    encoders = load_label_encoders()
except FileNotFoundError:
    st.error(
        "**label_encoders.json not found.** "
        "Place it in the same directory as app.py and restart."
    )
    st.stop()

for _secret in ("WATSONX_API_KEY", "WATSONX_SCORING_URL"):
    if _secret not in st.secrets:
        st.error(
            f"**Missing secret `{_secret}`** — add it to `.streamlit/secrets.toml` "
            f"and restart the app."
        )
        st.stop()

proto_options, service_options, flag_options = _init_session_state(encoders)


# ---------------------------------------------------------------------------
# Capacity notice modal — shown once per session on first load.
# ---------------------------------------------------------------------------

@st.dialog("⚠️ Notice: Live Predictions Temporarily Paused")
def _capacity_notice() -> None:
    st.markdown(
        "This project's IBM watsonx.ai model deployment has reached its monthly "
        "**Capacity Unit Hours (CUH)** limit. "
        "The quota resets automatically at the start of next month. "
        "You can still explore the full dashboard."
    )
    if st.button("Got it, continue to dashboard", type="primary", use_container_width=True):
        st.session_state.notice_dismissed = True
        st.rerun()


if not st.session_state.notice_dismissed:
    _capacity_notice()


# ---------------------------------------------------------------------------
# Preset callback — on_click callbacks run before the rerender, so writing to
# input_ keys here is always safe (no widget has been instantiated yet).
# ---------------------------------------------------------------------------

def apply_preset(class_name: str) -> None:
    """on_click callback for the five quick-test buttons."""
    preset = PRESETS[class_name]
    st.session_state.last_preset = dict(preset)
    st.session_state.input_protocol_type = preset["protocol_type"]
    st.session_state.input_service = preset["service"]
    st.session_state.input_flag = preset["flag"]
    st.session_state.input_src_bytes = int(preset["src_bytes"])
    st.session_state.input_dst_bytes = int(preset["dst_bytes"])
    st.session_state.input_num_failed_logins = int(preset["num_failed_logins"])
    st.session_state.last_source = f"preset:{class_name}"
    st.session_state.error_message = None
    with st.spinner("Scoring traffic..."):
        try:
            st.session_state.result = call_scoring_api(preset, encoders)
        except RuntimeError as exc:
            st.session_state.error_message = str(exc)

# ---------------------------------------------------------------------------
# Sub-Task 5 — Sidebar
# ---------------------------------------------------------------------------



with st.sidebar:
    st.title("🛡️ Traffic Inspector")
    st.markdown("Adjust the inputs below, then click **Check Traffic**.")
    st.divider()

    st.selectbox(
        "Protocol type",
        options=proto_options,
        key="input_protocol_type",
    )
    st.selectbox(
        "Service",
        options=service_options,
        key="input_service",
    )
    st.selectbox(
        "Flag",
        options=flag_options,
        key="input_flag",
    )
    st.number_input(
        "Data sent by client (bytes)",
        min_value=0,
        step=1,
        key="input_src_bytes",
        help="Source-to-destination byte count (no upper limit).",
    )
    st.number_input(
        "Data received back (bytes)",
        min_value=0,
        step=1,
        key="input_dst_bytes",
        help="Destination-to-source byte count (no upper limit).",
    )
    st.number_input(
        "Failed login attempts",
        min_value=0,
        max_value=10,
        step=1,
        key="input_num_failed_logins",
    )
    st.divider()

    check_clicked = st.button("Check Traffic", use_container_width=True, type="primary")

if check_clicked:
    base_row = dict(st.session_state.last_preset) if st.session_state.last_preset else dict(ZERO_ROW)
    base_row.update({
        "protocol_type": st.session_state.input_protocol_type,
        "service": st.session_state.input_service,
        "flag": st.session_state.input_flag,
        "src_bytes": st.session_state.input_src_bytes,
        "dst_bytes": st.session_state.input_dst_bytes,
        "num_failed_logins": st.session_state.input_num_failed_logins,
    })
    st.session_state.last_source = "manual"
    st.session_state.error_message = None
    with st.spinner("Scoring traffic..."):
        try:
            st.session_state.result = call_scoring_api(base_row, encoders)
        except RuntimeError as exc:
            st.session_state.error_message = str(exc)

# ---------------------------------------------------------------------------
# Main area — header
# ---------------------------------------------------------------------------

# Reduce default Streamlit top padding so the content starts higher.
st.markdown(
    "<style>.block-container{padding-top:1.25rem;}</style>",
    unsafe_allow_html=True,
)

st.title("Network Intrusion Detection")
st.markdown(
    "Uses an IBM watsonx.ai model trained on NSL-KDD data to classify "
    "network traffic into one of five categories: **Normal**, **DoS**, "
    "**Probe**, **R2L**, or **U2R**."
)

# ---------------------------------------------------------------------------
# Quick-test preset buttons
# ---------------------------------------------------------------------------

st.subheader("Quick tests")
st.caption("Click a button to load a real example row and run the model instantly.")

cols = st.columns(5)
for col, name in zip(cols, ["Normal", "DoS", "Probe", "R2L", "U2R"]):
    col.button(
        f"Test {name}",
        on_click=apply_preset,
        args=(name,),
        use_container_width=True,
    )

# ---------------------------------------------------------------------------
# Error display (from callbacks and Check Traffic)
# ---------------------------------------------------------------------------

if st.session_state.error_message:
    st.error(f"**Prediction failed:** {st.session_state.error_message}")
    st.session_state.error_message = None

# ---------------------------------------------------------------------------
# Result display
# ---------------------------------------------------------------------------

render_result(st.session_state.result, st.session_state.last_source)
