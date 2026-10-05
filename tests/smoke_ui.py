"""Runs app.py end-to-end with a stub Streamlit (no server/browser needed) to catch crashes.
   python -m tests.smoke_ui"""
import os, runpy, sys, tempfile

tmp = tempfile.mkdtemp()
os.environ["AUDIT_LOG"] = os.path.join(tmp, "audit.jsonl")
os.environ["PATIENT_FEEDBACK"] = os.path.join(tmp, "fb.jsonl")
CLICK = {"v": False}


class Fake:
    session_state = {}

    def __getattr__(self, name):
        def noop(*a, **k):
            return Fake()
        return {"columns": self.columns, "tabs": self.tabs, "selectbox": self.selectbox,
                "multiselect": self.multiselect, "checkbox": self.checkbox, "toggle": self.checkbox,
                "text_input": self.text_input, "button": self.button, "cache_data": self.cache_data,
                "sidebar": Fake()}.get(name, noop)

    def __enter__(self): return self
    def __exit__(self, *a): return False
    def columns(self, spec, **k): return [Fake() for _ in range(spec if isinstance(spec, int) else len(spec))]
    def tabs(self, labels): return [Fake() for _ in labels]
    def selectbox(self, label, options, format_func=None, **k):
        options = list(options)
        if format_func and options: format_func(options[0])
        return options[0] if options else None
    def multiselect(self, label, options, default=None, **k): return default or []
    def checkbox(self, label, value=False, **k): return value
    def text_input(self, label, value="", **k): return value
    def button(self, *a, **k): return CLICK["v"]
    def cache_data(self, f=None, **k): return f if f else (lambda g: g)


fake = Fake()
sys.modules["streamlit"] = fake
for clicked in (False, True):
    CLICK["v"] = clicked
    Fake.session_state = {}
    runpy.run_path("app.py")
    print("app.py ran OK (buttons clicked: %s)" % clicked)
