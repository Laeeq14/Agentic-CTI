"""Patch script: inject latency display + FP gate into app.py."""
import re

with open("app.py", encoding="utf-8") as f:
    content = f.read()

# --- Inject Pipeline Time + FP gate after the closing </div> of the metadata card ---
# The metadata card ends with: st.markdown("</div>", unsafe_allow_html=True)
# followed by a blank line and "    # ── Landing state"

NEEDLE = '            st.markdown("</div>", unsafe_allow_html=True)\n\n    # \u2500\u2500 Landing state'
REPLACEMENT = '''\
            # Pipeline Time bar + FP threshold gate -------------------------
            try:
                from tests.eval.fp_evaluator import run_fp_check as _fpcheck, FP_RATE_THRESHOLD as _FPTHRESH
                _msgs: list[str] = []
                for _rt, _fm in [
                    (result.get("final_yaral_rule"), "yaral"),
                    (result.get("sigma_rule"),       "sigma"),
                    (result.get("kql_query"),         "kql"),
                ]:
                    if _rt:
                        _rv = _fpcheck(_rt, fmt=_fm)
                        if _rv.get("needs_review"):
                            _msgs.append(
                                f"{_fm.upper()}: {_rv['fp_rate']*100:.1f}% FP rate "
                                f"({_rv['fp_count']} of {_rv['total_benign_events']} benign events matched)"
                            )
                if _msgs:
                    _thresh_pct = int(_FPTHRESH * 100)
                    _detail = "  \\n".join(_msgs)
                    st.warning(
                        f"FP THRESHOLD EXCEEDED (>{_thresh_pct}%) — review IOC specificity before deploying:\\n"
                        f"  {_detail}",
                        icon="\u26a0\ufe0f",
                    )
            except ImportError:
                pass
            st.markdown(
                f"""<div style="margin-top:8px;padding:6px 12px;background:rgba(0,212,255,0.04);
                             border-radius:4px;font-family:'JetBrains Mono',monospace;
                             font-size:0.78rem;color:#4a8fa8;">
                    PIPELINE TIME: <span style="color:{'#00d4ff' if elapsed_seconds<30 else '#ffaa00'}">{elapsed_seconds:.1f}s</span>
                    &nbsp;&nbsp;|&nbsp;&nbsp;
                    FORMATS: YARA-L 2.0 &bull; Sigma &bull; KQL
                </div>""",
                unsafe_allow_html=True,
            )
            st.markdown("</div>", unsafe_allow_html=True)

    # \u2500\u2500 Landing state'''

if NEEDLE in content:
    content = content.replace(NEEDLE, REPLACEMENT, 1)
    with open("app.py", "w", encoding="utf-8") as f:
        f.write(content)
    print("PATCHED OK")
else:
    # Debug: show what's around that area
    idx = content.find('st.markdown("</div>"')
    while idx != -1:
        print(f"Found at {idx}: {repr(content[idx:idx+50])}")
        idx = content.find('st.markdown("</div>"', idx+1)
    print("NEEDLE NOT FOUND")
