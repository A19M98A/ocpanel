#!/usr/bin/env bash
# Check your edits before restarting the panel.
# Reports the file and line number of any syntax or stylesheet error.
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export PYTHONDONTWRITEBYTECODE=1
"$DIR/venv/bin/python" - "$DIR/ocpanel" <<'PY'
import ast, pathlib, sys
bad = 0
for f in sorted(pathlib.Path(sys.argv[1]).glob("*.py")):
    try:
        ast.parse(f.read_text(), str(f))
    except SyntaxError as e:
        print(f"  SYNTAX ERROR  {f.name}:{e.lineno}  {e.msg}")
        bad += 1
try:
    from textual.css.stylesheet import Stylesheet
    from textual.theme import BUILTIN_THEMES
    # The stylesheet uses theme variables ($surface, $accent ...), which only
    # exist once a theme is loaded - supply them so parsing resolves.
    variables = BUILTIN_THEMES["textual-dark"].to_color_system().generate()
    css = pathlib.Path(sys.argv[1]) / "app.tcss"
    s = Stylesheet(variables=variables)
    s.add_source(css.read_text(), read_from=(str(css), str(css)))
    s.parse()
except Exception as e:
    import re
    shown = False
    for rule in getattr(getattr(e, "errors", None), "rules", []):
        for token, message in getattr(rule, "errors", []):
            line = getattr(token, "line_number", None)
            where = f"app.tcss:{line + 1}" if isinstance(line, int) else "app.tcss"
            sel = ", ".join(getattr(rule, "selector_names", []) or []) or "?"
            clean = re.sub(r"\[/?[a-z]*\]", "", str(message))
            print(f"  STYLESHEET ERROR  {where}  in rule '{sel}'  ->  {clean}")
            shown = True
    if not shown:
        print(f"  STYLESHEET ERROR  {type(e).__name__}: {str(e).splitlines()[0][:120]}")
    bad += 1
print("  all good - safe to restart the panel" if not bad else f"  {bad} problem(s) - fix before restarting")
sys.exit(1 if bad else 0)
PY
