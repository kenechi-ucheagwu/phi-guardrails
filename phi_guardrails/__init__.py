"""Keep patient identifiers out of git history.

phi_guardrails builds a keyed-hash roster from patient exports and uses it in
git hooks and in a full-history scan. Findings name a path, a line and a
category, never the matched text.
"""

__version__ = "0.1.0"
