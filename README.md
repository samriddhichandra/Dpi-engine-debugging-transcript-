# DPI Engine — AI-Assisted Debugging Transcript

This repo documents a real debugging session on an existing C++ multi-threaded
[Deep Packet Inspection engine](https://github.com/samriddhichandra/Deep-Packet-Inspection-System), done together with Claude (Sonnet 4.6)
in an agentic coding session.

**What's here:**
- [`dpi-engine-debugging-transcript.md`](./dpi-engine-debugging-transcript.md) — the full writeup:
  how the bug was found by actually running the engine against test traffic, root-caused to a
  substring-matching flaw in the TLS SNI → application classifier, fixed at the systemic level
  (not just the symptom), and verified with an adversarial test suite.
- [`types_fixed.cpp`](./types_fixed.cpp) — the patched classifier source, with the new
  domain-suffix matcher.
- [`test_classify.cpp`](./test_classify.cpp) — a standalone test harness with 16 cases, including
  ones specifically designed to try to break the fix (domain-spoofing-style false positives).

**The short version:** the classifier was using raw substring matching to map TLS SNI values to
applications. Two short patterns (`x.com`, `t.co` for Twitter/X) were silently matching unrelated
domains — `netflix.com` and `microsoft.com` were both being misclassified as Twitter, which would
have caused real `--block-app` rules to make wrong blocking decisions. The fix replaces unsafe
substring checks with proper domain-suffix matching across the whole classifier, not just the two
patterns that happened to surface first.

This is included as a portfolio sample to show how I plan, direct, and verify AI-assisted coding —
including catching when a quick patch isn't enough and the underlying class of bug needs fixing.
