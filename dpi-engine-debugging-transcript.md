# Debugging Session: SNI Application Misclassification in a Multi-threaded DPI Engine

**Project:** [Deep-Packet-Inspection-System](https://github.com) — a C++17 multi-threaded Deep Packet
Inspection engine (custom PCAP parser, TLS SNI extraction, connection tracking, load-balanced
worker threads, rule-based blocking).

**Tool used:** Claude (Sonnet 4.6), working directly against the project's source in an agentic
coding session — reading files, compiling, running the binary against test traffic, editing code,
and re-verifying.

**Goal of this session:** find a real, non-trivial bug in the existing codebase and fix it properly,
to demonstrate how I plan, direct, and verify AI-assisted debugging work — including the parts that
needed pushing back on or digging deeper into.

---

## 1. Orientation

The repo's `CMakeLists.txt` only builds a minimal `packet_analyzer` (raw PCAP printer). The actual
"DPI Engine" — multi-threaded, with SNI extraction and app/domain blocking — lives in
`src/dpi_mt.cpp` and friends but isn't wired into the CMake build at all. There are also four
different `main*.cpp` variants sitting in `src/` unused, a sign of earlier iteration that was never
cleaned up.

Rather than guessing, I had Claude compile the full DPI engine manually against `g++` directly
(bypassing the stale CMake config) to see whether it even still worked:

```bash
g++ -std=c++17 -pthread -Iinclude -o dpi_engine \
  src/dpi_mt.cpp src/pcap_reader.cpp src/packet_parser.cpp src/connection_tracker.cpp \
  src/sni_extractor.cpp src/rule_manager.cpp src/fast_path.cpp src/load_balancer.cpp src/types.cpp
```

It compiled and linked cleanly. So the build-system gap wasn't the most pressing issue — instead of
chasing that, I asked Claude to actually *run* the engine against generated test traffic
(`generate_test_pcap.py`, which ships 16 TLS connections with realistic SNIs for major apps) to see
whether the headline feature — classifying traffic by application from the TLS SNI — worked
correctly.

## 2. The bug, caught from real output

Running the engine with `--block-ip 192.168.1.50` against the test PCAP printed an application
breakdown and a per-domain classification table. Two entries jumped out immediately:

```
- www.netflix.com   -> Twitter/X      ❌ should be Netflix
- www.microsoft.com -> Twitter/X      ❌ should be Microsoft
```

This wasn't a crash or a build failure — it was a silent correctness bug in a feature that's
*supposed to drive firewall-style blocking decisions* (`--block-app Twitter` vs `--block-app
Microsoft`). That makes it worse than a crash: it fails quietly and produces wrong security
decisions.

## 3. Root-causing it

I had Claude trace the classification path into `src/types.cpp`, `sniToAppType()`. The Twitter/X
block looked like this:

```cpp
// Twitter/X
if (lower_sni.find("twitter") != std::string::npos ||
    lower_sni.find("twimg") != std::string::npos ||
    lower_sni.find("x.com") != std::string::npos ||
    lower_sni.find("t.co") != std::string::npos) {
    return AppType::TWITTER;
}
```

`std::string::find` does a raw substring search — it has no concept of domain-label boundaries. Two
of these patterns are short enough to be substrings of unrelated domains:

- `"x.com"` is a literal substring of `"netflix.com"` (`netfli` + **`x.com`**).
- `"t.co"` is a substring of *any* domain ending in `t.com` — `"microsoft.com"` ends in `...t.com`,
  and `"t.com"` trivially contains `"t.co"`. This single pattern silently misclassifies every
  `...t.com` domain (Microsoft, and hypothetically many others) as Twitter.

Because this block runs before the Netflix and Microsoft checks in the if-chain, both got shadowed.

## 4. Decision point

I asked the engineer driving the session (me, in the conversation with Claude) whether to:

1. Patch just the two broken patterns (`x.com`, `t.co`), or
2. Fix the underlying class of bug — since the same `find()`-based substring matching is used for
   *every* app in the function, and several other patterns (`fb.com`, `meta.com`, `wa.me`,
   `msn.com`, `live.com`, `t.me`, `scdn.co`, a bare `"aws"`) are equally short and equally exposed.

I told Claude to use its judgment and pick whichever showed stronger engineering instinct. It chose
option 2 — fix the systemic issue, not just the two symptoms that happened to surface in this test
run — and explained why before touching code.

## 5. The fix

Claude added a proper domain-suffix matcher:

```cpp
// Returns true only if `pattern` matches `domain` as a real domain label,
// i.e. domain == pattern, or domain ends with "." + pattern.
bool isDomainSuffixMatch(const std::string& domain, const std::string& pattern) {
    if (pattern.size() > domain.size()) return false;
    if (domain == pattern) return true;
    size_t pos = domain.size() - pattern.size();
    return domain.compare(pos, pattern.size(), pattern) == 0 && domain[pos - 1] == '.';
}
```

...and replaced every short/ambiguous `find()` pattern across the function with it — Twitter
(`x.com`, `t.co`), Facebook (`fb.com`, `meta.com`), WhatsApp (`wa.me`), Microsoft (`msn.com`,
`live.com`), Telegram (`t.me`), Spotify (`scdn.co`), and Amazon's bare `"aws"` (tightened to
`aws.com` / `.aws.` patterns). Longer, lower-collision-risk patterns (`"facebook"`, `"microsoft"`,
`"netflix"`, etc.) were left as substring matches since they're specific enough not to need it.

## 6. Verification

Rebuilt and re-ran the original failing case:

```
- www.netflix.com   -> Netflix      ✅
- www.microsoft.com -> Microsoft    ✅
- twitter.com       -> Twitter/X    ✅ (still correct — didn't break the real case)
```

That alone wasn't enough — a fix that only satisfies the two cases you already saw fail is weak
evidence. I had Claude write a standalone adversarial test (`test_classify.cpp`) covering 16 cases,
including ones designed specifically to try to break the *new* logic:

```
PASS www.netflix.com -> Netflix
PASS www.microsoft.com -> Microsoft
PASS twitter.com -> Twitter/X
PASS t.co -> Twitter/X                       (real twitter short-link domain, must still match)
PASS x.com -> Twitter/X                      (real x.com root domain)
PASS abc.x.com -> Twitter/X                  (subdomain should still match)
PASS msn.com -> Microsoft
PASS fakemsn.com -> HTTPS                    (must NOT false-positive)
PASS randomwa.me.evil.com -> HTTPS           (evasion attempt: pattern embedded but not a real suffix)
PASS notscdn.co.attacker.com -> HTTPS        (same idea for Spotify's pattern)
PASS jawbone-aws.io -> HTTPS                 (bare "aws" substring, must NOT match Amazon)
PASS s3.amazonaws.com -> Amazon

16 passed, 0 failed
```

The two "evasion attempt" cases mattered most: a naive suffix check could still be wrong in subtle
ways (e.g. matching `pattern` anywhere instead of requiring it as a true trailing label), so I made
sure the test suite specifically tried to construct domains that *contain* the pattern without
*ending* in it as a real label — to make sure the fix wasn't just narrowly tuned to pass the cases
I'd already seen.

Finally, ran the full engine end-to-end again with `--block-app Twitter` to confirm the
blocking/forwarding decision itself was now correct, not just the printed label.

## 7. What I'd flag for follow-up (not fixed in this session)

- The CMake build still doesn't include the DPI engine sources — worth fixing so `cmake --build`
  produces the real binary instead of only the basic packet printer.
- Four redundant `main*.cpp` files should be consolidated or removed; left as-is here since it was
  out of scope for this bug fix and I didn't want to scope-creep a correctness fix into a refactor.
- The same `find()`-based pattern exists for CDN-style patterns (`gstatic`, `fbcdn`, `nflxvideo`,
  etc.) — these are long/specific enough that they're low risk, but worth a second pass if this
  classifier is ever extended with more apps.

---

### Why I'm including this one

This wasn't a synthetic exercise — it's a real bug, found by actually running the project against
its own test data rather than just reading the code, root-caused to a specific line, fixed at the
systemic level instead of the two symptoms that happened to be visible, and verified with a test
suite designed to actively try to break the fix rather than just confirm it. That loop — run it,
don't trust the first green output, write adversarial tests, check for blast radius — is how I try
to work with AI coding tools generally.
