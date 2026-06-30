#include "types.h"
#include <iostream>
#include <vector>
#include <string>
using namespace DPI;

int main() {
    std::vector<std::pair<std::string, std::string>> cases = {
        // {sni, expected}
        {"www.netflix.com", "Netflix"},
        {"www.microsoft.com", "Microsoft"},
        {"twitter.com", "Twitter/X"},
        {"t.co", "Twitter/X"},                  // real twitter shortlink domain
        {"x.com", "Twitter/X"},                 // real x.com root domain
        {"abc.x.com", "Twitter/X"},             // subdomain of x.com
        {"outlook.office.com", "Microsoft"},
        {"msn.com", "Microsoft"},
        {"fakemsn.com", "HTTPS"},               // should NOT match msn.com pattern
        {"randomwa.me.evil.com", "HTTPS"},      // should NOT match wa.me as suffix
        {"web.whatsapp.com", "WhatsApp"},
        {"api.spotify.com", "Spotify"},
        {"scdn.co", "Spotify"},
        {"notscdn.co.attacker.com", "HTTPS"},   // should not falsely match
        {"jawbone-aws.io", "HTTPS"},            // 'aws' substring but not Amazon
        {"s3.amazonaws.com", "Amazon"},
    };

    int pass = 0, fail = 0;
    for (auto& [sni, expected] : cases) {
        std::string got = appTypeToString(sniToAppType(sni));
        bool ok = (got == expected);
        std::cout << (ok ? "PASS " : "FAIL ") << sni << " -> " << got
                  << " (expected " << expected << ")\n";
        ok ? pass++ : fail++;
    }
    std::cout << "\n" << pass << " passed, " << fail << " failed\n";
    return fail == 0 ? 0 : 1;
}
