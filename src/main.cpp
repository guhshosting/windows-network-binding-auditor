#include "model.hpp"
#include <iostream>
#include <cstdio>
#include <stdexcept>
int wmain(int argc, wchar_t **argv) {
  try {
    std::vector<std::string> args;
    for (int i = 1; i < argc; ++i)
      args.push_back(audit::utf8(argv[i]));
    const auto options = audit::parse(args);
    if (options.mode == "version") {
      std::cout << "windows-network-binding-auditor 1.0.0\n";
      return 0;
    }
    if (options.mode == "help") {
      std::cout << "windows-network-binding-auditor 1.0.0\n"
                   "Usage: windows-network-binding-auditor [--summary | "
                   "--adapters | --adapter <identifier>] [--json]\n"
                   "       windows-network-binding-auditor --help | --version\n"
                   "Identifier: GUID (braces optional), decimal interface "
                   "index, or exact case-sensitive friendly name.\n"
                   "Duplicate names are rejected. UTF-8 output. Read-only "
                   "local configuration; no connectivity tests.\n"
                   "JSON always contains full detail for selected adapters.\n"
                   "Exit: 0 complete, 1 partial/unavailable acquisition, 2 "
                   "invalid arguments/identifier, 3 fatal error.\n";
      return 0;
    }
    auto s = audit::acquire();
    if (!options.identifier.empty()) {
      const auto selected = audit::select(s, options.identifier);
      auto a = s.adapters[selected.front()];
      s.adapters = {std::move(a)};
    }
    bool complete = s.interfaces_complete && s.netcfg_complete;
    for (const auto &a : s.adapters)
      complete = complete && a.bindings_complete && a.errors.empty();
    std::cout << (options.json ? audit::json(s)
                               : audit::render(s, options.mode));
    if (!std::cout)
      return 3;
    return complete ? 0 : 1;
  } catch (const std::invalid_argument &e) {
    std::fprintf(stderr, "Error: %s\n", e.what());
    return 2;
  } catch (const std::exception &e) {
    std::fprintf(stderr, "Fatal: %s\n", e.what());
    return 3;
  }
}