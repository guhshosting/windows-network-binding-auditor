#include "model.hpp"
#include <algorithm>
#include <iostream>
#include <cstdio>
#include <stdexcept>
using namespace audit;
static unsigned checks = 0;
static void check(bool v, const char *message) {
  ++checks;
  if (!v)
    throw std::runtime_error(message);
}
template <class F> static void invalid(F f) {
  bool threw = false;
  try {
    f();
  } catch (const std::invalid_argument &) {
    threw = true;
  }
  check(threw, "Expected invalid argument");
}
static Adapter fixture(std::string guid, std::string name,
                       std::string op = "up") {
  Adapter a;
  a.guid = guid.size() == 1 ? "00000000-0000-0000-0000-00000000000" + guid
                            : std::move(guid);
  a.name = std::move(name);
  a.operational = std::move(op);
  a.kind = "hardware";
  a.bindings_complete = true;
  a.paths = {{State::enabled, {{"ms_tcpip", "IPv4"}}},
             {State::enabled, {{"ms_tcpip6", "IPv6"}}}};
  return a;
}
int main(int argc, char **argv) {
  try {
    auto ethernet = fixture("b", "Ethernet");
    auto wifi = fixture("a", "Wi-Fi", "down");
    wifi.index = 12;
    check(component_state(ethernet, "ms_tcpip") == State::enabled,
          "Ethernet IPv4");
    ethernet.paths[1].state = State::disabled;
    check(component_state(ethernet, "ms_tcpip6") == State::disabled,
          "IPv4-only style");
    wifi.paths[0].state = State::disabled;
    check(component_state(wifi, "ms_tcpip") == State::disabled,
          "IPv6-only style");
    check(!findings(wifi).empty(), "Disconnected finding");
    auto virt = fixture("c", "vEthernet");
    virt.kind = "non_hardware";
    virt.paths.push_back({State::enabled, {{"vms_pp", "Hyper-V"}}});
    check(findings(virt).back().find("Hyper-V") != std::string::npos,
          "Virtual evidence");
    check(component_state(virt, "ms_server") == State::absent, "Absent");
    virt.paths.push_back({State::disabled, {{"ms_tcpip", "IPv4"}}});
    check(component_state(virt, "ms_tcpip") == State::mixed, "Mixed");
    virt.paths.push_back({State::unknown, {{"ms_tcpip6", "IPv6"}}});
    check(component_state(virt, "ms_tcpip6") == State::unknown, "Unknown");
    virt.bindings_complete = false;
    check(component_state(virt, "ms_server") == State::unavailable,
          "Partial cannot imply absent");
    Snapshot s;
    s.adapters = {ethernet, wifi, virt, fixture("d", "Ethernet")};
    invalid([&] { select(s, "Ethernet"); });
    invalid([&] { select(s, "missing"); });
    check(select(s, "12").front() == 1, "Index");
    const std::string guid = "01234567-89ab-cdef-0123-456789abcdef";
    s.adapters.push_back(fixture("{" + guid + "}", "網路 адаптер 😀"));
    check(select(s, "網路 адаптер 😀").front() == 4, "Unicode selector");
    check(select(s, guid).front() == 4, "GUID selector");
    check(quote(std::string("\x01\n\"\\\t")) == "\"\\u0001\\n\\\"\\\\\\t\"",
          "JSON escapes");
    normalize(s);
    const auto stable = json(s);
    std::reverse(s.adapters.begin(), s.adapters.end());
    for (auto &a : s.adapters)
      std::reverse(a.paths.begin(), a.paths.end());
    normalize(s);
    check(json(s) == stable, "Deterministic JSON");
    check(stable.find("網路 адаптер 😀") != std::string::npos, "Unicode JSON");
    check(parse({"--summary", "--json"}).json, "Combined JSON");
    check(parse({"--adapter", "Ethernet"}).identifier == "Ethernet",
          "Adapter parse");
    invalid([] { parse({"--adapter"}); });
    invalid([] { parse({"--bogus"}); });
    invalid([] { parse({"--summary", "--adapters"}); });
    invalid([] { parse({"--json", "--json"}); });
    invalid([] { parse({"--help", "--json"}); });
    invalid([] { parse({"--adapter", ""}); });
    check(select(s, "{01234567-89AB-CDEF-0123-456789ABCDEF}").size() == 1,
          "Uppercase GUID");
    invalid([&] { select(s, "ethernet"); });
    invalid([] { parse({"--adapter", "--json"}); });
    invalid([] { parse({"--version", "--summary"}); });
    check(parse({}).mode == "full", "Default mode");
    check(parse({"--adapters"}).mode == "adapters", "Adapters mode");
    check(parse({"--version"}).mode == "version", "Version mode");
    check(parse({"--help"}).mode == "help", "Help mode");
    check(parse({"--json", "--summary"}).mode == "summary",
          "Order-independent option");
    auto known_empty = fixture("e", "No paths");
    known_empty.paths.clear();
    check(component_state(known_empty, "ms_tcpip") == State::absent,
          "Complete empty paths");
    known_empty.bindings_complete = false;
    check(component_state(known_empty, "ms_tcpip") == State::unavailable,
          "Unavailable empty paths");
    auto uncertain = fixture("f", "Unknown path");
    uncertain.paths[0].state = State::unknown;
    check(component_state(uncertain, "ms_tcpip") == State::unknown,
          "Unknown containing path");
    uncertain.paths[1].state = State::enabled;
    check(component_state(uncertain, "ms_tcpip6") == State::enabled,
          "Unrelated unknown path");
    auto disabled_client = fixture("1", "Disabled client");
    disabled_client.paths.push_back(
        {State::disabled,
         {{"ms_msclient", "Client"}, {"ms_server", "Server"}}});
    check(component_state(disabled_client, "ms_msclient") == State::disabled,
          "Disabled client");
    check(component_state(disabled_client, "ms_server") == State::disabled,
          "Disabled server");
    disabled_client.paths.push_back(
        {State::enabled, {{"custom_filter", "Custom filter"}}});
    disabled_client.paths.push_back(
        {State::enabled, {{"ms_bridge", "Bridge"}}});
    check(component_state(disabled_client, "custom_filter") == State::enabled,
          "Third-party component retained");
    check(findings(disabled_client).back().find("membership") !=
              std::string::npos,
          "Bridge evidence caveat");
    for (unsigned c = 0; c < 32; ++c) {
      const auto escaped = quote(std::string(1, static_cast<char>(c)));
      check(escaped.find(static_cast<char>(c)) == std::string::npos,
            "Control byte escaped");
    }
    Snapshot mixed_source;
    s.interfaces_complete = true;
    s.netcfg_complete = true;
    mixed_source.adapters = {uncertain, known_empty, disabled_client};
    mixed_source.interfaces_complete = false;
    mixed_source.netcfg_complete = true;
    mixed_source.errors = {"GetIfTable2 failed: fixture"};
    normalize(mixed_source);
    check(json(mixed_source).find("\"interfaces_complete\":false") !=
              std::string::npos,
          "NetCfg-only partial acquisition");
    auto mixed = fixture("2", "Mixed IPv4");
    mixed.paths.push_back({State::disabled, {{"ms_tcpip", "IPv4"}}});
    s.adapters.push_back(mixed);
    s.adapters.push_back(uncertain);
    s.adapters.push_back(known_empty);
    s.adapters.push_back(disabled_client);
    auto absent = fixture("3", "Absent IPv4");
    absent.paths.clear();
    s.adapters.push_back(absent);
    normalize(s);
    check(json(s).find("\"ms_tcpip\":\"mixed\"") != std::string::npos,
          "Mixed JSON");
    check(json(s).find("\"ms_tcpip\":\"unknown\"") != std::string::npos,
          "Unknown JSON");
    const auto permutation = json(s);
    std::reverse(s.adapters.begin(), s.adapters.end());
    normalize(s);
    check(json(s) == permutation, "All fixture permutation stable");
    Snapshot empty;
    check(json(empty).find("\"interfaces_complete\":false") !=
              std::string::npos,
          "Empty partial");
    check(render(s, "full").find("Adapters differ") != std::string::npos,
          "Material differences");
    if (argc == 2 && std::string(argv[1]) == "--json")
      std::cout << json(s);
    else
      std::cout << checks << " fixture assertions passed\n";
    return 0;
  } catch (const std::exception &e) {
    std::fprintf(stderr, "%s\n", e.what());
    return 1;
  }
}