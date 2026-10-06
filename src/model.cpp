#include "model.hpp"
#include <algorithm>
#include <array>
#include <sstream>
#include <stdexcept>
#include <tuple>
namespace audit {
const char *state_name(State s) {
  switch (s) {
  case State::enabled:
    return "enabled";
  case State::disabled:
    return "disabled";
  case State::mixed:
    return "mixed";
  case State::absent:
    return "absent";
  case State::unavailable:
    return "unavailable";
  case State::unknown:
    return "unknown";
  }
  return "unknown";
}
std::string quote(const std::string &s) {
  const char *hex = "0123456789abcdef";
  std::string out = "\"";
  for (unsigned char c : s) {
    switch (c) {
    case '"':
      out += "\\\"";
      break;
    case '\\':
      out += "\\\\";
      break;
    case '\n':
      out += "\\n";
      break;
    case '\r':
      out += "\\r";
      break;
    case '\t':
      out += "\\t";
      break;
    default:
      if (c < 32) {
        out += "\\u00";
        out += hex[static_cast<unsigned>(c) >> 4U];
        out += hex[static_cast<unsigned>(c) & 15U];
      } else {
        out += static_cast<char>(c);
      }
    }
  }
  return out + "\"";
}
Options parse(const std::vector<std::string> &args) {
  Options o;
  bool mode = false;
  for (std::size_t i = 0; i < args.size(); ++i) {
    const auto &a = args[i];
    if (a == "--json") {
      if (o.json)
        throw std::invalid_argument("Repeated --json");
      o.json = true;
    } else {
      if (mode)
        throw std::invalid_argument("Choose one output mode");
      mode = true;
      if (a == "--summary")
        o.mode = "summary";
      else if (a == "--adapters")
        o.mode = "adapters";
      else if (a == "--help")
        o.mode = "help";
      else if (a == "--version")
        o.mode = "version";
      else if (a == "--adapter") {
        ++i;
        if (i == args.size() || args[i].empty() || args[i].rfind("--", 0) == 0)
          throw std::invalid_argument(
              "--adapter requires GUID, index, or exact friendly name");
        o.identifier = args[i];
      } else
        throw std::invalid_argument("Unknown option: " + a);
    }
  }
  if (o.json && (o.mode == "help" || o.mode == "version"))
    throw std::invalid_argument("--json cannot combine with help/version");
  return o;
}
static std::string folded(std::string s) {
  std::transform(s.begin(), s.end(), s.begin(), [](char c) {
    return c >= 'A' && c <= 'Z' ? static_cast<char>(c + ('a' - 'A')) : c;
  });
  return s;
}
static std::string canonical_guid(std::string s) {
  s = folded(s);
  if (s.size() == 38 && s.front() == '{' && s.back() == '}')
    s = s.substr(1, 36);
  return s;
}
static std::string path_key(const Path &p) {
  std::string k = state_name(p.state);
  for (const auto &c : p.components)
    k += quote(c.id) + quote(c.name);
  return k;
}
void normalize(Snapshot &s) {
  for (auto &a : s.adapters) {
    a.guid = canonical_guid(a.guid);
    for (auto &p : a.paths)
      for (auto &c : p.components)
        c.id = folded(c.id);
    std::sort(a.paths.begin(), a.paths.end(), [](const Path &x, const Path &y) {
      return path_key(x) < path_key(y);
    });
    std::sort(a.errors.begin(), a.errors.end());
  }
  std::sort(s.adapters.begin(), s.adapters.end(),
            [](const Adapter &a, const Adapter &b) {
              return std::tie(a.guid, a.index, a.name) <
                     std::tie(b.guid, b.index, b.name);
            });
  std::sort(s.errors.begin(), s.errors.end());
}
State component_state(const Adapter &a, const std::string &id) {
  bool en = false, dis = false, unknown = false, seen = false;
  for (const auto &p : a.paths)
    for (const auto &c : p.components)
      if (c.id == id) {
        seen = true;
        en |= p.state == State::enabled;
        dis |= p.state == State::disabled;
        unknown |= p.state != State::enabled && p.state != State::disabled;
      }
  if (!a.bindings_complete)
    return State::unavailable;
  if (!seen)
    return State::absent;
  if (unknown)
    return State::unknown;
  if (en && dis)
    return State::mixed;
  return en ? State::enabled : State::disabled;
}
std::vector<std::string> findings(const Adapter &a) {
  std::vector<std::string> f;
  if (!a.bindings_complete)
    f.emplace_back("Binding acquisition unavailable or partial; absence cannot "
                   "be inferred.");
  for (const auto *id : {"ms_tcpip", "ms_tcpip6"})
    if (component_state(a, id) == State::disabled)
      f.emplace_back(std::string(id) +
                     " occurs only on locally disabled binding paths.");
  const auto disabled =
      std::count_if(a.paths.begin(), a.paths.end(),
                    [](const Path &p) { return p.state == State::disabled; });
  if (disabled > 0)
    f.emplace_back(
        std::to_string(disabled) +
        " disabled binding path(s); this does not establish a fault.");
  if (a.operational != "up" && !a.paths.empty())
    f.emplace_back(
        "Adapter is not reported up and still has configured binding paths.");
  bool hyperv = false;
  for (const auto &p : a.paths)
    for (const auto &c : p.components) {
      hyperv |= c.id == "vms_pp";
      if (c.id == "ms_bridge" || c.id == "ms_implat")
        f.emplace_back("Bridge/team-related component observed: " + c.id +
                       "; membership is not established.");
    }
  if (hyperv)
    f.emplace_back("Hyper-V switch protocol observed; this does not prove "
                   "switch attachment or connectivity.");
  return f;
}
std::vector<std::size_t> select(const Snapshot &s, const std::string &id) {
  std::vector<std::size_t> result;
  for (std::size_t i = 0; i < s.adapters.size(); ++i) {
    const auto &a = s.adapters[i];
    if (canonical_guid(id) == canonical_guid(a.guid) || id == a.name ||
        (a.index != 0 && id == std::to_string(a.index)))
      result.push_back(i);
  }
  if (result.empty())
    throw std::invalid_argument("Adapter identifier not found");
  if (result.size() != 1)
    throw std::invalid_argument(
        "Ambiguous adapter identifier; use an interface GUID or index");
  return result;
}
static void strings(std::ostringstream &out,
                    const std::vector<std::string> &ss) {
  out << '[';
  bool first = true;
  for (const auto &x : ss) {
    if (!first)
      out << ',';
    first = false;
    out << quote(x);
  }
  out << ']';
}
static constexpr std::array<const char *, 6> known{{"ms_tcpip", "ms_tcpip6",
                                                    "ms_msclient", "ms_server",
                                                    "ms_pacer", "vms_pp"}};
std::string json(const Snapshot &s) {
  std::ostringstream out;
  out << "{\"schema_version\":\"1.0.0\",\"application_version\":\"1.0.0\","
         "\"interfaces_complete\":"
      << (s.interfaces_complete ? "true" : "false")
      << ",\"netcfg_complete\":" << (s.netcfg_complete ? "true" : "false")
      << ",\"errors\":";
  strings(out, s.errors);
  out << ",\"adapters\":[";
  bool first = true;
  for (const auto &a : s.adapters) {
    if (!first)
      out << ',';
    first = false;
    out << "{\"guid\":" << quote(a.guid) << ",\"index\":";
    if (a.index == 0)
      out << "null";
    else
      out << a.index;
    out << ",\"name\":" << quote(a.name)
        << ",\"description\":" << quote(a.description)
        << ",\"classification\":" << quote(a.kind)
        << ",\"operational_state\":" << quote(a.operational)
        << ",\"bindings_complete\":" << (a.bindings_complete ? "true" : "false")
        << ",\"known_components\":{";
    bool kc = true;
    for (const auto *id : known) {
      if (!kc)
        out << ',';
      kc = false;
      out << quote(id) << ':' << quote(state_name(component_state(a, id)));
    }
    out << "},\"paths\":[";
    bool fp = true;
    for (const auto &p : a.paths) {
      if (!fp)
        out << ',';
      fp = false;
      out << "{\"state\":" << quote(state_name(p.state)) << ",\"components\":[";
      bool fc = true;
      for (const auto &c : p.components) {
        if (!fc)
          out << ',';
        fc = false;
        out << "{\"id\":" << quote(c.id) << ",\"name\":" << quote(c.name)
            << '}';
      }
      out << "]}";
    }
    out << "],\"errors\":";
    strings(out, a.errors);
    out << ",\"findings\":";
    strings(out, findings(a));
    out << '}';
  }
  out << "]}\n";
  return out.str();
}
static std::string signature(const Adapter &a) {
  std::string s;
  for (const auto *id : known)
    s += std::string(id) + ":" + state_name(component_state(a, id)) + ";";
  return s;
}
std::string render(const Snapshot &s, const std::string &mode) {
  std::ostringstream out;
  out << "windows-network-binding-auditor 1.0.0\nLocal configuration only; no "
         "connectivity inference.\n"
      << "Adapters: " << s.adapters.size() << "; interfaces "
      << (s.interfaces_complete ? "complete" : "partial/unavailable")
      << "; NetCfg " << (s.netcfg_complete ? "complete" : "partial/unavailable")
      << "\n";
  for (const auto &e : s.errors)
    out << "Acquisition: " << e << '\n';
  std::vector<std::string> signatures;
  for (const auto &a : s.adapters) {
    out << "\n"
        << quote(a.name) << " [" << a.guid << "] index=" << a.index << " "
        << a.operational << " " << a.kind << '\n';
    if (mode == "adapters")
      continue;
    out << "  " << quote(a.description) << '\n';
    for (const auto *id : known)
      out << "  " << id << ": " << state_name(component_state(a, id)) << '\n';
    if (mode == "full")
      for (const auto &p : a.paths) {
        out << "  Path " << state_name(p.state) << ':';
        for (const auto &c : p.components)
          out << " " << c.id << " (" << quote(c.name) << ")";
        out << '\n';
      }
    for (const auto &e : a.errors)
      out << "  Acquisition: " << e << '\n';
    for (const auto &f : findings(a))
      out << "  Finding: " << f << '\n';
    if (a.bindings_complete)
      signatures.push_back(signature(a));
  }
  if (signatures.size() > 1 &&
      std::any_of(
          signatures.begin() + 1, signatures.end(),
          [&](const std::string &x) { return x != signatures.front(); }))
    out << "\nAdapters differ in observed core component path states; adapter "
           "roles may explain differences.\n";
  return out.str();
}
} // namespace audit