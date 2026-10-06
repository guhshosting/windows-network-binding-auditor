#pragma once
#include <cstdint>
#include <string>
#include <vector>
namespace audit {
enum class State : std::uint8_t {
  enabled,
  disabled,
  mixed,
  absent,
  unavailable,
  unknown
};
const char *state_name(State s);
struct Component {
  std::string id, name;
};
struct Path {
  State state = State::unknown;
  std::vector<Component> components;
};
struct Adapter {
  std::string guid, name, description, kind = "unknown",
                                       operational = "unknown";
  std::uint32_t index = 0;
  bool bindings_complete = false;
  std::vector<Path> paths;
  std::vector<std::string> errors;
};
struct Snapshot {
  bool interfaces_complete = false, netcfg_complete = false;
  std::vector<Adapter> adapters;
  std::vector<std::string> errors;
};
struct Options {
  std::string mode = "full", identifier;
  bool json = false;
};
Options parse(const std::vector<std::string> &args);
void normalize(Snapshot &s);
State component_state(const Adapter &a, const std::string &id);
std::vector<std::string> findings(const Adapter &a);
std::vector<std::size_t> select(const Snapshot &s, const std::string &id);
std::string json(const Snapshot &s);
std::string render(const Snapshot &s, const std::string &mode);
std::string quote(const std::string &s);
Snapshot acquire();
std::string utf8(const wchar_t *s);
} // namespace audit