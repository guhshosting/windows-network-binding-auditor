#include "model.hpp"
#include <winsock2.h>
#include <windows.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>
#include <netcfgx.h>
#include <netcfgn.h>
#include <devguid.h>
#include <wrl/client.h>
#include <algorithm>
#include <memory>
#include <sstream>
#include <stdexcept>
namespace audit {
using Microsoft::WRL::ComPtr;
std::string utf8(const wchar_t *s) {
  if (!s || !*s)
    return {};
  const int n = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, s, -1,
                                    nullptr, 0, nullptr, nullptr);
  if (n <= 0)
    throw std::runtime_error("Invalid UTF-16 metadata");
  std::string r(static_cast<std::size_t>(n), '\0');
  if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, s, -1, r.data(), n,
                          nullptr, nullptr) != n)
    throw std::runtime_error("UTF-8 conversion failed");
  r.pop_back();
  return r;
}
static std::string guid_text(const GUID &g) {
  wchar_t b[40]{};
  if (StringFromGUID2(g, b, 40) == 0)
    throw std::runtime_error("GUID formatting failed");
  return utf8(b);
}
static std::string error(const char *what, HRESULT hr) {
  std::ostringstream s;
  s << what << " (0x" << std::hex << static_cast<unsigned long>(hr) << ')';
  return s.str();
}
struct TaskFree {
  void operator()(wchar_t *p) const { CoTaskMemFree(p); }
};
static std::string component_text(INetCfgComponent *c, bool id, bool &ok) {
  wchar_t *p = nullptr;
  const HRESULT hr = id ? c->GetId(&p) : c->GetDisplayName(&p);
  std::unique_ptr<wchar_t, TaskFree> mem(p);
  if (FAILED(hr) || !p) {
    ok = false;
    return {};
  }
  return utf8(p);
}
struct ComSession {
  HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
  ~ComSession() {
    if (SUCCEEDED(hr))
      CoUninitialize();
  }
};
struct NetSession {
  ComPtr<INetCfg> cfg;
  bool initialized = false;
  ~NetSession() {
    if (initialized)
      cfg->Uninitialize();
  }
};
static const char *op(IF_OPER_STATUS s) {
  switch (s) {
  case IfOperStatusUp:
    return "up";
  case IfOperStatusDown:
    return "down";
  case IfOperStatusTesting:
    return "testing";
  case IfOperStatusUnknown:
    return "unknown";
  case IfOperStatusDormant:
    return "dormant";
  case IfOperStatusNotPresent:
    return "not_present";
  case IfOperStatusLowerLayerDown:
    return "lower_layer_down";
  }
  return "unknown";
}
static void read_paths(INetCfgComponent *component, Adapter &a) {
  ComPtr<INetCfgComponentBindings> binds;
  HRESULT hr = component->QueryInterface(IID_PPV_ARGS(&binds));
  if (FAILED(hr)) {
    a.errors.push_back(error("Query binding interface", hr));
    return;
  }
  ComPtr<IEnumNetCfgBindingPath> paths;
  hr = binds->EnumBindingPaths(EBP_ABOVE, &paths);
  if (FAILED(hr) || !paths) {
    a.errors.push_back(error("EnumBindingPaths", hr));
    return;
  }
  bool complete = true;
  for (;;) {
    ComPtr<INetCfgBindingPath> path;
    hr = paths->Next(1, &path, nullptr);
    if (hr == S_FALSE)
      break;
    if (hr != S_OK || !path) {
      a.errors.push_back(error("Binding path Next", hr));
      complete = false;
      break;
    }
    Path p;
    hr = path->IsEnabled();
    p.state = hr == S_OK      ? State::enabled
              : hr == S_FALSE ? State::disabled
                              : State::unknown;
    if (FAILED(hr))
      a.errors.push_back(error("IsEnabled", hr));
    ComPtr<IEnumNetCfgBindingInterface> interfaces;
    hr = path->EnumBindingInterfaces(&interfaces);
    if (FAILED(hr) || !interfaces) {
      a.errors.push_back(error("EnumBindingInterfaces", hr));
      complete = false;
      continue;
    }
    for (;;) {
      ComPtr<INetCfgBindingInterface> bi;
      hr = interfaces->Next(1, &bi, nullptr);
      if (hr == S_FALSE)
        break;
      if (hr != S_OK || !bi) {
        a.errors.push_back(error("Binding interface Next", hr));
        complete = false;
        break;
      }
      ComPtr<INetCfgComponent> upper;
      hr = bi->GetUpperComponent(&upper);
      if (FAILED(hr) || !upper) {
        a.errors.push_back(error("GetUpperComponent", hr));
        complete = false;
        continue;
      }
      bool ok = true;
      Component c;
      c.id = component_text(upper.Get(), true, ok);
      c.name = component_text(upper.Get(), false, ok);
      if (!ok || c.id.empty()) {
        a.errors.emplace_back("Component metadata incomplete");
        complete = false;
      }
      p.components.push_back(std::move(c));
    }
    a.paths.push_back(std::move(p));
  }
  a.bindings_complete = complete;
}
Snapshot acquire() {
  Snapshot s;
  MIB_IF_TABLE2 *raw = nullptr;
  const ULONG result = GetIfTable2(&raw);
  const auto free_table = [](MIB_IF_TABLE2 *p) {
    if (p)
      FreeMibTable(p);
  };
  std::unique_ptr<MIB_IF_TABLE2, decltype(free_table)> table(raw, free_table);
  if (result == NO_ERROR && raw) {
    s.interfaces_complete = true;
    for (ULONG i = 0; i < raw->NumEntries; ++i) {
      const auto &row = raw->Table[i];
      Adapter a;
      a.guid = guid_text(row.InterfaceGuid);
      a.index = row.InterfaceIndex;
      a.name = utf8(row.Alias);
      a.description = utf8(row.Description);
      a.operational = op(row.OperStatus);
      if (row.Type == IF_TYPE_SOFTWARE_LOOPBACK)
        a.kind = "loopback";
      else if (row.Type == IF_TYPE_TUNNEL)
        a.kind = "tunnel";
      else if (row.InterfaceAndOperStatusFlags.HardwareInterface)
        a.kind = "hardware";
      else
        a.kind = "non_hardware";
      s.adapters.push_back(std::move(a));
    }
  } else
    s.errors.push_back("GetIfTable2 failed: " + std::to_string(result));
  ComSession com;
  if (FAILED(com.hr)) {
    s.errors.push_back(error("CoInitializeEx", com.hr));
    normalize(s);
    return s;
  }
  NetSession net;
  HRESULT hr = CoCreateInstance(CLSID_CNetCfg, nullptr, CLSCTX_INPROC_SERVER,
                                IID_PPV_ARGS(&net.cfg));
  if (FAILED(hr)) {
    s.errors.push_back(error("Create INetCfg", hr));
    normalize(s);
    return s;
  }
  hr = net.cfg->Initialize(nullptr);
  if (FAILED(hr)) {
    s.errors.push_back(error("Initialize INetCfg", hr));
    normalize(s);
    return s;
  }
  net.initialized = true;
  ComPtr<IEnumNetCfgComponent> components;
  hr = net.cfg->EnumComponents(&GUID_DEVCLASS_NET, &components);
  if (FAILED(hr) || !components) {
    s.errors.push_back(error("Enum adapter components", hr));
    normalize(s);
    return s;
  }
  s.netcfg_complete = true;
  for (;;) {
    ComPtr<INetCfgComponent> component;
    hr = components->Next(1, &component, nullptr);
    if (hr == S_FALSE)
      break;
    if (hr != S_OK || !component) {
      s.errors.push_back(error("Adapter component Next", hr));
      s.netcfg_complete = false;
      break;
    }
    GUID g{};
    hr = component->GetInstanceGuid(&g);
    if (FAILED(hr)) {
      s.errors.push_back(error("GetInstanceGuid", hr));
      s.netcfg_complete = false;
      continue;
    }
    const std::string id = guid_text(g);
    const auto match =
        std::find_if(s.adapters.begin(), s.adapters.end(),
                     [&](const Adapter &a) { return a.guid == id; });
    Adapter *found = match == s.adapters.end() ? nullptr : &*match;
    if (!found) {
      Adapter a;
      a.guid = id;
      bool ok = true;
      a.name = component_text(component.Get(), false, ok);
      if (!ok)
        a.errors.emplace_back("Adapter display name unavailable");
      s.adapters.push_back(std::move(a));
      found = &s.adapters.back();
    }
    read_paths(component.Get(), *found);
  }
  for (auto &a : s.adapters)
    if (!a.bindings_complete && a.errors.empty())
      a.errors.emplace_back(
          "No matching NetCfg adapter component; bindings unavailable");
  normalize(s);
  return s;
}
} // namespace audit