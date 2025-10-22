# NVIDIA Platform Event Extension

Extension for phosphor-logging to support device-specific error aggregation, topology-aware error handling, and D-Bus status reporting for Platform Resiliency Firmware Upgrade.

## Overview

This extension processes device error logs with comprehensive topology awareness and provides:
- **Device topology management** via EntityManager integration
- **Topology-aware error handling** (parent precedence, power propagation)
- **Priority-based error classification** using PDI enums
- **Unified device registry** (topology + errors + D-Bus interfaces)
- **D-Bus status interfaces** for device health queries
- **Dynamic device discovery** via InterfacesAdded signals


## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│ EntityManager (xyz.openbmc_project.EntityManager)              │
│ - Publishes device topology via GetManagedObjects              │
│ - Emits InterfacesAdded signals for dynamic devices            │
└─────────────────────┬───────────────────────────────────────────┘
                      │ D-Bus queries/signals
                     ▼
┌─────────────────────────────────────────────────────────────────┐
│ lib/topology/em_interface.cpp                                   │
│ - Minimal EntityManager D-Bus interface wrapper                 │
│ - queryAllDevices() - Initial topology query                    │
│ - setupSignalMonitoring() - Dynamic device discovery           │
└─────────────────────┬───────────────────────────────────────────┘
                      │ Provides device data
                     ▼
┌─────────────────────────────────────────────────────────────────┐
│ extensions/nvidia-platform-event/device_topology.cpp            │
│ - initializeTopology() - Build device registry at startup       │
│ - setupTopologyMonitoring() - Handle InterfacesAdded signals   │
│ - builddeviceErrorDatabase() - Parse device properties               │
│ - linkDeviceHierarchy() - Build parent-child relationships     │
│ - handleDeviceAdded() - Process dynamically added devices       │
└─────────────────────┬───────────────────────────────────────────┘
                      │ Populates
                     ▼
┌─────────────────────────────────────────────────────────────────┐
│ extensions/nvidia-platform-event/device_error_database.cpp      │
│                                                                  │
│ Unified Device Registry (deviceErrorDatabase):                       │
│ ┌──────────────────────────────────────────────────────────┐   │
│ │ DeviceErrorStore (per device):                           │   │
│ │ - Identity: EID, deviceId                                │   │
│ │ - Topology: parentEid, poweredInStandby                  │   │
│ │ - Errors: errorClasses (sorted by priority), status      │   │
│ │ - D-Bus: dbusInterface (shared_ptr)                      │   │
│ └──────────────────────────────────────────────────────────┘   │
│                                                                  │
│ Core API:                                                        │
│ - processDeviceErrorLog() - Store error + topology logic        │
│ - getDeviceStatus() - Query with parent precedence             │
│ - clearDeviceErrors() - Clear device errors                    │
│ - createDeviceStatusInterface() - Create D-Bus object          │
└─────────────────────┬───────────────────────────────────────────┘
                      │ Exposes via D-Bus
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│ extensions/nvidia-platform-event/device_status_interface.cpp    │
│ - D-Bus interface: com.nvidia.State.DeviceState                │
│ - Path: /com/nvidia/state/device_status/<EID>                  │
│ - Property: DeviceStatus (read/write)                          │
│   - Returns: {StatusType: (DeviceHealth, [(ErrorCode, ErrorClass, AdditionalData)])} │
└─────────────────────────────────────────────────────────────────┘
```

## File Structure

```
phosphor-logging/
├── lib/
│   └── topology/
│       ├── em_interface.hpp          # EntityManager D-Bus interface
│       ├── em_interface.cpp          # Query + signal monitoring
│       └── meson.build
│
├── extensions/nvidia-platform-event/
│   ├── README.md                     # This file
│   │
│   │ # Core Data & Logic
│   ├── device_error_database.hpp     # DeviceErrorStore, unified registry
│   ├── device_error_database.cpp     # Error processing + topology logic
│   │
│   │ # Topology Management
│   ├── device_topology.hpp           # Topology build/link functions
│   ├── device_topology.cpp           # EntityManager integration
│   │
│   │ # D-Bus Interface
│   ├── device_status_interface.hpp   # com.nvidia.State.DeviceState
│   ├── device_status_interface.cpp   # Property-based status query
│   │
│   │ # Extension Glue
│   ├── manager.hpp                   # Extension manager
│   ├── manager.cpp                   # Topology + error initialization
│   ├── entry_points.hpp              # Extension hooks
│   ├── entry_points.cpp              # Hook implementations
│   │
│   └── meson.build                   # Build configuration
│
└── test/
    ├── topology_test_helper.hpp      # Test topology builder + cleanup
    ├── platform_event_dbus_tests.cpp # 27 comprehensive integration tests
```

## Key Data Structures

### DeviceErrorStore (Unified Per-Device Storage)

The heart of the architecture - each device gets one `DeviceErrorStore`:

```cpp
struct DeviceErrorStore {
    // ========== IDENTITY ==========
    uint8_t eid;                              // Device EID (0-255)
    std::string deviceId;                     // Name (e.g., "GPU0", "Bridge1")
    
    // ========== CACHED TOPOLOGY ==========
    std::optional<uint8_t> parentEid;         // Direct parent (for precedence)
    bool poweredInStandby;               // Power dependency flag
    
    // ========== ERROR STORAGE ==========
    std::map<ErrorClass, ErrorClassData, ErrorClassComparator> errorClasses;  // Sorted by priority
    DeviceStatus status;                      // Healthy or Degraded
    
    // ========== D-BUS INTERFACE ==========
    std::shared_ptr<DeviceStatusInterface> dbusInterface;  // D-Bus object
};
```

**Key Benefits:**
- **O(1) lookups**: All topology info cached, no runtime cross-module calls
- **Single source of truth**: All device data in one place
- **Memory efficient**: Pre-allocated error class buckets prevent dynamic allocation

### DeviceErrorMetadata (Per-Error Information)

```cpp
struct DeviceErrorMetadata {
    uint8_t eid;                              // Device EID
    int64_t errorNumber;                      // Error code
    ErrorClass errorClass;                    // PDI enum (Power, MCTP, etc.)
    std::string errorNamespace;               // Namespace (Common, PLDM T5, etc.)
    int priority;                             // 0=highest, 4=lowest
    std::chrono::system_clock::time_point timestamp;
    std::string redfishMessageId;             // Redfish message ID
    std::string redfishMessageArgs;           // Redfish args
};
```

### Error Priority Levels (PDI Enum-Based)

| Priority | PDI ErrorClass          | Description                    |
|----------|-------------------------|--------------------------------|
| 0        | ErrorClass::Power       | System-level critical          |
| 0        | ErrorClass::Recovery    | Firmware recovery codes        |
| 1        | ErrorClass::PhysicalInterface | Device present/absent   |
| 1        | ErrorClass::MCTP        | MCTP communication errors      |

**Note:** Error classes uses PDI-generated enums directly.

## Topology Features

### Parent Precedence
When querying device status, parent errors **override** child errors:
- If Bridge has MCTP error, GPU status returns Bridge's error (not GPU's own error)
- Root cause analysis: Fix the parent first

### Power Propagation
Power-off errors automatically propagate to power-dependent descendants:
- BMC power-off → propagates to GPU (if `poweredInStandby=true`)
- Bridge power-off → propagates through hierarchy to all power-dependent children
- Power-on automatically clears propagated errors

### Dynamic Device Discovery
Handles devices added after startup via EntityManager `InterfacesAdded` signals:
- Devices added to registry dynamically
- Parent-child relationships resolved (including forward references)
- D-Bus interfaces created automatically

## Core API Functions

### Error Processing
```cpp
// Process and store device error (called by extension hooks)
void processDeviceErrorLog(const DeviceErrorMetadata& error);
```
**Features:**
- Rejects errors from unknown EIDs (not in topology)
- Applies power propagation rules
- Updates cached priority
- Creates D-Bus interface if needed

### Status Query
```cpp
// Get device status with topology awareness
std::vector<DeviceErrorMetadata> getDeviceStatus(uint8_t eid);
```
**Features:**
- Returns parent errors if parent has errors (precedence)
   - Returns only highest priority errors
- O(1) lookup using cached data

### Error Clearance
```cpp
// Clear all errors for a device
void clearDeviceErrors(uint8_t eid);
```
**Features:**
- Clears all error class queues
- Resets highest priority
   - Called when device recovers

### Topology Initialization
```cpp
// Initialize topology at startup (called by Manager)
int initializeTopology(sdbusplus::bus_t& bus);

// Monitor for dynamic devices (called by Manager)
void setupTopologyMonitoring(sdbusplus::bus_t& bus);
```

## D-Bus Interface

### Device Status Interface
**Interface:** `com.nvidia.State.DeviceState`  
**Path:** `/com/nvidia/state/device_status/<EID>` (EID in decimal)

**Property:** `DeviceStatus` (read/write)
```cpp
// Type signature: a{y(ya(x(ssa{ss})))}
map<StatusType, tuple<DeviceHealth, vector<tuple<ErrorCode, ErrorClass, AdditionalData>>>>
```

**Example Query:**
```bash
busctl get-property com.nvidia.State.DeviceState \
    /com/nvidia/state/device_status/17 \
    com.nvidia.State.DeviceState DeviceStatus
```

**Example Clear (write empty):**
```bash
busctl set-property com.nvidia.State.DeviceState \
    /com/nvidia/state/device_status/17 \
    com.nvidia.State.DeviceState DeviceStatus \
    "a{y(ya(x(ssa{ss})))}" 0  # Empty map = clear
```

## Public API (for other services)

Located in `lib/include/phosphor-logging/device_error_log.hpp`:

```cpp
using ErrorClass = sdbusplus::server::com::nvidia::state::DeviceState::ErrorClass;

// Commit a device error (with Redfish metadata)
void CommitDeviceError(
    uint8_t deviceAddress,  // EID: 0-255
    int64_t errorCode,
    ErrorClass errorClass,
    const std::map<std::string, std::string>& additionalData = {}
);

// Get Redfish metadata for an error
ErrorInfo GetRedfishErrorInfo(int64_t errorCode, ErrorClass errorClass);

// Get error priority
uint8_t GetErrorPriority(ErrorClass errorClass);
```

**Usage Example:**
```cpp
#include <phosphor-logging/device_error_log.hpp>

// GPU at EID 0x11 reports MCTP timeout
auto info = nv::lg2::GetRedfishErrorInfo(
    nv::lg2::ErrorCode::MCTP::MCTP_TRANSPORT_FAIL_PING_TIMEOUT,
    nv::lg2::ErrorClass::MCTP
);

nv::lg2::CommitDeviceError(
    0x11,  // GPU EID
    nv::lg2::ErrorCode::MCTP::MCTP_TRANSPORT_FAIL_PING_TIMEOUT,
    nv::lg2::ErrorClass::MCTP,
    {
        {"REDFISH_MESSAGE_ID", info.redfishMessageId},
        {"REDFISH_MESSAGE_ARGS", "GPU0, " + info.errorMessage}
    }
);
```

## Testing

### Unit Tests
27 comprehensive tests in `test/platform_event_dbus_tests.cpp`:
- Basic error creation and FIFO queue behavior
- Parent precedence (3-level hierarchy tests)
- Power propagation (recursive, selective by property)
- D-Bus interface lifecycle
- Error clearing and recovery
- Boundary conditions (EID ranges, unknown devices)

**Run tests:**
```bash
cd build
ninja test
# Or run directly:
./test/test-platform-event-dbus-tests
```

### Test Topology
Tests use a 4-device hierarchy via `test/topology_test_helper.hpp`:
```
BMC (0x01) - Root device
├─ Bridge (0x10) - PCIe Bridge, child of BMC
│  └─ GPU (0x11) - GPU device, child of Bridge (power-dependent)
└─ CPU (0x20) - CPU device, child of BMC (power-dependent)
```

### Manual Testing
Inject errors via D-Bus:
```bash
# Create an error for device 0x11 (GPU)
busctl call xyz.openbmc_project.Logging \
    /xyz/openbmc_project/logging \
    xyz.openbmc_project.Logging.Create Create ssa{ss} \
    xyz.openbmc_project.Common.Error.InternalFailure \
    xyz.openbmc_project.Logging.Entry.Level.Error 3 \
    PLATFORM_DEVICE_ADDRESS "17" \
    PLATFORM_DEVICE_ERROR "2" \
    PLATFORM_DEVICE_CLASS "1"

# Query device status
busctl get-property com.nvidia.State.DeviceState \
    /com/nvidia/state/device_status/17 \
    com.nvidia.State.DeviceState DeviceStatus
```

## Performance Characteristics

### Initialization (Startup)
- **O(n)**: Parse n devices from EntityManager
- **O(n)**: Build parent-child relationships
- **O(n)**: Create D-Bus interfaces for all devices

### Runtime (Per Error)
- **O(1)**: Device lookup in registry
- **O(1)**: Error insertion into FIFO queue
- **O(c)**: Power propagation (c = number of children)
- **O(1)**: Priority update
- **Zero** cross-module topology calls

### Query (Per Status Request)
- **O(1)**: Device lookup
- **O(1)**: Parent check (if parent exists)
- **O(k)**: Error retrieval (k = errors in highest priority class)

## Configuration

### Meson Options
```bash
# Maximum errors per error class (FIFO queue size)
meson configure -Dmax-errors-per-class=20
```

### EntityManager Requirements
Devices must expose these properties:
- `Name` - Unique device identifier
- `DeviceAddress` - Format: "MCTP:n" where n is decimal EID
- `ConnectsToName` - Parent device name (empty for root)
- `DeviceType` - Device type (e.g., "BMC", "PCIeBridge", "GPU", "CPU")
- `poweredInStandby` - Boolean power dependency flag

