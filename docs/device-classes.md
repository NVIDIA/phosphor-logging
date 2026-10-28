# Namespace bins and device classes

Logs that carry the AdditionalData key `namespace` are kept in a bin (a
folder under the error path, with its own error and info capacity). A log whose
namespace has no bin goes to the default bin.

## Class of a namespace

The class of a namespace is its name with the all-numeric `_`-separated parts
removed: `GPU_0` is class `GPU`, `GPU_0_XID` is `GPU_XID`, `IO_Board_2` is
`IO_Board`, `FWUpdate` is `FWUpdate`. Only letters, digits and `_` are
accepted (the name becomes a folder name), a name is at most 64 characters, no
`_`-separated part is empty and an all-numeric part has at most 4 digits. Any
other name never matches a class and goes to the default bin. A name that is
all numeric parts has no class either.

## Default device classes

`config/phosphor-logging-device-classes.json` is installed to
`/usr/share/phosphor-logging/device-classes.json` (`device_classes_file_path`)
and read at start. It has one entry per class:

```json
{ "Classes": [ { "ID": "GPU", "ErrorCapacity": 180, "InfoErrorCapacity": 10 } ] }
```

`PersistInfoLog` (default true) and `DefaultCapacity` (default 0) are optional,
as in `Namespaces` entries. The file is the union of the classes used by the
platform json files; where platforms used different capacities for the same
class the value of the newest platforms is used, and a platform that needs
other values lists the class (or the instance) in its own file.

## Platform json (`argv[1]`)

The platform json may still list instances in `Namespaces` (bins created at
start, as before) and may add or replace classes in `Classes`. An instance bin
listed in `Namespaces` always wins over a class. The platform json is optional.

## When a bin is created

* At start, for each folder left by a previous boot whose name belongs to a
  class (before the logs are restored).
* When a log arrives for a namespace that has no bin but belongs to a class
  (the folder is created if it does not exist).

Until then the namespace answers like an empty bin: `GetStats` returns
`(0, 0)`, `GetAll` returns no entries, `DeleteAll` succeeds. A namespace that
has no bin and matches no class keeps the earlier behavior: `GetStats` and
`DeleteAll` return `ResourceNotFound`, `GetAll` returns the entries of the
default bin and its logs go to the default bin.
