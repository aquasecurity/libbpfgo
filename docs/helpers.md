# Helpers

## OSInfo and KernelConfig

In order to support eBPF CO-RE (Compile Once - Run Everywhere) technology, all
the code using libbpfgo must have access to /etc/os-release file (OSInfo API at
helpers/osinfo) and either /boot/config-$(uname-r) OR /proc/config.gz files
(KernelConfig API at helpers/kernel_config).

### OSInfo

The `OSInfo` API reads the [/etc/os-release
file](https://www.freedesktop.org/software/systemd/man/os-release.html) by
default and allows user to know about the running OS environment with
information such as name, id and version of the Linux distribution.

> If the environment does not have a /etc/os-release, libbpfgo will only
> provide the running kernel version information unless another os-release file
> is overriden. There won't be any information regarding the Linux distribution
> being executed at.

> If you need to override the /etc/os-release file - e.g. when running your
> code inside a container, that might have an os-release file different than
> the host - you may export the `LIBBPFGO_OSRELEASE_FILE` environment variable,
> pointing to another os-release file (created with just enough information,
> for example):

An example of such file could be `/etc/os-release-host`, with:

```
NAME="Ubuntu"
VERSION="21.04 (Hirsute Hippo)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 21.04"
VERSION_ID="21.04"
VERSION_CODENAME=hirsute
UBUNTU_CODENAME=hirsute
```

and your eBPF go program would be executed like:

```
$ sudo LIBBPFGO_OSRELEASE_FILE=/etc/os-release-host ./program
```

Some ways of using the `OSInfo` API include:

```go
    OSInfo, err := helpers.GetOSInfo()
```

```go
    OSInfo.GetOSReleaseFieldValue(helpers.OS_KERNEL_RELEASE)
```

```go
    for k, v := range OSInfo.GetOSReleaseAllFieldValues() {
        fmt.Fprintf(os.Stdout, "OSInfo: %v: %v\n", k, v)
    }
```

### KernelConfig

The `KernelConfig` API reads all kconfig options and values from either
/proc/config.gz (less common) or /boot/config-$(uname -r) (used more often).
The API already has a list of pre-defined kconfig options that could needed -
and required by user - in order for an eBPF program to work.

With this API, user reads the kconfig initially and may configure a set of
needed KernelConfigOptions for your eBPF programs to run. In case those
kconfig options are not set, it is possible to fail and inform which options
are missing in the running kernel configuration.

Example:

```go
    kernelConfig, err := helpers.InitKernelConfig()
    if err == nil {
        kernelConfig.AddNeeded(helpers.CONFIG_BPF, helpers.BUILTIN)
        kernelConfig.AddNeeded(helpers.CONFIG_BPF_SYSCALL, helpers.BUILTIN)
        kernelConfig.AddNeeded(helpers.CONFIG_KPROBE_EVENTS, helpers.BUILTIN)
        kernelConfig.AddNeeded(helpers.CONFIG_BPF_EVENTS, helpers.BUILTIN)
        missing := kernelConfig.CheckMissing()
        if len(missing) > 0 {
            return fmt.Errorf("missing kernel configuration options: %s\n", missing)
        }
    }
```

> If you need to override the kconfig file, telling libbpfgo not to use
> /proc/config.gz nor /boot/config-$(uname -r), because of a specific need like
> when running your code inside a container, for example, you may export the
> `LIBBPFGO_KCONFIG_FILE` environment variable pointing to another kconfile
> file.

> **Attention** make sure to set the correct kconfig values in that file as
> libbpfgo might take decisions based on available kconfig options and their
> values.

#### KernelConfig (Bonus)

Through the KernelConfig API is also possible to 'add' custom
KernelConfigOption's variables that you might need for your eBPF's program
execution. Example:

```go
	const (
		CONFIG_ARCH_HAS_SYSCALL_WRAPPER helpers.KernelConfigOption = iota + helpers.CUSTOM_OPTION_START
	)
```

and

```go
	var value helpers.KernelConfigOptionValue

	key := CONFIG_ARCH_HAS_SYSCALL_WRAPPER
	keyString := "CONFIG_ARCH_HAS_SYSCALL_WRAPPER"

	if err = t.config.KernelConfig.AddCustomKernelConfig(key, keyString); err != nil {
	        return err
	}

	if err = t.config.KernelConfig.LoadKernelConfig(); err != nil { // invalid kconfig file: assume values then
		fmt.Fprintf(os.Stderr, "KConfig: warning: assuming kconfig values, might have unexpected behavior\n")
	        value = helpers.BUILTIN
	} else {
	        value = t.config.KernelConfig.GetValue(key) // undefined, builtin, module OR string
	}
```

might feed your eBPF program. Instead of relying on libbpf's automated kconfig
embedded relocations, libbpfgo implements that feature using a map called
kconfig_map as well.
