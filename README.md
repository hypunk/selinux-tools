# selinux-tools
Util scripts for SELiunx debug

## ScanCIL - Tool for dependency check on CIL files

Usage: `scancil.py [-h] [-m {d,l,e,t,r}] [-e ENABLE] [--debug] [-s] [-c CIL_PATH]`

Optional arguments:
```
  -h, --help            show this help message and exit
  -m {d,l,e,t,r}, --mode {d,l,e,t,r}
                        Select mode. See MODES.
  -e ENABLE, --enable ENABLE
                        Comma-separated list of modules (used by -me and -md modes)
  --debug
  -s, --silent          Reduce messages: show only data JSON.
  -c CIL_PATH, --cil_path CIL_PATH
                        Base path of CIL-files. By default: /var/lib/selinux/targeted/active/modules

    MODES:
        -md - List all dependencies
        -ml - List all modules
        -mt - List all types
        -me - Show recursive dependency for module (require -e XXX)
        -mr - Show recursive usage of module (require -e XXX)
```
