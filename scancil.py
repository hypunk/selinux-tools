#!/bin/python

"""
SELinux Modules dependency builder.
Scan for cil-files in active directory and show type-require binds

# TODO BACKLOG:
    + Filter list/types by module
"""

__author__='i_kuznetsov'
__version__='0.1.1'

import bz2
import os
import re
import json
import argparse

SILENT=True
DEBUG=True

DEFAULT_BASEDIR='/var/lib/selinux/targeted/active/modules'
BASEDIR = DEFAULT_BASEDIR
RE_TYPE = re.compile(b'\\(type ([a-z0-9A-Z_]+)\\)')
RE_RQ   = re.compile(b'\\(typeattributeset cil_gen_require ([a-z0-9A-Z_]+)\\)')

# ======================
def say(m, f='+'):
    if SILENT: return
    print(f' [{f}] {m}')

def dbg(m):
    if not DEBUG: return
    say(m, 'DBG')

def todo(m):
    if not DEBUG: return
    say(m, 'TODO')

def cil(name, path, types, requires):
    "Generate dict for CIL file"
    return {'name': name,
            'path': path,
            'types': types,
            'requires': requires
            }

def scan():
    "Scan and return list of CIL-files"

    dbg(f'Find modules {BASEDIR}')
    result = []
    for p in os.walk(BASEDIR):
        path, dirs, files = p
        for file in files:
            if file == 'cil':
                result.append(f"{path}/{file}")
    return result
    # return ['/var/lib/selinux/targeted/active/modules/400/gogs/cil']

def processCIL(path):
    "Read CIL file and generate structure"

    types = []
    requires = []
    with bz2.open(path) as file:
        for line in file.readlines():
            if RE_TYPE.match(line):
                m = RE_TYPE.match(line)
                types.append( RE_TYPE.match(line).groups()[0].decode())
            elif RE_RQ.match(line):
                requires.append( RE_RQ.match(line).groups()[0].decode())
    return cil(path.split('/')[-2], path.split('/')[-3], types, requires)


def hello():
    "Hello message"

    say(f'### SEL_DEP v{__version__} ###', '#')
    say('Capture SELinux modules dependency tree', '#')

def get_mods():
    "Get modules"

    result = []
    for path in scan():
        mod = processCIL(path)
        result.append(mod)
    return result

def get_types(mods):
    "Get dict of types by modules"

    result = {}
    for mod in mods:
        for tp in mod['types']:
            if tp in result:
                dbg(f"Module {tp} already exists as `{result[tp]}`, but want `{mod['name']}`")
            result[tp] = mod['name']
    return result

def get_dependencies(mods, types):
    result = {}
    for mod in mods:
        dp = []
        for rq in mod['requires']:
            if rq not in types:
                dbg(f"NOT FOUND DEPENDENCY FOR: {mod['name']} {rq}")
                continue
            if types[rq] not in dp:
                dp.append(types[rq])
        if mod['name'] not in result:
            result[mod['name']] = []
        result[mod['name']] += dp
    return result


def mode_list():
    "Process - list of modules"

    mods = get_mods()
    say('Modules: ')
    print(json.dumps(mods))


def mode_deps():
    "Process Dependency-list mode"

    mods = get_mods()
    types = get_types(mods)
    deps = get_dependencies(mods, types)
    
    say("Dependencies list")
    print(json.dumps(deps))

def mode_type():
    mods = get_mods()
    types = get_types(mods)
    say('Types: ')
    print(json.dumps(types))

def mode_enable(modules):
    "Process dependency tree of modules needed to be enabled"

    dbg(f'Enable modules: {modules}')
    if modules is None: 
        say("No modules...")
        return

    # Fetch data:
    mods = get_mods()
    types = get_types(mods)
    deps = get_dependencies(mods, types)

    # Build dependency tree for modules
    result = {}
    for mod in modules:
        checked = set()
        
        # Collect dependencies recursive
        if mod not in deps:
            dbg(f'Not found module `{mod}`')
            continue
        need_to_check = deps[mod]
        while len(need_to_check) > 0:
            nxt = need_to_check[0]
            del need_to_check[0]
            if nxt in checked: continue
            need_to_check += deps[nxt]
            checked.add(nxt)

        result[mod] = list(checked)
    say("Requested modules dependencies")
    print(json.dumps(result))

def mode_disable(modules):
    "Process dependency tree of modules needed to be enabled"

    dbg(f'Enable modules: {modules}')
    if modules is None: 
        say("No modules...")
        return

    # Fetch data:
    mods = get_mods()
    types = get_types(mods)
    deps = get_dependencies(mods, types)

    rev_dep = {}
    for dp in deps:
        if dp not in rev_dep: rev_dep[dp] = []
        for m in deps[dp]:
            if m not in rev_dep:
                rev_dep[m] = []
            rev_dep[m].append(dp)

    # Build dependency tree for modules
    result = {}
    for mod in modules:
        checked = set()
        
        # Collect dependencies recursive
        if mod not in rev_dep:
            dbg(f'Not found module `{mod}`')
            continue
        need_to_check = rev_dep[mod]
        while len(need_to_check) > 0:
            nxt = need_to_check[0]
            del need_to_check[0]
            if nxt in checked or nxt == mod: continue
            need_to_check += rev_dep[nxt]
            checked.add(nxt)

        result[mod] = list(checked)
    say("Requested modules dependencies")
    print(json.dumps(result))
            
# ENTRY POINT
def main():
    "Main logic here..."

    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter, epilog='''
    MODES:
        -md - List all dependencies
        -ml - List all modules
        -mt - List all types
        -me - Show recursive dependency for module (require -e XXX)
        -mr - Show recursive usage of module (require -e XXX)
                                                                                                  ''')
    #parser.add_argument('mode', choices=['d', 'l'], default='d', help='d - Dependency, l - List module')
    parser.add_argument('-m', '--mode', choices=['d', 'l', 'e', 't', 'r'], default='d', help='Select mode. See MODES.')
    parser.add_argument('-e', '--enable', default="", help='Comma-separated list of modules (used by -me and -md modes)')

    parser.add_argument('--debug', action='store_true')
    parser.add_argument('-s', '--silent', action='store_true', help="Reduce messages: show only data JSON.")
    parser.add_argument('-c', '--cil_path', default=DEFAULT_BASEDIR, help=f"Base path of CIL-files. By default: {DEFAULT_BASEDIR}")
    args = parser.parse_args()

    global SILENT, DEBUG, BASEDIR
    DEBUG = args.debug
    SILENT = args.silent
    BASEDIR = args.cil_path

    hello()
     
    # Select mode of process
    if args.mode == 'l': mode_list()
    elif args.mode == 'd': mode_deps()
    elif args.mode == 't': mode_type()
    elif args.mode == 'e': mode_enable(args.enable.split(','))
    elif args.mode == 'r': mode_disable(args.enable.split(','))
    else: mode_list()

    
    # Bind dependencies
    todo('Build dependency')

if __name__ == '__main__': main()
