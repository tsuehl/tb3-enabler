#!/usr/bin/env python

# Modified based on Loic Nageleisen's trim_patcher
# https://github.com/lloeki/trim_patcher/

import os
import sys
import re
import hashlib
import shutil
from subprocess import Popen, PIPE
import shlex

ORIGINAL = 'original'
PATCHED = 'patched'

target = ("/System/Library/Extensions/IOThunderboltFamily.kext/"
          "Contents/MacOS/IOThunderboltFamily")
backup = "%s.original" % target

md5_version = {
    "00e2f0eb5db157462a83e4de50583e33": ["10.12.1 (16B2659)"],
    "ebde660af1f51dc7482551e8d07c62fd": ["10.12.2 (16C67)"],
}
md5_patch = {
    "00e2f0eb5db157462a83e4de50583e33": "a6c2143c2f085c2c104369d7a1adfe03",
    "ebde660af1f51dc7482551e8d07c62fd": "2ebb68137da4a1cb0dfc6e6f05be3db2"
}
md5_patch_r = dict((v, k) for k, v in md5_patch.items())

re_index = [
    {
        'search': "\x55\x48\x89\xE5\x41\x57\x41\x56\x41\x55\x41\x54\x53\x48\x81\xEC\x38\x01",
        'replace': "\x55\x48\x89\xE5\x31\xC0\x5D\xC3\x41\x55\x41\x54\x53\x48\x81\xEC\x38\x01"
    }
]
re_md5 = {
    0: [
        "00e2f0eb5db157462a83e4de50583e33",
        ],
}
md5_re = dict((v, re_index[k]) for k, l in re_md5.items() for v in l)


def md5(filename):
    h = hashlib.md5()
    with open(filename, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), ''):
            h.update(chunk)
    return h.hexdigest()


def backquote(command):
    return Popen(shlex.split(command), stdout=PIPE).communicate()[0]

def check_SIP():
    sip_info = backquote("nvram csr-active-config")
    if sip_info.find("w%00%00%00") == -1:
        print >> sys.stderr, "you must disable System Integrity Protection"
        sys.exit(1)

def check_rootness():
    if os.geteuid() != 0:
        print >> sys.stderr, "you must be root"
        sys.exit(1)


def clear_kext_cache():
    print "clearing kext cache...",
    backquote("kextcache -system-prelinked-kernel")
    backquote("kextcache -system-caches")
    print "done"


class UnknownFile(Exception):
    def __init__(self, md5=None):
        self.md5 = md5


class NoBackup(Exception):
    pass


def target_status():
    h = md5(target)
    try:
        return (ORIGINAL, md5_version[h])
    except KeyError:
        pass
    try:
        return (PATCHED, md5_version[md5_patch_r[h]])
    except KeyError:
        pass
    raise UnknownFile(h)


def backup_status():
    if not os.path.exists(backup):
        raise NoBackup
    h = md5(backup)
    try:
        return (ORIGINAL, md5_version[h])
    except KeyError:
        pass
    try:
        return (PATCHED, md5_version[md5_patch_r[h]])
    except KeyError:
        pass
    raise UnknownFile(h)


def apply_patch():
    h = md5(target)
    search_re = md5_re[h]['search']
    replace_re = md5_re[h]['replace']
    with open(target, 'rb') as f:
        source_data = f.read()
    patched_data = re.sub(search_re, replace_re, source_data)
    with open(target, 'wb') as out:
        out.write(patched_data)


def perform_backup():
    shutil.copyfile(target, backup)

def do_backup():
    check_rootness()
    check_SIP()
    try:
        s, t = target_status()
        if s == PATCHED:
            print "already patched, won't backup"
            sys.exit(1)
        else:
            try:
                _, v = backup_status()
            except NoBackup:
                print "backing up...",
                perform_backup()
                print "done"
            else:
                if v == t:
                    print "backup found"
                else:
                    print "backing up...",
                    perform_backup()
                    print "done"
    except UnknownFile as e:
        print "unknown file, won't backup (md5=%s)" % e.md5
        sys.exit(1)


def do_restore():
    check_rootness()
    check_SIP()
    print "restoring...",
    backup_status()
    shutil.copyfile(backup, target)
    print "done"
    clear_kext_cache()


def do_apply():
    check_rootness()
    check_SIP()
    do_backup()
    try:
        s, v = target_status()
        if s == PATCHED:
            print "already patched"
            sys.exit()
    except UnknownFile as e:
        print "unknown file: won't patch (md5=%s)" % e.md5
        sys.exit(1)

    print "patching...",
    apply_patch()

    try:
        s, v = target_status()
        if s != PATCHED:
            print "no change made"
        else:
            print "done"
            clear_kext_cache()
    except UnknownFile as e:
        print "failed (md5=%s), " % e.md5,
        do_restore()


def do_status():
    try:
        print "target:",
        s, v = target_status()
        print s+',', ' or '.join(v)
    except UnknownFile as e:
        print "unknown (md5=%s)" % e.md5

    try:
        print "backup:",
        s, v = backup_status()
        print s+',', ' or '.join(v)
    except NoBackup:
        print "none"
    except UnknownFile as e:
        print "unknown (md5=%s)" % e.md5


def do_diff():
    try:
        backup_status()
    except NoBackup:
        print "no backup"
    else:
        command = ("bash -c "
                   "'diff <(xxd \"%s\") <(xxd \"%s\")'" % (backup, target))
        print os.system(command)


commands = {
    'status': do_status,
    'backup': do_backup,
    'apply': do_apply,
    'restore': do_restore,
    'diff': do_diff,
}

try:
    function = commands[sys.argv[1]]
    function()
except IndexError:
    print >> sys.stderr, "no command provided"
    print >> sys.stderr, "list of commands: %s" % ', '.join(commands.keys())
    sys.exit(1)
except KeyError:
    print >> sys.stderr, "unknown command"
    sys.exit(1)