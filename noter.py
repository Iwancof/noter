import gdb
import json
import os
import datetime
import re

reaesc = re.compile(r'\x1b[^m]*m')

""" LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
             Start                End Perm     Size Offset File
    0x557200c7a000     0x557200c7b000 r--p     1000      0 /home/iwancof/WorkSpace/CTF/competitions/patriot_ctf_2023/guessing_game/guessinggame
    0x557200c7b000     0x557200c7c000 r-xp     1000   1000 /home/iwancof/WorkSpace/CTF/competitions/patriot_ctf_2023/guessing_game/guessinggame
    0x557200c7c000     0x557200c7d000 r--p     1000   2000 /home/iwancof/WorkSpace/CTF/competitions/patriot_ctf_2023/guessing_game/guessinggame
    0x557200c7d000     0x557200c7f000 rw-p     2000   2000 /home/iwancof/WorkSpace/CTF/competitions/patriot_ctf_2023/guessing_game/guessinggame
    0x7fafb73a2000     0x7fafb73a3000 r--p     1000      0 /usr/lib/ld-linux-x86-64.so.2
    0x7fafb73a3000     0x7fafb73c9000 r-xp    26000   1000 /usr/lib/ld-linux-x86-64.so.2
    0x7fafb73c9000     0x7fafb73d3000 r--p     a000  27000 /usr/lib/ld-linux-x86-64.so.2
    0x7fafb73d3000     0x7fafb73d7000 rw-p     4000  31000 /usr/lib/ld-linux-x86-64.so.2
    0x7ffd51b58000     0x7ffd51b7a000 rw-p    22000      0 [stack]
    0x7ffd51ba1000     0x7ffd51ba5000 r--p     4000      0 [vvar]
    0x7ffd51ba5000     0x7ffd51ba7000 r-xp     2000      0 [vdso]
0xffffffffff600000 0xffffffffff601000 --xp     1000      0 [vsyscall]
"""

noter_title = None

def parse_vmmap(value):
    result = {}

    elements = value.split('\n')[2: ]
    for elm in elements:
        elm = reaesc.sub('', elm)

        elm = elm.strip(' ')
        old = 'dummy'
        while old != elm:
            old = elm
            elm = elm.replace('  ', ' ')

        elm = elm.strip(' ')
        
        entry = elm.split(' ')
        if len(entry) != 6:
            continue

        start, _end, perm, _size, _offset, file = entry
        start = int(start, 16)

        if '/' in file:
            name = file[file.rfind('/') + 1: ]
        else:
            name = file

        if f'{name}_{perm}' in result:
            print(f'[warn] found duplicate entry: {name}_{perm}')
            result[f'{name}_{perm}'].append(start)
        else:
            result[f'{name}_{perm}'] = [start]

    return result

class NoterCommand(gdb.Command):
    def __init__(self):
        super(NoterCommand, self).__init__("noter", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        global noter_title

        # カレントディレクトリのnote.jsonのパスを取得
        filepath = os.path.join(os.getcwd(), "note.json")

        # note.jsonが存在する場合は読み込み、存在しない場合は新しい辞書を作成
        if os.path.exists(filepath):
            with open(filepath, "r") as f:
                notes = json.load(f)
        else:
            notes = {}

        # 引数が与えられている場合はその引数をキーとし、与えられていない場合は現在の時刻をキーとする
        noter_title = arg if arg else datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S')

        result = gdb.execute("vmmap", to_string=True)
        value = parse_vmmap(result);

        # 適当な値を追加
        notes[noter_title] = value

        # 変更をnote.jsonに書き込む
        with open(filepath, "w") as f:
            json.dump(notes, f, indent=4)

        print(f"Note added with key: {noter_title}")

NoterCommand()

class NoterImmCommand(gdb.Command):
    def __init__(self):
        super(NoterImmCommand, self).__init__("noter_imm", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        global noter_title

        args = gdb.string_to_argv(arg)
        if len(args) != 2:
            print("Usage: noter_imm <key> <value>")
            return

        # カレントディレクトリのnote.jsonのパスを取得
        filepath = os.path.join(os.getcwd(), "note.json")

        # note.jsonが存在する場合は読み込み、存在しない場合は新しい辞書を作成
        if os.path.exists(filepath):
            with open(filepath, "r") as f:
                notes = json.load(f)
        else:
            notes = {}

        key, value = args
        if value.startwith('0x'):
            value = int(value, 16)
        else:
            value = int(value, 10)

        notes[noter_title][key] = value

        # 変更をnote.jsonに書き込む
        with open(filepath, "w") as f:
            json.dump(notes, f, indent=4)

        print(f"Added entry: {key} = {value}")

NoterImmCommand()

class NoterValCommand(gdb.Command):
    def __init__(self):
        super(NoterValCommand, self).__init__("noter_val", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        global noter_title

        args = gdb.string_to_argv(arg)
        if len(args) != 2:
            print("Usage: noter_val <key> <val>")
            return

        # カレントディレクトリのnote.jsonのパスを取得
        filepath = os.path.join(os.getcwd(), "note.json")

        # note.jsonが存在する場合は読み込み、存在しない場合は新しい辞書を作成
        if os.path.exists(filepath):
            with open(filepath, "r") as f:
                notes = json.load(f)
        else:
            notes = {}

        key, value = args

        value = gdb.execute(f'p/d {value}', to_string=True)
        
        print(f'value: {value}')
        pattern = r"^\$[0-9]+ = (.+)$"
        match = re.match(pattern, value)

        if match:
            val = match.group(1)
        else:
            print(f'reuslt is incorrect {value}')
            return

        val = int(val)
        notes[noter_title][key] = val

        # 変更をnote.jsonに書き込む
        with open(filepath, "w") as f:
            json.dump(notes, f, indent=4)

        print(f"Added entry: {key} = {val}")

NoterValCommand()
