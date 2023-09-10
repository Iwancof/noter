# Install

Clone repository and add path to noter.py to .gdbinit

```
git clone https://github.com/Iwancof/noter.git

echo "source /path/to/noter.py" >> ~/.gdbinit
```

# How to use

# noter

In gdb prompt, `noter` command will record memory map offsets to `${PWD}/note.json`
This means initialization.
Following other commands need to execute `noter`

```
pwndbg> noter
Note added with key: 2023-09-10T21:30:32
```

The argument is title of this record.

# noter_imm

Record immidiate value

```
noter_imm name 0x1234
```

# noter_val

Record variables

```
noter_val stack_on_ret $rsp
```

third argument will evaluate to `p/d (third arg)` and convert to integer.

