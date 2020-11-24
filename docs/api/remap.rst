=========
``remap``
=========

.. automodule:: pydecipher.remap
    :no-members:

There are three methods that remap can use to recover the scrambled opcode mappings. The first two of the three
methods perform a chosen plaintext attack against the modified Python bytecode, and the last method walks the opcode.pyc
file's constants table. These methods are described in greater detail below.

.. warning::

    These methods may not work if other compiler modifications are present in the bytecode, beyond scrambled opcodes.


Method 1: Diff'ing Against the Python Standard Library Bytecode
---------------------------------------------------------------

.. note::

    This method was first described by Rich Smith in pyREtic's whitepaper, which can be found `here`_. The following
    description is a high-level overview.

How the method works
~~~~~~~~~~~~~~~~~~~~

Any substantial Python application should have a heavy reliance on Python's standard library. For frozen Python
applications, the Python standard library files typically get included as .pyc files in a zip file. This zip file is
most commonly found in the interpreter binary's overlay or delivered alongside the application as a standalone file.
For example, the `TRITON malware`_ discovered by FireEye in 2017 delivered a |Py2Exe| interpreter (trilog.exe)
alongside a zip file of compiled .pyc files. Interestingly, this adversary didn't bother to rename the zipfile from its
default name, library.zip.

Since these Python bytecode files are compiled from a known source, we know what the correct ('standard') compilation
should look like. Therefore, when we see compiled Python files that look different than what we would expect, we can
easily spot the differences by diff-ing the modified opcodes against the standard version's opcodes. Consider the
following simplified example:

.. code-block:: python

    print("Hello, World!")

The Python Code object for this segment of code has the following bytecode instructions when compiled with a standard
Python 2.7 interpreter: ``640000474864010053``. The table below more coherently displays what the bytecode is doing ::

    opcode | argument | opname
    -------+----------+-------
    0x64   |   0000   | LOAD_CONST ('Hello, World!')
    0x47   |          | PRINT_ITEM
    0x48   |          | PRINT_NEWLINE
    0x64   |   0001   | LOAD_CONST (None)
    0x53   |          | RETURN_VALUE

Now consider a modified Python interpreter that compiles the same `Hello, World!` statement, but instead produces this
bytecode stream: ::

    opcode | argument
    -------+---------
    0x84   |   0000
    0x67   |
    0x68   |
    0x84   |   0001
    0x73   |

It becomes apparent that the modified interpreter has remapped (at least) the following opcodes ::

        opname    | old value | new value
    --------------+-----------+----------
    LOAD_CONST    |    0x64   |   0x84
    PRINT_ITEM    |    0x47   |   0x67
    PRINT_NEWLINE |    0x48   |   0x68
    RETURN_VALUE  |    0x53   |   0x73

In reality, there are no ``print('Hello, World!')`` statements in Python's standard library, but there is a whole lot
of other code that can be used to perform this method. **remap** will attempt to use as much of the standard library as
possible, with the limiting factor being what standard library bytecode is available from the modified interpreter.

.. _TRITON malware: https://www.fireeye.com/blog/threat-research/2017/12/attackers-deploy-new-ics-attack-framework-triton.html

Using this method
~~~~~~~~~~~~~~~~~

This method requires a somewhat significant amount of the Python standard library to be included with your modified
interpreter, and a reference set of compiled Python standard library files.

To get the reference set of Python standard library files, you can use pydecipher's StandardBytecodeGenerator docker
image. For example, if you need a reference set of Python 2.7.15 standard library .pyc files, you would run:

.. code-block:: console

    $ docker run --volume "$(pwd):/bc" pydecipher/sbg 2.7.15

And a directory titled 2.7.15 will appear in your working directory. From there, you can run:

.. code-block:: console

    $ remap --standard-bytecode-path ./2.7.15 ./path/to/custom_interpreter/bytecode/

Method 2: Diff'ing Against a 'Megafile'
---------------------------------------

.. note::

    This method comes from dedrop_, a project by Dhiru Kholia and Przemysław Węgrzyn that analyzed the custom Dropbox
    interpreter.

How the method works
~~~~~~~~~~~~~~~~~~~~

This method is theoretically identical to the first method, but differs in its application by only using a single,
specially-crafted file to ascertain remapped opcodes instead of the entirety of the Python standard library. Since
"specially-crafted Python file that when compiled uses every opcode for a specific version" is a mouthful, we've decided
to use the name 'megafile' to refer to these files.

By taking the standard compiled output of a megafile, and comparing it to a custom interpreter's compiled output, we
can identify how the opcodes change and reconstruct an opmap just from this one comparison.

Using this method
~~~~~~~~~~~~~~~~~

.. warning::

    At first, this may seem like the easiest option. Why reconstruct the opmap using tens (potentially hundreds) of
    compiled Python standard library files, when a single file can do? In practice, creating the megafile can be a
    tedious and laborious process of editing Python code and recompiling to ensure you've covered every possible opcode.
    Additionally, once you have the megafile, getting the modified interpreter to execute and compile this file may be
    difficult if the interpreter binary employs other obfuscation or anti-analysis techniques.

The first step to applying this opcode-recovery method is learning what version of Python was used by the custom
interpreter you are analyzing. If you run pydecipher with the verbose flag (``pydecipher -v custom_interpreter.exe``),
any strings found in the binary that match potential Python versions will be printed out. If you still cannot determine
the version, you will have to manually analyze the interpreter binary.

Once you know the version use, you will have to acquire (or likely, create yourself) a Python file that uses every
single opcode (the 'megafile') from this version. Since opcode versions change in Python from version to version, a
megafile will likely only be usable within a single Python minor version. An example of a Python 2.7 megafile is all.py
from the dedrop_ project. Currently, pydecipher includes dedrop's all.py with the package, so if you are analyzing
Python 2.7 code, you can simply pass the string ``2.7`` to ``remap`` like so:

    .. code-block:: console

        $ remap --version 2.7 -m remapped_megafile.pyc

Pull requests to add more megafile versions are welcome! If pydecipher doesn't already have a megafile for the version
you are analyzing, you can create your own megafile and pass it in:

    .. code-block:: console

        $ remap -m remapped_megafile.pyc standard_megafile.pyc

To create the remapped_megafile.pyc from your Python source code megafile, you will have to hijack control of the
modified interpreter while it is running in memory and force it to compile your source code. There are a few different
techniques to accomplish this, and your choice of technique will be limited by what OS your interpreter targets and by
any anti-analysis tricks the interpreter employs.

A moderately detailed description of one technique can be found in Ryan Tracey's `report on the PyXie RAT`_. The
following list of steps is an overview of this method:

    #. Identify the location of the `Py_Initialize()`_ function in the custom interpreter. This can be done through
       a combination of string analysis and manual comparison of the custom interpreter to a standard interpreter of
       the same version (i.e. Python27.dll).
    #. Set a breakpoint to stop execution after ``Py_Initialize`` returns, and run the code to this breakpoint. If you
       attempt to hijack control of the interpreter before the environment has been initialized properly your
       interpreter will probably crash.
    #. Identify the location of the `PyRun_SimpleStringFlags()`_ function in the custom interpreter.
    #. Drop your megafile sourcecode (i.e. `all.py`_) in the working directory of the interpreter.
    #. In a code cave, write the string ``import <name_of_megafile>`` and note the address in memory. If your megafile
       is named ``all.py``, you would write ``import all``.
    #. In a code cave, assemble the instructions ``push [address_of_import_string]``, followed by a ``call
       [address_of_PyRun_SimpleStringFlags]``.
    #. Set your EIP to the new push instruction, and have it step through your code cave to execute the
       ``PyRun_SimpleStringFlags`` function. In your working directory, you should see a new compiled Python file
       get created. This will be the custom interpreter's compiled version of the megafile, that can now be diffed
       against the standard compiled megafile.

    .. figure:: ../_static/img/x32dbg_import_all_zoomed.png
        :align: center
        :figclass: align-center

        x32dbg ready to create the compiled megafile for the PyXie RAT

.. _all.py: https://github.com/kholia/dedrop/blob/master/src/dedrop/all.py
.. _dedrop: https://github.com/kholia/dedrop
.. _report on the PyXie RAT: https://threatvector.cylance.com/en_us/home/meet-pyxie-a-nefarious-new-python-rat.html
.. _PyRun_SimpleStringFlags(): https://github.com/python/cpython/blob/2b74c835a7280840a853e3a9aaeb83758b13a458/Python/pythonrun.c#L463
.. _Py_Initialize(): https://github.com/python/cpython/blob/252346acd937ddba4845331994b8ff4f90349625/Python/pylifecycle.c#L1179

Method 3: Walking the opcode.pyc Constants
------------------------------------------

.. warning::

    The opcode.pyc constant-walking method will only work if there is parity between the opcode values contained in the
    modified interpreter's Lib/opcode.py file and the values that have been changed in the modified interpreter's
    opcode.h file (in CPython). The creator of the custom interpreter would only need parity between these two opmaps
    if their Python code uses the dis module to inspect bytecode produced by the custom interpreter (or another
    interpreter with the same opmap). Therefore, it is not always the case that someone  who has taken the time to
    scramble their CPython interpreter's opcode values will also change the values in the opcode.py file. It is also
    possible that a modified interpreter won't even include the opcode.py file at all, if the dis module isn't needed.

With that huge caveat out of the way, we can get into the details of how this opmap recovery technique works.

How the method works
~~~~~~~~~~~~~~~~~~~~

When a Python source code file is compiled by the interpreter, its code is marshalled into a single code object which
gets appended to a header, and then dumped to a file on disk. During the marshalling of the Code object, any literals
that get encountered get dumped into a `tuple`_ attribute of the Code object called `co_consts`. This includes all
different types of literals - numbers, strings, even more Code objects (which themselves have their own co_consts
attributes!). Furthermore, **order matters in the creation of the co_consts list** - literals are added to the co_consts
attribute in the order in which they appear in the Code object. Consider the example below.

.. code-block:: python

    # /usr/bin/env python
    def main():
        print("hello")
        print(1)
        print(2)
        print("world")
        return 3

    if __name__ == "__main__":
        main()

The co_consts attribute for the above code's Code object would be: ::

    (
        None
        'hello'
        1
        2
        'world'
        3
    )

We can see that the order in which the string constants and integer literals appear in the source code file exactly
matches their order in the co_consts attribute. The initial ``None`` is always included in the co_consts attribute;
`this stackoverflow post`_ provides a succint explanation as to why.

.. rubric:: Rebuilding the opcode map from opcode.py's co_consts

If you've never seen what the opcode.py file looks like in a standard CPython interpreter, I suggest you `take a look`_
before reading further.

The high-level purpose of the opcode.py file is to assist with the analysis of Python bytecode. `The dis module`_ is
one example of the type of bytecode analysis that can be done using the opcode module. The primary function that the
opcode module performs is the recreation of the opname to opcode mapping, known as the opmap. During the creation of
the opmap, the operation names and operation code values are passed into a registering function called ``def_op``.

.. code-block:: python
    :lineno-start: 57
    :caption: A segment of opcode.py from Python 2.7

    def_op('STOP_CODE', 0)
    def_op('POP_TOP', 1)
    def_op('ROT_TWO', 2)
    def_op('ROT_THREE', 3)
    def_op('DUP_TOP', 4)
    def_op('ROT_FOUR', 5)


As discussed in the primer above, when a module gets compiled, the module's literals get marshalled into the Code
object's co_consts attribute in the order they appear in the file. For **almost** all of the opname and opcode literals,
the first and only time these values are seen is in these ``def_op`` calls. Knowing this, we can exploit the ordering of
constants in the co_consts attribute to rebuild the opmap. For example, the standard opcode.py's Code object's co_consts
attribute has the following segment:

.. code-block:: python
    :caption: The segment of opcode.py's `co_consts` attribute that corresponds to the code in the above block

      ...
      'STOP_CODE'
      0
      'POP_TOP'
      1
      'ROT_TWO'
      2
      'ROT_THREE'
      3
      'DUP_TOP'
      4
      'ROT_FOUR'
      5
      'NOP'
      9
      'UNARY_POSITIVE'
      10
      ...

Since the order of these constants is exactly representative of their opname to opcode mapping as created by the
``def_op`` calls, it is trivial to recreate the opmap. There are a few exceptions which are handled on a case-by-case
basis in remap's code.

.. _here: https://github.com/MyNameIsMeerkat/pyREtic/blob/master/docs/pyREtic%20%20In%20memory%20reverse%20engineering%20for%20obfuscated%20Python%20bytecode.pdf
.. _this stackoverflow post: https://stackoverflow.com/questions/27667747/what-is-none-doing-in-the-code-objects-co-consts-attribute/27667752#27667752
.. _tuple: https://github.com/python/cpython/blob/3.6/Objects/codeobject.c#L379
.. _take a look: https://github.com/python/cpython/blob/master/Lib/opcode.py
.. _The dis module: https://github.com/python/cpython/blob/master/Lib/dis.py

Using this method
~~~~~~~~~~~~~~~~~

This method is quite simple to use. First, you will need to locate the opcode.pyc file for the custom interpreter.
If you are analyzing a PyInstaller binary, this will be contained within the ZlibArchive. If you are analyzing a
Py2Exe binary, this will be in the zipfile included alongside (or within the overlay) of the binary. pydecipher should
be able to dump and extract these artifacts automatically. Once you have the located thd compiled `opcode.py`_ file for
the interpreter, run:

.. code-block:: console

    $ remap --opcode-file path/to/opcode.pyc

Output
------

The output of remap is a directory with two files. The directory is named ``remap_output_*``, where the * is substituted
for a :meth:`pydecipher.utils.slugify`-ed version of the input artifact's name. The first file in this directory is a
verbose log of remap's execution. The second is a JSON file, typically named ``remapping.txt``, of the following
format::

    {
        "python_version": "<version_str>",
        "method": "<method_name>",
        "command line": "<command_line>"
        "remapped_opcodes": [
            {
                "opcode": "<original_opcode_value>",
                "opname": "<operation_name>",
                "remapped_value": "<new_opcode_value>",
                "guess": "<bool>"
            },
            ...
        ]
    }

If a ``remapping.txt`` file already exists in the output directory, then the file will have a monotonically increasing
integer appended to it (remapping-1.txt, remapping-2.txt, etc.). The bracketed values in the above code block are better
described here:

:`version_str`: This string denotes the opmap's Python version. It can be `any Python version supported by xdis`_.
:`method_name`: This is one of `standard_bytecode_diff`, `megafile_diff`, `opcode_pyc_constants`, if this file was
                produced by remap. It can also be something else entirely, if the opmap was created by a multitude
                of methods, by hand, etc. It is not parsed by pydecipher, and only servers as a reference to future
                analysts using this file
:`command_line`: The command line, if any, that produced this file. Reference only; not parsed by pydecipher.
:`original_opcode_value`: The opcode for this bytecode operation according to an unmodified Python interpreter
                          (of the version specified by `version_str`).
:`operation_name`: The operation name corresponding to the original opcode.
:`new_opcode_value`: The new, remapped value for this operation.
:`guess`: remap will only produce complete opmaps with 1:1 pairings of opnames and opcodes, so if we can't figure out
          the remapped value of an opcode using one of the methods above, we must guess. If this value is True, that
          means this pairing is a guess. This is not parsed by pydecipher.

pydecipher will only accept a remapping file that has a complete set of opcodes for the specified version. Run remap
with the ``--check-remapping`` flag to determine if a opcode map is valid and supported by pydecipher.

.. _any Python version supported by xdis: https://github.com/rocky/python-xdis/blob/master/xdis/magics.py
.. _opcode.py: https://github.com/python/cpython/blob/master/Lib/opcode.py
.. _slugify:
.. automodule:: pydecipher.remap
    :members:
    :private-members:
    :noindex:
