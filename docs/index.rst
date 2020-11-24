############################################################
pydecipher: unfreeze and deobfuscate your frozen python code
############################################################

What is pydecipher?
-------------------

pydecipher is a Python package to unpack/unfreeze and analyze :ref:`frozen <what-is-python-freezing>` Python artifacts with the ultimate goal of producing the artifact's underlying, high-level, Python source code.

pydecipher can be used as a direct replacement for tools like |unpy2exe| and |pyinstxtractor|, and as an alternative to |pyREtic| for situations where you need to analyze opcode-obfuscation and have the compiled Python files on disk (as opposed to live Python objects in memory). Currently, pydecipher supports the analysis of PE files, |PyInstaller| artifacts, |Py2Exe| artifacts, individual bytecode files (.pyc), and zip files of Python bytecode files.


How do I use pydecipher?
------------------------

pydecipher can be run on the command line in Python 3.8 or newer environments on macOS and Linux. Windows should also theoretically be supported, but it has not been tested thoroughly yet.

.. code-block:: console

    $ pydecipher example.exe
    [*] Unpacking /home/user/example.exe
    [+] Dumped this PE's overlay data to pydecipher_output_example/overlay_data
    [*] Unpacking /home/user/pydecipher_output_example/overlay_data
    [!] Potential entrypoint found at script example_main.py
    [*] Unpacking /home/user/pydecipher_output_example/overlay_data_output/PYZ-00.pyz
    [+] Successfully extracted 133 files from this ZlibArchive.
    [+] Successfully extracted 7 files from this CArchive.
    [+] Successfully decompiled 6 .pyc files.

For more examples, see the :doc:`User Guide </user_guide>`. Additionally, it can be run from other Python code by importing the relevant parts of the :doc:`API </api>`.

During execution, pydecipher will recursively search the input artifact for Python bytecode, dump that bytecode using |xdis| and attempt to
convert any dumped bytecode to high-level Python source code using |uncompyle6|. For example, the output directory of the example above looks
like this:

.. code-block:: console

    $ tree pydecipher_output_example/ -L 2
    pydecipher_output_example/
    ├── log_18_18_33_Dec_04_2019.txt
    ├── overlay_data
    └── overlay_data_output
        ├── PYZ-00.pyz
        ├── pyiboot01_bootstrap.py
        ├── pyiboot01_bootstrap.pyc
        ├── pyimod01_os_path.py
        ├── pyimod01_os_path.pyc
        ├── pyimod02_archive.py
        ├── pyimod02_archive.pyc
        ├── pyimod03_importers.py
        ├── pyimod03_importers.pyc
        ├── pyz-00_output
        ├── struct.py
        ├── struct.pyc
        ├── example_main.py
        └── example_main.pyc
    2 directories, 15 files

pydecipher also implements certain deobfuscation techniques on any recovered bytecode. Basic tampering with bytecode file
headers can be automatically reversed in pydecipher's processing pipeline. Additionally, bytecode that has been produced with
a custom interpreter that has remapped its opcodes can be studied using pydecipher's  :doc:`remap </api/remap>` module.

.. _what-is-python-freezing:

What is Python freezing?
-------------------------

To 'freeze' Python code is to take Python source code and package it with a Python interpreter, typically bundled into a single executable binary (PE, ELF, Mach-O, etc.).

There are several different tools that can be used to freeze Python code. As of pydecipher's initial writing (2019), |PyInstaller| is the most popular and best-maintained. It is also cross-platform, working on Windows, macOS, and Linux. Some other commonly used freezers are |Py2Exe| (Windows), |py2app| (macOS), |cx_Freeze| (cross-platform) and |bbFreeze| (cross-platform). The primary reason Python code is frozen is so developers do not have to rely on end-users' systems to have the right version of Python installed (or any version at all) in order to run Python code. Python-freezing tools have also `lowered the bar for malware development`_.

.. _lowered the bar for malware development: https://www.reddit.com/r/HowToHack/comments/ejab1r/how_can_you_write_viruses_in_certain_languages_id/fcwicme/

For a full overview on Python freezing, check out python-guide.org's `primer on freezing`_.

.. _primer on freezing: https://docs.python-guide.org/shipping/freezing/


Why was pydecipher created?
---------------------------

Python's increasing popularity, combined with the advent of freezing tools, has led to an increase in Python-based malware. There are existing open-source tools that handle the different stages of analyzing these frozen Python binaries (extraction vs. disassembly vs. deobfuscation vs. decompilation), however many of those tools are no longer maintained, have cumbersome set-up processes, only work within a narrow range of Python versions, or generally leave other things to be desired. pydecipher aims to be the quickest possible solution for a reverse-engineer to recover Python source code by handling and automating as many of those analysis stages as possible.

.. toctree::
    :caption: Navigation
    :hidden:
    :maxdepth: 1

    installing
    User Guide <user_guide>
    development
    changelog
    contact
    credits

API
---

If you are importing pydecipher for use in another project, or just want to peek under the hood to understand how the
tool works, you can view the auto-generated API documentation :doc:`here </api>`.

    .. toctree::
        :name: API
        :caption: API
        :hidden:

        Overview <api>
        __init__ <api/init>
        main <api/main>
        bytecode <api/bytecode>
        utils <api/utils>
        remap <api/remap>
        artifact_types <api/artifact_types>
