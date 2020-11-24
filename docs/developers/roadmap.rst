#######
Roadmap
#######

Here are some ideas on how to improve the tool, if you would like to contribute.

    * Add support for Macho-O/ELF artifact types.

      * How to guide for writing a new parser.

    * Add a ``--no-decompile`` option for pydecipher to just extract bytecode without attempting to decompile.

    * Add man page

    * Look into the possibility of using decompile-3 for Python 3.7 or later bytecode: https://github.com/rocky/python-decompile3.

    * Add bug report templates

    * Windows/cross platform check

    * Look into poetry for package management

    * Improve testing

      * Unit tests

      * More tests for certificate extraction in pe artifact code.

      * Implement coverage tracking

    * CI/CD for

      * Linting code

      * Running integration tests

      * Running unit tests

    * Set up readthedocs for pydecipher's documentation

    * More comprehensive user-guide, including one exclusively dedicated to ``remap``
