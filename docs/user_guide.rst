==========
User Guide
==========

Using pydecipher from the command line
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The syntax of the ``pydecipher`` command is:

    ``pydecipher`` *[options] python_artifact*

In the most simple case, set the current directory to the location of the Python artifact you want to examine, and execute:

.. code-block:: console

    $ pydecipher my_artifact.exe

.. note::

    If you get lazy, you can also type the command ``melt`` as a replacement for ``pydecipher``.

During execution, pydecipher will

    - recursively search the given artifact for frozen Python file formats and data structures
    - write any Python bytecode contained within the artifact to the output directory
    - process any extracted bytecode through uncompyle6_ to produce high-level Python source code
    - perform any clean-up functions needed
    - verbosely log output to a log file in the output directory

.. _uncompyle6: https://github.com/rocky/python-uncompyle6

Options
~~~~~~~

+--------------------------+----------------------------------------+----------------------------------+
| **Short Flag**           |     **Long Flag**                      |     **Description**              |
+==========================+========================================+==================================+
|  -h                      |  --help                                |  Show a help message and exit.   |
+--------------------------+----------------------------------------+----------------------------------+
|  -V                      |  --version                             |  Show the version number and     |
|                          |                                        |  exit.                           |
+--------------------------+----------------------------------------+----------------------------------+
|  -q                      |  --quiet                               |  Suppress all stdout/err output. |
+--------------------------+----------------------------------------+----------------------------------+
|  -v                      |  --verbose                             |  Show verbose output.            |
+--------------------------+----------------------------------------+----------------------------------+
|  -d                      |  --decompile-all                       |  Decompile all pyc files in      |
|                          |                                        |  addition to the top-level files |
|                          |                                        |  found in each artifact.         |
+--------------------------+----------------------------------------+----------------------------------+
|  -o <path>               |  --output <path>                       |  Location for the                |
|                          |                                        |  ``pydecipher_output_*``         |
|                          |                                        |  directory (defaults to current  |
|                          |                                        |  working directory).             |
+--------------------------+----------------------------------------+----------------------------------+
|                          |  --version-hint <version>              | The version of Python used to    |
|                          |                                        | freeze the artifact, if known.   |
|                          |                                        |                                  |
|                          |                                        |                                  |
+--------------------------+----------------------------------------+----------------------------------+
| -r <remapping JSON file> | --remapping-file <remapping JSON file> | The path to the remapping JSON   |
|                          |                                        | file that contains the opmap     |
|                          |                                        | for this artifact's bytecode.    |
|                          |                                        |                                  |
+--------------------------+----------------------------------------+----------------------------------+

Example Usages
~~~~~~~~~~~~~~

Simple use-case:

.. code-block:: console

    $ pydecipher evil.exe

More advanced use-case, where the output directory gets placed on the user's desktop and all pyc files found within sample.zip get decompiled:

.. code-block:: console

    $ pydecipher --decompile-all --output ~/Desktop sample.zip

.. warning::
    ⚠️ The ``--decompile-all`` flag may increase the run-time of pydecipher, especially if a lot of Python bytecode is discovered within the artifact being analyzed.

.. _docker-run:

Using the pydecipher Docker container
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. note::
    This section assumes the pydecipher container already exists in your Docker environment, either from pulling it from a Docker registry like Dockerhub, or :ref:`docker-build`.

pydecipher can be run without a Python environment through use of its Docker container. The container's working directory (and consequently, default pydecipher output directory) is the ``/root`` directory, so you will need to map a local directory as a bind-mount volume into this destination in the container to retrieve output. All program options are the same as the command line use-case.

.. code-block:: console

    $ docker run -v $(pwd):/root/ pydecipher sample.exe

If you built the pydecipher image locally, and you named it something besides *pydecipher*, you will need to change the above example to use your image name.

Running pydecipher from code
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

pydecipher can be run from within Python code by importing the :meth:`pydecipher.main.run` function and passing the command line arguments in as a list:

.. code-block:: python

    #! /usr/bin/env python3

    import pydecipher.main

    pydecipher.main.run([
        '--decompile-all',
        '--verbose',
        'example.exe'
    ])

Alternatively, you can read the :doc:`API </api>` and import only the exact parts of pydecipher you need. For example, if you only wanted to extract the bytecode from an artifact - but not decompile the bytecode into source code - you could import the :meth:`pydecipher.main.unpack` function.
