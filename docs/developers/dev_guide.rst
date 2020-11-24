.. _dev-guide:

#################
Developer's Guide
#################

The Python environment
----------------------

The first part of setting up your development environment is to ensure you have Python installed. pydecipher requires Python 3.8 or newer, and we recommend using the latest stable version of Python that has been released. Ultimately, how you set up your development environment is up to you, but the following instructions can serve as a guideline for someone who doesn't already have their own preferences.

.. attention::

    The following instructions apply to macOS/\*nix platforms. If you will be developing on Windows, you're on your own. And if you'd like to share your workflow, please feel free to contribute a Windows environment set-up guide!

1. Install pyenv_ to manage your system's python environment more easily and reliably than using apt/brew/whatever package manager your OS uses.
2. Install pyenv-virtualenv_ to create and manage virtual environments within pyenv.
3. Run ``pyenv install 3.8.2``, or whatever is the latest stable release of Python.
4. Create a virtual environment for pydecipher development with ``pyenv virtualenv 3.8.2 pydecipher``

.. _pyenv: https://github.com/pyenv/pyenv
.. _pyenv-virtualenv: https://github.com/pyenv/pyenv-virtualenv

Installing the package for development
--------------------------------------

1. Clone the repository:

    .. code-block:: console

        $ git clone <pydecipher-url>


2. (*Optional*) If you are using pyenv-virtualenv to manage a pydecipher development virtual environment, enter the code directory you just cloned and run:

    .. code-block:: console

        $ pyenv local pydecipher     # or whatever you named your virtual environment

  This will drop a ``.python-version`` file in the root level of your pydecipher directory, enabling pyenv to automatically activate the environment whenever your current working directory is set to the pydecipher directory, or any of its subdirectories.

3. Ensure you are in the correct python environment, and then run the ``pip install`` command with the *--editable* flag:

    .. code-block:: console

        $ pip install -e .[dev]

4. Check that pydecipher installed correctly by running:

    .. parsed-literal::

        $ pydecipher -V
        pydecipher |pydecipher_version|

5. Install pre-commit_:

    .. code-block:: console

        $ pre-commit install

.. _pre-commit: https://pre-commit.com/

.. _docker-build:

Building the Docker container
-----------------------------


In order to build the Docker image, you will need to first clone the repository. After cloning the repository, change directory into the root directory of your working copy of the repository (the directory containing the Dockerfile), and run the following command to build the Docker image.

    .. code-block:: console
        :linenos:

        $ docker build -t pydecipher .


After the Docker image is built, pydecipher can be run from within a Docker container by following the directions in :ref:`docker-run`. If changes to the code have been made, but are seemingly not appearing in the container, rebuilding the image using the ``--no-cache`` argument will build the image from scratch without using any cached image layers.


Style and formatting
--------------------

All code should be run through black_ before submitting a PR. See the pyproject.toml file in the root of the directory to see our black configuration. For things that black doesn't account for (naming conventions, import conventions, etc), please attempt to follow existing conventions in the codebase and PEP8_ to the best of your ability (in that order).

Versioning
----------

We follow `PEP 440`_-versioning (by way of bump2version_) to maintain the version number through all code and documentation. We differ from PEP 440 guidelines in that our pre-release versions don't have an *alpha* build, and we don't use X.Y as shorthand for X.Y.0. Our versions go as follows:

==================  ================
**Version Format**  **Release Type**
------------------  ----------------
X.Y.Zb              Beta release
X.Y.Zrc             Release Candidate
X.Y.Z               Final release
==================  ================

Generally, releases should go from beta to release candidate, and release candidate to final. The following ``bump2version`` commands can be used to follow this format.

    .. code-block:: console

        $ bump2version release                          # 1.0.0b → 1.0.0
        $ bump2version patch                            # 1.0.0 → 1.0.1b
        $ bump2version minor                            # 1.0.1b → 1.1.0b
        $ bump2version patch --new-version 1.1.0rc      # 1.1.0b → 1.1.0rc
        $ bump2version patch --new-version 1.1.0        # 1.1.0rc → 1.1.0
        $ bump2version major                            # 1.1.0 → 2.0.0b

The ``bump2version`` command will tag a commit, but you can use the ``--verbose`` and ``--dry-run`` flags to prevent this and see what exactly will be changed before deciding if you actually want to run the ``bump2version`` command.

    .. code-block:: console

        $ bump2version --verbose --dry-run patch
        ['patch']
        current_version=1.0.0
        commit=True
        tag=False
        files=pydecipher/__init__.py
        parse=(?P<major>\d+)\.(?P<minor>\d+)(\.(?P<patch>\d+))?(?P<release>[a-z]+)?
        serialize=
        {major}.{minor}.{patch}{release}
        {major}.{minor}.{patch}
        {major}.{minor}
        new_version=1.0.1b

For more on versioning, read `this Medium article <https://medium.com/@vladyslav.krylasov/implement-versioning-of-python-projects-according-to-pep-440-af952199eb30>`__ about PEP440 and bumpversion.

.. _black: https://pypi.org/project/black/
.. _PEP8: https://www.python.org/dev/peps/pep-0008/
.. _PEP 440: https://www.python.org/dev/peps/pep-0440
.. _bump2version: https://pypi.org/project/bump2version/

Git
---

Commits
_______

Commits should have a short, descriptive title, and a body that explains the *why* behind the commit. Each logical change in the code should be placed in its own commit, without extraneous changes (fixing a typo in a totally unrelated file). For more on writing good commit messages, see the `PyInstaller developer's guide <https://pyinstaller.readthedocs.io/en/stable/development/commit-messages.html#please-write-good-commit-messages>`__.

Tags
____

Each version release on the master branch will receive a tag with the format v<version_number>. This includes beta and release candidate versions. For example, 1.0.0 has the tag v1.0.0.

Branches
________

We follow Vincent Driessen's git branching model as described `in this blog post <https://nvie.com/posts/a-successful-git-branching-model>`__.

        :`develop` branch: origin/develop is the main development branch where HEAD's source code is at a semi-stable state, waiting to be included in the next release.
        :`master` branch: origin/master is the release branch, where each commit considered a new release version. This includes beta and release candidates versions.
        :`release/` branches: These branches only appear when a new version is in the process of being released. They serve as a staging ground for the release workflow.
        :`hotfix/` branches: These branches are for urgent, unplanned production releases.
        :`feature/` branches: Feature branches are used to develop new features, and upon completion, get merged into `develop`.

Merge/Pull Requests
___________________

To create a pull request, first fork the repository and clone the fork's code:

    .. code-block:: console

        $ git clone <pydecipher_repo_url>
        $ cd pydecipher

Now, create a branch:

    .. code-block:: console

        $ git checkout -b feature/my-new-feature

Make your changes! Upon completion, please make sure you are still :ref:`passing the tests <testing>`. If possible, test on all platforms. Additionally, make sure to add an appropriate change-file to the ``docs/changes`` directory. See the :ref:`changelog guidelines <changelog-guidelines>` for more details. After adequate testing and documentation, synchronize your fork with the pydecipher upstream repository through a rebase or merge.

   1. Rebase your changes on the current development head.

    .. code-block:: console

        $ git remote add upstream <pydecipher_repo_url>
        $ git checkout feature/my-new-feature
        $ git pull --rebase upstream develop

   2. Merge the current development head into your changes:

    .. code-block:: console

        $ git remote add upstream <pydecipher_repo_url>
        $ git fetch upstream develop
        $ git checkout feature/my-new-feature
        $ git merge upstream/develop

Push your changes up to your fork:

    .. code-block:: console

        $ git push

Lastly, open the *Merge Requests* page at <pydecipher_repo_url> and click “new merge request”.

.. _changelog-guidelines:

Changelog and towncrier
-----------------------

We use `towncrier <https://github.com/hawkowl/towncrier>`__ to keep track of our changelog. With each pull request, please include a reStructuredText file of the format *issue_number.category*.rst. The issue number corresponds to the issue on GitHub, and the category is one of the following standard towncrier categories:

=============  ================
**File Ext.**   **Description**
-------------  ----------------
.feature        New features
.bugfix         Bug fix
.doc            Documentation improvement
.removal        Deprecation/removal of public API
.misc           Issue closed, but not of interest to users
=============  ================

For example, if you were submitting a pull request for a new feature that adds support for FooBar-frozen Python artifacts (issue #1337 on GitHub), your file ``1337.feature.rst`` would have the following contents:

.. code-block:: rst

        Added capability to extract source code from FooBar-frozen Python binaries.

Documentation
-------------

New modules should be documented with numpy style doc-strings.

.. _testing:

Testing
-------

Before merging new code, ensure that all the integration tests pass by using pytest in the tests/ directory. As xdis/uncompyle6 improve and get better at decompiling Python bytecode, some of the tests may fail because they are expecting a certain exact amount of files to be decompiled. If the tests fail because more files are present, then those numbers in the tests should be increased due to reflect the new counts.


To run some of the integration tests, test files that are not included in this repository are required. The test files and their respective SHA256 hashes are shown in the table below.

+-------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Filename (relative to tests/test_data/)         | SHA256                                                                                                                                                                                |
+=================================================+=======================================================================================================================================================================================+
| py2exe/py2exe_23                                | `7562c17e1886e4841950a18bb0a5e3134e756f69a1ea0ece4e7a947b2683e710 <https://www.virustotal.com/gui/file/7562c17e1886e4841950a18bb0a5e3134e756f69a1ea0ece4e7a947b2683e710/detection>`__ |
+-------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| py2exe/py2exe_24                                | `af47b2da6aea5c7a7b3e19f8470c07267ccac8cc8eeb4ad1bc10fbea0d71888b <https://www.virustotal.com/gui/file/af47b2da6aea5c7a7b3e19f8470c07267ccac8cc8eeb4ad1bc10fbea0d71888b/detection>`__ |
+-------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| py2exe/py2exe_25                                | `cb374e12f7b465985f8fdb75a6eff9065a8b7162b3cf6bdd9e47b3dbefd97235 <https://www.virustotal.com/gui/file/cb374e12f7b465985f8fdb75a6eff9065a8b7162b3cf6bdd9e47b3dbefd97235/detection>`__ |
+-------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| py2exe/py2exe_26                                | `089f234e111f41c0f907e7d8b7dca7d4473bc2b30072dc6b4804e86e9a19aedb <https://www.virustotal.com/gui/file/089f234e111f41c0f907e7d8b7dca7d4473bc2b30072dc6b4804e86e9a19aedb/detection>`__ |
+-------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| py2exe/py2exe_27                                | `9a2f37a4f90945451774ad3ea69281e5056843f0fc7fe9abc1c5d0ff3706f448 <https://www.virustotal.com/gui/file/9a2f37a4f90945451774ad3ea69281e5056843f0fc7fe9abc1c5d0ff3706f448/detection>`__ |
+-------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| py2exe/py2exe_33                                | `5bfd86b9a6c58c2799e7e51990b25b21ff8214d1041a8924edf9e2c4f033c620 <https://www.virustotal.com/gui/file/5bfd86b9a6c58c2799e7e51990b25b21ff8214d1041a8924edf9e2c4f033c620/detection>`__ |
+-------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| py2exe/py2exe_34                                | `3aa44916e758d653f9664a18292dbd0179a747f7decfd02a013a9ca5241427fe <https://www.virustotal.com/gui/file/3aa44916e758d653f9664a18292dbd0179a747f7decfd02a013a9ca5241427fe/detection>`__ |
+-------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| py2exe/py2exe_35                                | `a7a2269db0b90815390b8986b706212647506dfb988798b937ebf1b92e188d41 <https://www.virustotal.com/gui/file/a7a2269db0b90815390b8986b706212647506dfb988798b937ebf1b92e188d41/detection>`__ |
+-------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| py2exe/py2exe_36                                | `30925f55040295b1d2a70e4257b6a69897075554d9cf17ee84e9ba8b85625b82 <https://www.virustotal.com/gui/file/30925f55040295b1d2a70e4257b6a69897075554d9cf17ee84e9ba8b85625b82/detection>`__ |
+-------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| pyinstaller/pyinstaller_25                      | `04a3721bb28fc63aac4e53207ebfda270f0bcd442a87ee4e0eaff62bd169963c <https://www.virustotal.com/gui/file/04a3721bb28fc63aac4e53207ebfda270f0bcd442a87ee4e0eaff62bd169963c/detection>`__ |
+-------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| pyinstaller/pyinstaller_26                      | `96687dd580595875304498148cb1953a851c2e921bdfc3e836910c155c8c5418 <https://www.virustotal.com/gui/file/96687dd580595875304498148cb1953a851c2e921bdfc3e836910c155c8c5418/detection>`__ |
+-------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| pyinstaller/pyinstaller_27                      | `e50c253d08001490f9a2850ca8b2054be1503bf6efffe799c9aa12f880cf264f <https://www.virustotal.com/gui/file/e50c253d08001490f9a2850ca8b2054be1503bf6efffe799c9aa12f880cf264f/detection>`__ |
+-------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| pyinstaller/pyinstaller_33                      | `879fece71f5072a847772c94a80d7e76b83648ce11c328f6dd394634f7fd9d1f <https://www.virustotal.com/gui/file/879fece71f5072a847772c94a80d7e76b83648ce11c328f6dd394634f7fd9d1f/detection>`__ |
+-------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| pyinstaller/pyinstaller_34                      | `271ba0f829f2260c7e767e3ea42dca51f900336e82d859c08ca525d8067734f1 <https://www.virustotal.com/gui/file/271ba0f829f2260c7e767e3ea42dca51f900336e82d859c08ca525d8067734f1/detection>`__ |
+-------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| pyinstaller/pyinstaller_35                      | `65d4a2daa6a6e65bfef08b797f39b2342bb1d6d052d7dd74f680ad9ceb046870 <https://www.virustotal.com/gui/file/65d4a2daa6a6e65bfef08b797f39b2342bb1d6d052d7dd74f680ad9ceb046870/detection>`__ |
+-------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| pyinstaller/pyinstaller_36                      | `5d2677c7376b128813a15ce3e56f4badb9a4a1a88e2d536099e4ba1770bc39ba <https://www.virustotal.com/gui/file/5d2677c7376b128813a15ce3e56f4badb9a4a1a88e2d536099e4ba1770bc39ba/detection>`__ |
+-------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| obfuscated_opcodes/pyxie_rat/pyxie_bytecode_zip | `d1429f54baaad423a8596140a3f70f7d9f762373ad625bda730051929463847d <https://www.virustotal.com/gui/file/d1429f54baaad423a8596140a3f70f7d9f762373ad625bda730051929463847d/detection>`__ |
+-------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| obfuscated_opcodes/pyxie_rat/pyxie_interpreter  | `8d2b3b0cbb32618b86ec362acd142177f5890917ae384cb58bd64f61255e9c7f <https://www.virustotal.com/gui/file/8d2b3b0cbb32618b86ec362acd142177f5890917ae384cb58bd64f61255e9c7f/detection>`__ |
+-------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| zip/triton                                      | `bef59b9a3e00a14956e0cd4a1f3e7524448cbe5d3cc1295d95a15b83a3579c59 <https://www.virustotal.com/gui/file/bef59b9a3e00a14956e0cd4a1f3e7524448cbe5d3cc1295d95a15b83a3579c59/detection>`__ |
+-------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

