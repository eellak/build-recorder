# Build-recorder

The purpose of this project is
to fully record the interactions
between assets (files and tools)
when a software artifact is being built (compiled).

## Usage
**build-recorder** [-o outfile] command
* outfile: The output file, by default "build-recorder.out".
* command: The original build command with all its arguments.
    * e.g. cc -o hello helloworld.c 

## Description
**build-recorder** is a command line tool for linux 5.3+ that records
information about build processes. It achieves this by running transparently
in the background while the build process is running, tracing it
and extracting all relevant information, which it then stores in the output
file in RDF Turtle format.

A complete schema for the generated RDF can be found in docs/output.md.

**build-recorder** works regardless of the programming language, build system
or configuration used. In fact there is no limitation as to what the supplied 
command should be. If it runs, **build-recorder** can trace it.

## Build
To build it you are going to need the following tools:
* A C compiler
* make

As well as the following libraries:
* libcrypto
### Build from github repository
In order to build from the github repository directly, you are also going
to need
* autoconf
* automake

On the project's top-level directory, run:
```
autoreconf -i
./configure
make
```

### Build from release tarball
Assuming you've downloaded the tarball:
```
tar -xf <build-recorder-release>.tar.gz
cd <build-recorder-release>
./configure
make
```

## License

The code is licensed under
GNU Lesser General Public License v2.1 or later
(`LGPL-2.1-or-later`).

