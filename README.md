# Build-recorder

The purpose of this project is
to fully record the interactions
between assets (files and tools)
when a software artifact is being built (compiled).

## License

The code is licensed under
GNU Lesser General Public License v2.1 or later
(`LGPL-2.1-or-later`).

## Development

Requirements: [GNU Autotools](https://en.wikipedia.org/wiki/GNU_Autotools),
GNU Make, and a C compiler like GCC.

Building:
```sh
$ aclocal
$ autoheader
$ autoconf
$ automake --add-missing
$ autoconf
$ ./configure
$ make
```

NOTE: Can use `autoreconf` as well for building.