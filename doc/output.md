# build-recorder output format

Each run of `build-recorder` generates a single output file.

The information is represented in RDF triples,
saved in Turtle format.

## Ontology

The special types and predicates used are listed below:

### Types

#### Process
- pid: the process id
- cmd: the actual command line (concatenation of all arguments separated by white space)
- start: timestamp
- end: timestamp
- env: environment entry, in the form of "VAR=value"



#### File
- name: the file name
- size: the file size, in bytes
- hash: a hexadecimal string of a unique, git-compatible, hash of the content of the file
- abspath: the file's absolute file



### Relationships

#### execs
- Domain: Process
- Range: Process

#### reads
- Domain: Process
- Range: File

#### writes
- Domain: Process
- Range: File

#### creates
- Domain: Process
- Range: Process

#### executable
- Domain: Process
- Range: File



## Example

The example below is fictional
and is only to be used to represent typical uses.

The example is about a fictional compiler (`compile`),
called to compile a single file (`foo.c`).
The compiler calls a preprocesor (`preprocess`)
to generate a temporary file (`tmp.c`)
and then generate the object code in (`foo.o`)

```
pid1	a	process .
pid1	cmd	"compile -o foo.c" .
pid1	start	20220804T100000 .

pid2	a	process .
pid2	cmd	"preprocess foo.c tmp.c"
pid2	start	20220804T100000 .

pid1	execs	pid2 .

f1	a	file .
f1	name	"foo.c" .
f1	size	100 .
f1	hash	"0000000000000000000000000000000000000000" .

f2	a	file .
f2	name	"tmp.c" .
f2	size	888 .
f2	hash	"1111111111111111111111111111111111111111" .

pid2	reads	f1 .
pid2	writes	f2 .

pid3	a	process .
pid3	cmd	"c2o tmp.c foo.o" .

pid1	execs	pid3 .
pid3	reads	f2 .

f3	a	file .
f3	name	"foo.o" .
f3	size	444 .
f3	hash	"2222222222222222222222222222222222222222" .

pid3	writes	f3 .

```

The example is simplified on purpose,
since it does not show, for example,
the reading of the file of the executable "preprocess".

