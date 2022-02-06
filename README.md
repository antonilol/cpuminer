Stripped down sha256d-only version of pooler/cpuminer


#### Usage:
```
./minerd <blockheader>
```

Stats are logged to `stderr`, the valid block header (if found) to `stdout`.

#### Compiling:
```
./autogen.sh
./nomacro.pl
./configure CFLAGS="-O3"
make
```

For more platform specific build instructions/notes, see [pooler/cpuminer](https://github.com/pooler/cpuminer)'s README

#### License

GPLv2
