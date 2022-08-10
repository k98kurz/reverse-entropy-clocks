# Reverse Entropy Clock

This module uses sha256 to implement a reverse entropy logical clock; i.e. a
hash lock clock. This is a generalization of the hashlock used in Bitcoin UTXO
locking scripts and logical clocks as invented by Leslie Lamport.

## Overview

@todo

## Status

- [ ] @todo

## Installation

Currently, this project is still in development, so the best way to install is
to clone the repo and then run the following from within the root directory
(assuming a Linix terminal):

```
python -m venv venv/
source venv/bin/activate
pip install -r requirements.txt
```

On Windows, you may have to run `source venv/Scripts/activate` instead
of `source venv/bin/activate`.

These instructions will change once development is complete and the module is
published as a package.

## Classes and Interfaces

@todo

## Examples

@todo

## Tests

Open a terminal in the root directory and run the following:

```
cd tests/
python -m unittest
```

## ISC License

Copyleft (c) 2022 k98kurz

Permission to use, copy, modify, and/or distribute this software
for any purpose with or without fee is hereby granted, provided
that the above copyleft notice and this permission notice appear in
all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
