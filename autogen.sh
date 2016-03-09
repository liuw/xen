#!/bin/sh -e
autoconf -f
( cd tools
  autoconf -f
  autoheader
)
( cd docs
  autoconf -f
)
