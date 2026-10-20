# ENA definitions (third-party)

These headers are copied unchanged from the Amazon ENA drivers repository:

- Source: https://github.com/amzn/amzn-drivers, `kernel/fbsd/ena/ena-com/ena_defs/`
- Commit: 9d5ca4021f7c9f8421e404c1e89edb0b1325372c (2026-10-14)
- License: BSD-3-Clause, Copyright (c) 2015-2023 Amazon.com, Inc. or its affiliates
  (the full license text is at the top of each file)

`../ena.c` (mtabe19/qedos fork) defines `GENMASK()` before including them, as `ena_plat.h` of the
same source does.
