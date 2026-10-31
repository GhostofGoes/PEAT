# Woodward test data

- `tunables_synthetic.tc`: a **synthetic** Control Assistant tunable file, hand written to
  match the layout PEAT's parser expects (three metadata lines, a `Mode` column header, and
  tab-separated rows). No public example of a real `.tc` file is available. It is not from
  a real control, and the block and field names are made up.
- `*.wset`, `*.sid`, and `*.wtool` fixtures are built at test time by `nrbf_builder.py`
  (synthetic .NET serialization streams and ToolKit container headers), or taken from
  `examples/devices/woodward/` (a real easYgen-3500 settings file, stored gzip compressed).
