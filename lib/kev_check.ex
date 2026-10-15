defmodule KevCheck do
  @moduledoc """
  Answers one question: is this CVE on CISA's Known Exploited Vulnerabilities catalog?

  Pure parsing and lookup live under `Core`. Everything else here holds state or
  talks to the outside world: `Lookup` runs one check inside a telemetry span,
  `LookupLog` writes its log line, `Faults` holds the demo knobs, and
  `Catalog.Store` keeps the catalog in memory and refreshes it.
  """

  use Boundary,
    deps: [Req],
    exports: [{Core, []}, Lookup, LookupLog, Faults, Catalog.Store]
end
