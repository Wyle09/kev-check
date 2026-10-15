defmodule KevCheck do
  @moduledoc """
  Answers one question: is this CVE on CISA's Known Exploited Vulnerabilities catalog?

  Pure parsing and lookup live under `Core`. Everything else here holds state or
  talks to the outside world.
  """

  use Boundary, deps: [], exports: [{Core, []}]
end
