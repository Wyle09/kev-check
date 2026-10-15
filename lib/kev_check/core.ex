defmodule KevCheck.Core do
  @moduledoc """
  Pure functions. Data in, data out. No I/O.

  `CveId` checks the shape of an ID, `Entry` is one vulnerability from CISA's
  feed, and `Catalog` parses the feed and answers lookups.
  """

  use Boundary, type: :strict, deps: [], exports: [CveId, Entry, Catalog]
end
