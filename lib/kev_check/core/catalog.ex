defmodule KevCheck.Core.Catalog do
  @moduledoc """
  CISA's Known Exploited Vulnerabilities catalog: parse the JSON feed and answer lookups.

  A feed that is empty or has any entry we can't read is rejected whole, so a
  refresh never swaps a good catalog for a partial one.
  """

  alias KevCheck.Core.CveId
  alias KevCheck.Core.Entry

  @type t :: %__MODULE__{
          version: String.t(),
          released_at: DateTime.t(),
          entries: %{CveId.t() => Entry.t()}
        }

  @type answer :: %{
          cve_id: CveId.t(),
          known_exploited: boolean(),
          entry: Entry.t() | nil,
          catalog_version: String.t()
        }

  @enforce_keys [:version, :released_at, :entries]
  defstruct @enforce_keys

  @doc "Decode the feed's JSON into a catalog, or reject it."
  @spec parse(binary()) :: {:ok, t()} | {:error, :invalid_catalog}
  def parse(json) when is_binary(json) do
    with {:ok,
          %{"catalogVersion" => version, "dateReleased" => released, "vulnerabilities" => items}}
         when is_binary(version) and is_binary(released) and is_list(items) and items != [] <-
           JSON.decode(json),
         {:ok, released_at, _offset} <- DateTime.from_iso8601(released),
         {:ok, entries} <- entries(items) do
      {:ok, %__MODULE__{version: version, released_at: released_at, entries: entries}}
    else
      _unusable -> {:error, :invalid_catalog}
    end
  end

  @doc "Say whether `cve_id` is on the catalog, with its entry when it is."
  @spec answer(t(), CveId.t()) :: answer()
  def answer(%__MODULE__{entries: entries, version: version}, cve_id) do
    entry = Map.get(entries, cve_id)
    %{cve_id: cve_id, known_exploited: entry != nil, entry: entry, catalog_version: version}
  end

  @doc "Seconds from the catalog's release to `now`, never negative."
  @spec age_seconds(t(), DateTime.t()) :: non_neg_integer()
  def age_seconds(%__MODULE__{released_at: released_at}, now),
    do: max(DateTime.diff(now, released_at), 0)

  @doc "How many vulnerabilities the catalog holds."
  @spec size(t()) :: non_neg_integer()
  def size(%__MODULE__{entries: entries}), do: map_size(entries)

  defp entries(items) do
    Enum.reduce_while(items, {:ok, %{}}, fn item, {:ok, acc} ->
      case Entry.from_map(item) do
        {:ok, entry} -> {:cont, {:ok, Map.put(acc, entry.cve_id, entry)}}
        {:error, :invalid_entry} = error -> {:halt, error}
      end
    end)
  end
end
