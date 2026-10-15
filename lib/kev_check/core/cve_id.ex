defmodule KevCheck.Core.CveId do
  @moduledoc """
  Checks that an ID is shaped like `CVE-2021-44228` and returns it in canonical form.
  """

  @type t :: String.t()
  @type reason :: :missing_id | :invalid_format | :year_out_of_range

  # The CVE program started assigning IDs in 1999.
  @first_year 1999
  # The cveId pattern from the CVE JSON record schema.
  @pattern ~r/\ACVE-([0-9]{4})-[0-9]{4,19}\z/

  @doc "Trim and upcase `raw`, then accept it if it names a year from 1999 through `current_year`."
  @spec parse(term(), Calendar.year()) :: {:ok, t()} | {:error, reason()}
  def parse(nil, _current_year), do: {:error, :missing_id}

  def parse(raw, current_year) when is_binary(raw) do
    raw
    |> String.trim()
    |> String.upcase()
    |> match(current_year)
  end

  def parse(_raw, _current_year), do: {:error, :invalid_format}

  @doc "True when `id` is already canonical, the way CISA's feed writes it."
  @spec canonical?(String.t()) :: boolean()
  def canonical?(id) when is_binary(id), do: Regex.match?(@pattern, id)

  defp match("", _current_year), do: {:error, :missing_id}

  defp match(id, current_year) do
    case Regex.run(@pattern, id, capture: :all_but_first) do
      [year] -> in_range(id, String.to_integer(year), current_year)
      nil -> {:error, :invalid_format}
    end
  end

  defp in_range(id, year, current_year) when year >= @first_year and year <= current_year,
    do: {:ok, id}

  defp in_range(_id, _year, _current_year), do: {:error, :year_out_of_range}
end
