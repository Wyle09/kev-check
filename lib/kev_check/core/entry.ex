defmodule KevCheck.Core.Entry do
  @moduledoc """
  One vulnerability from CISA's KEV feed, trimmed to the fields the API returns.
  """

  alias KevCheck.Core.CveId

  @type t :: %__MODULE__{
          cve_id: CveId.t(),
          vendor: String.t(),
          product: String.t(),
          name: String.t(),
          date_added: Date.t(),
          due_date: Date.t(),
          known_ransomware_use: boolean(),
          required_action: String.t()
        }

  @enforce_keys [
    :cve_id,
    :vendor,
    :product,
    :name,
    :date_added,
    :due_date,
    :known_ransomware_use,
    :required_action
  ]
  defstruct @enforce_keys

  @doc "Build an entry from one item of the feed's `vulnerabilities` list."
  @spec from_map(term()) :: {:ok, t()} | {:error, :invalid_entry}
  def from_map(%{
        "cveID" => cve_id,
        "vendorProject" => vendor,
        "product" => product,
        "vulnerabilityName" => name,
        "dateAdded" => date_added,
        "dueDate" => due_date,
        "knownRansomwareCampaignUse" => ransomware,
        "requiredAction" => required_action
      })
      when is_binary(cve_id) and is_binary(vendor) and is_binary(product) and is_binary(name) and
             is_binary(date_added) and is_binary(due_date) and is_binary(required_action) and
             ransomware in ["Known", "Unknown"] do
    with true <- CveId.canonical?(cve_id),
         {:ok, added} <- Date.from_iso8601(date_added),
         {:ok, due} <- Date.from_iso8601(due_date) do
      {:ok,
       %__MODULE__{
         cve_id: cve_id,
         vendor: vendor,
         product: product,
         name: name,
         date_added: added,
         due_date: due,
         known_ransomware_use: ransomware == "Known",
         required_action: required_action
       }}
    else
      false -> {:error, :invalid_entry}
      {:error, _date_error} -> {:error, :invalid_entry}
    end
  end

  def from_map(_item), do: {:error, :invalid_entry}
end
