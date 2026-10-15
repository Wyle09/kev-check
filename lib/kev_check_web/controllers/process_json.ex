defmodule KevCheckWeb.ProcessJSON do
  @moduledoc "JSON bodies for `/process`."

  alias KevCheck.Core.Entry

  @doc "A lookup that got an answer. `known_exploited: false` is still an answer."
  @spec show(map()) :: map()
  def show(%{answer: %{entry: nil} = answer}),
    do: %{cve_id: answer.cve_id, known_exploited: false, catalog_version: answer.catalog_version}

  def show(%{answer: %{entry: %Entry{} = entry} = answer}) do
    %{
      cve_id: answer.cve_id,
      known_exploited: true,
      catalog_version: answer.catalog_version,
      vendor: entry.vendor,
      product: entry.product,
      name: entry.name,
      date_added: entry.date_added,
      due_date: entry.due_date,
      known_ransomware_use: entry.known_ransomware_use,
      required_action: entry.required_action
    }
  end

  @doc "A lookup that couldn't be answered, with a stable machine-readable `error`."
  @spec error(map()) :: map()
  def error(%{reason: reason}), do: %{error: reason, message: message(reason)}

  defp message(:missing_id), do: "Pass a CVE ID, for example /process?id=CVE-2021-44228."
  defp message(:invalid_format), do: "Expected an ID shaped like CVE-YYYY-NNNN."
  defp message(:year_out_of_range), do: "CVE IDs start in 1999 and can't be from a future year."

  defp message(:catalog_unavailable),
    do: "The KEV catalog isn't available right now. Try again shortly."
end
