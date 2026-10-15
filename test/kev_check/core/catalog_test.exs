defmodule KevCheck.Core.CatalogTest do
  use ExUnit.Case, async: true

  alias KevCheck.Core.Catalog
  alias KevCheck.Core.Entry

  @log4shell %{
    "cveID" => "CVE-2021-44228",
    "vendorProject" => "Apache",
    "product" => "Log4j2",
    "vulnerabilityName" => "Apache Log4j2 Remote Code Execution Vulnerability",
    "dateAdded" => "2021-12-10",
    "shortDescription" =>
      "Apache Log4j2 contains a vulnerability where JNDI features do not protect against attacker-controlled JNDI-related endpoints, allowing for remote code execution.",
    "requiredAction" =>
      "For all affected software assets for which updates exist, the only acceptable remediation actions are: 1) Apply updates; OR 2) remove affected assets from agency networks. Temporary mitigations using one of the measures provided at https://www.cisa.gov/uscert/ed-22-02-apache-log4j-recommended-mitigation-measures are only acceptable until updates are available.",
    "dueDate" => "2021-12-24",
    "knownRansomwareCampaignUse" => "Known",
    "forensicTriage" => "No",
    "notes" => "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
    "cwes" => ["CWE-20", "CWE-400", "CWE-502"]
  }

  @shellshock %{
    "cveID" => "CVE-2014-6271",
    "vendorProject" => "GNU",
    "product" => "Bourne-Again Shell (Bash)",
    "vulnerabilityName" => "GNU Bourne-Again Shell (Bash) Arbitrary Code Execution Vulnerability",
    "dateAdded" => "2022-01-28",
    "shortDescription" =>
      "GNU Bash through 4.3 processes trailing strings after function definitions in the values of environment variables, which allows remote attackers to execute code.",
    "requiredAction" => "Apply updates per vendor instructions.",
    "dueDate" => "2022-07-28",
    "knownRansomwareCampaignUse" => "Unknown",
    "forensicTriage" => "No",
    "notes" => "https://nvd.nist.gov/vuln/detail/CVE-2014-6271",
    "cwes" => ["CWE-78"]
  }

  describe "parse/1" do
    test "reads the version, the release time, and every entry" do
      assert {:ok, catalog} = Catalog.parse(feed([@log4shell, @shellshock]))

      assert catalog.version == "2026.10.14"
      assert catalog.released_at == ~U[2026-10-14 19:27:28.0105Z]

      assert %Entry{
               cve_id: "CVE-2021-44228",
               vendor: "Apache",
               product: "Log4j2",
               name: "Apache Log4j2 Remote Code Execution Vulnerability",
               date_added: ~D[2021-12-10],
               due_date: ~D[2021-12-24],
               known_ransomware_use: true,
               required_action: "For all affected software assets" <> _rest
             } = catalog.entries["CVE-2021-44228"]

      assert %Entry{
               known_ransomware_use: false,
               required_action: "Apply updates per vendor instructions."
             } = catalog.entries["CVE-2014-6271"]
    end

    test "rejects text that isn't JSON" do
      assert Catalog.parse("<html>Service Unavailable</html>") == {:error, :invalid_catalog}
    end

    test "rejects JSON that isn't a feed object" do
      assert Catalog.parse("[]") == {:error, :invalid_catalog}
      assert Catalog.parse("null") == {:error, :invalid_catalog}
    end

    for key <- ~w(catalogVersion dateReleased vulnerabilities) do
      test "rejects a feed whose #{key} is missing or null" do
        missing = Map.delete(feed_map([@log4shell]), unquote(key))
        null = Map.put(feed_map([@log4shell]), unquote(key), nil)

        assert Catalog.parse(JSON.encode!(missing)) == {:error, :invalid_catalog}
        assert Catalog.parse(JSON.encode!(null)) == {:error, :invalid_catalog}
      end
    end

    test "rejects a release time that isn't a timestamp" do
      json = [@log4shell] |> feed_map() |> Map.put("dateReleased", "yesterday") |> JSON.encode!()

      assert Catalog.parse(json) == {:error, :invalid_catalog}
    end

    test "rejects a feed with no vulnerabilities" do
      assert Catalog.parse(feed([])) == {:error, :invalid_catalog}
    end

    test "rejects the whole feed when one item isn't an object" do
      assert Catalog.parse(feed([@log4shell, "CVE-2014-6271"])) == {:error, :invalid_catalog}
    end

    required_fields =
      ~w(cveID vendorProject product vulnerabilityName dateAdded dueDate knownRansomwareCampaignUse requiredAction)

    for field <- required_fields do
      test "rejects the whole feed when one entry's #{field} is missing or null" do
        missing = Map.delete(@shellshock, unquote(field))
        null = Map.put(@shellshock, unquote(field), nil)

        assert Catalog.parse(feed([@log4shell, missing])) == {:error, :invalid_catalog}
        assert Catalog.parse(feed([@log4shell, null])) == {:error, :invalid_catalog}
      end
    end

    bad_values = [
      {"dueDate", "soon"},
      {"cveID", "cve-2014-6271"},
      {"cveID", "CVE-2014-6271 "},
      {"knownRansomwareCampaignUse", "Suspected"}
    ]

    for {field, value} <- bad_values do
      test "rejects the whole feed when one entry's #{field} is #{inspect(value)}" do
        bad = Map.put(@shellshock, unquote(field), unquote(value))

        assert Catalog.parse(feed([@log4shell, bad])) == {:error, :invalid_catalog}
      end
    end
  end

  describe "with a parsed catalog" do
    setup do
      {:ok, catalog} = Catalog.parse(feed([@log4shell, @shellshock]))
      %{catalog: catalog}
    end

    test "answer/2 returns the entry for a listed ID", %{catalog: catalog} do
      assert %{
               cve_id: "CVE-2021-44228",
               known_exploited: true,
               entry: %Entry{name: "Apache Log4j2 Remote Code Execution Vulnerability"},
               catalog_version: "2026.10.14"
             } = Catalog.answer(catalog, "CVE-2021-44228")
    end

    test "answer/2 says no for an ID that isn't listed", %{catalog: catalog} do
      assert Catalog.answer(catalog, "CVE-2023-99999") == %{
               cve_id: "CVE-2023-99999",
               known_exploited: false,
               entry: nil,
               catalog_version: "2026.10.14"
             }
    end

    test "age_seconds/2 counts from the release and never goes negative", %{catalog: catalog} do
      assert Catalog.age_seconds(catalog, DateTime.add(catalog.released_at, 1, :day)) == 86_400
      assert Catalog.age_seconds(catalog, DateTime.add(catalog.released_at, -60, :second)) == 0
    end

    test "size/1 counts entries", %{catalog: catalog} do
      assert Catalog.size(catalog) == 2
    end
  end

  defp feed(items), do: items |> feed_map() |> JSON.encode!()

  defp feed_map(items) do
    %{
      "title" => "CISA Catalog of Known Exploited Vulnerabilities",
      "catalogVersion" => "2026.10.14",
      "dateReleased" => "2026-10-14T19:27:28.0105Z",
      "count" => length(items),
      "vulnerabilities" => items
    }
  end
end
