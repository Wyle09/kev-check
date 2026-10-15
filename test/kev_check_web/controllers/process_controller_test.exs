defmodule KevCheckWeb.ProcessControllerTest do
  # The fault knobs are global, so these tests can't run alongside each other.
  use KevCheckWeb.ConnCase, async: false

  alias KevCheck.Faults

  setup do
    on_exit(&Faults.reset/0)
  end

  @log4shell %{
    "cve_id" => "CVE-2021-44228",
    "known_exploited" => true,
    "catalog_version" => "2026.10.14",
    "vendor" => "Apache",
    "product" => "Log4j2",
    "name" => "Apache Log4j2 Remote Code Execution Vulnerability",
    "date_added" => "2021-12-10",
    "due_date" => "2021-12-24",
    "known_ransomware_use" => true,
    "required_action" =>
      "For all affected software assets for which updates exist, the only acceptable remediation actions are: 1) Apply updates; OR 2) remove affected assets from agency networks. Temporary mitigations using one of the measures provided at https://www.cisa.gov/uscert/ed-22-02-apache-log4j-recommended-mitigation-measures are only acceptable until updates are available."
  }

  describe "GET /process answers" do
    test "a listed CVE with its catalog entry", %{conn: conn} do
      assert conn |> get("/process?id=CVE-2021-44228") |> json_response(200) == @log4shell
    end

    test "a lowercase ID the same way", %{conn: conn} do
      assert conn |> get("/process?id=cve-2021-44228") |> json_response(200) == @log4shell
    end

    test "an unlisted CVE with known_exploited false, which is still an answer", %{conn: conn} do
      assert conn |> get("/process?id=CVE-2023-99999") |> json_response(200) == %{
               "cve_id" => "CVE-2023-99999",
               "known_exploited" => false,
               "catalog_version" => "2026.10.14"
             }
    end
  end

  describe "GET /process rejects" do
    rejections = [
      {"no id", "/process", 400, "missing_id"},
      {"a blank id", "/process?id=%20%20", 400, "missing_id"},
      {"a bare number", "/process?id=123", 400, "invalid_format"},
      {"a repeated param", "/process?id[]=CVE-2021-44228", 400, "invalid_format"},
      {"a future year", "/process?id=CVE-2099-0001", 422, "year_out_of_range"}
    ]

    for {name, path, status, error} <- rejections do
      test "#{name} with #{status} #{error}", %{conn: conn} do
        assert %{"error" => unquote(error), "message" => message} =
                 conn |> get(unquote(path)) |> json_response(unquote(status))

        assert message =~ ~r/\S/
      end
    end
  end

  describe "GET /process when the catalog is unavailable" do
    setup do
      Faults.put(error_rate: 1.0)
      :ok
    end

    test "returns 503 catalog_unavailable", %{conn: conn} do
      assert conn |> get("/process?id=CVE-2021-44228") |> json_response(503) == %{
               "error" => "catalog_unavailable",
               "message" => "The KEV catalog isn't available right now. Try again shortly."
             }
    end

    test "still rejects bad input with 400, because input is checked before the faults",
         %{conn: conn} do
      assert %{"error" => "invalid_format"} =
               conn |> get("/process?id=123") |> json_response(400)
    end
  end

  test "GET /healthz answers ok in plain text", %{conn: conn} do
    conn = get(conn, "/healthz")

    assert text_response(conn, 200) == "ok"
  end
end
