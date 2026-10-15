defmodule KevCheck.Core.CveIdTest do
  use ExUnit.Case, async: true

  alias KevCheck.Core.CveId

  @current_year 2026

  cases = [
    {"canonical", "CVE-2021-44228", {:ok, "CVE-2021-44228"}},
    {"lowercase and padded", "  cve-2021-44228 ", {:ok, "CVE-2021-44228"}},
    {"six-digit sequence", "CVE-2026-105134", {:ok, "CVE-2026-105134"}},
    {"19-digit sequence", "CVE-2021-1234567890123456789", {:ok, "CVE-2021-1234567890123456789"}},
    {"first CVE year", "CVE-1999-0001", {:ok, "CVE-1999-0001"}},
    {"current year", "CVE-2026-0001", {:ok, "CVE-2026-0001"}},
    {"missing", nil, {:error, :missing_id}},
    {"blank", "   ", {:error, :missing_id}},
    {"a bare number", "123", {:error, :invalid_format}},
    {"short sequence", "CVE-2021-123", {:error, :invalid_format}},
    {"20-digit sequence", "CVE-2021-12345678901234567890", {:error, :invalid_format}},
    {"two-digit year", "CVE-21-44228", {:error, :invalid_format}},
    {"five-digit year", "CVE-20211-0001", {:error, :invalid_format}},
    {"leading junk", "xCVE-2021-44228", {:error, :invalid_format}},
    {"trailing junk", "CVE-2021-44228x", {:error, :invalid_format}},
    {"repeated param", ["CVE-2021-44228"], {:error, :invalid_format}},
    {"before the program", "CVE-1998-0001", {:error, :year_out_of_range}},
    {"future year", "CVE-2027-0001", {:error, :year_out_of_range}}
  ]

  for {name, input, expected} <- cases do
    test "parse/2: #{name}" do
      assert CveId.parse(unquote(input), @current_year) == unquote(expected)
    end
  end

  test "canonical?/1 accepts only the exact form the feed uses" do
    assert CveId.canonical?("CVE-2021-44228")

    refute CveId.canonical?("cve-2021-44228")
    refute CveId.canonical?("CVE-2021-44228 ")
    refute CveId.canonical?("not a cve")
  end
end
