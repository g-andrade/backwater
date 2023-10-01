defmodule BackwaterElixirTests.Mixfile do
  use Mix.Project

  def project do
    [app: :backwater_elixir_tests,
     version: "0.1.0",
     elixir: "~> 1.4",
     #compilers: [:backwater, :elixir, :app],
     compilers: [:elixir, :app],
     build_embedded: Mix.env == :prod,
     start_permanent: Mix.env == :prod,
     deps: deps()]
  end

  # Configuration for the OTP application
  #
  # Type "mix help compile.app" for more information
  def application do
    # Specify extra applications you'll use from Erlang/Elixir
    [extra_applications: [:logger]]
  end

  defp deps do
    [
      {:backwater, path: ".."}
    ]
  end
end
