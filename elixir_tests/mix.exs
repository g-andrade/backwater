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

  # Dependencies can be Hex packages:
  #
  #   {:my_dep, "~> 0.3.0"}
  #
  # Or git/path repositories:
  #
  #   {:my_dep, git: "https://github.com/elixir-lang/my_dep.git", tag: "0.1.0"}
  #
  # Type "mix help deps" for more examples and options
  defp deps do
    #[{:backwater, "1.0.0-rc.2"}]
    #[{:backwater, git: "https://github.com/g-andrade/backwater.git", ref: "aaeae98"}]
    [{:backwater, path: ".."}]
  end
end
