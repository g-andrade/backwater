defmodule SpecifyingBackwaterExports.Application do
  # See http://elixir-lang.org/docs/stable/elixir/Application.html
  # for more information on OTP Applications
  @moduledoc false

  use Application

  def server_ref, do: :exposed_ets

  # Generate your own secret randomly e.g. using :crypto.strong_rand_bytes(32)
  # It must be equal to the client's.
  def secret, do: "VERY_SENSITIVE_SECRET_CHANGE_THIS"

  def start(_type, _args) do
    import Supervisor.Spec, warn: false

    {:ok, _pid} =
      :backwater_server.start_clear(
        server_ref(),
        %{ :secret => secret(),
           :exposed_modules => [ModuleWithBackwaterExports] },
        [{:port, 8080}],
        %{})

    # Define workers and child supervisors to be supervised
    children = [
      # Starts a worker by calling: SpecifyingBackwaterExports.Worker.start_link(arg1, arg2, arg3)
      # worker(SpecifyingBackwaterExports.Worker, [arg1, arg2, arg3]),
    ]

    # See http://elixir-lang.org/docs/stable/elixir/Supervisor.html
    # for other strategies and supported options
    opts = [strategy: :one_for_one, name: SpecifyingBackwaterExports.Supervisor]
    Supervisor.start_link(children, opts)
  end

  def stop(_app) do
    :ok = :backwater_server.stop_listener(server_ref())
  end
end
