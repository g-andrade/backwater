defmodule ExposedEtsClient.Application do
  # See http://elixir-lang.org/docs/stable/elixir/Application.html
  # for more information on OTP Applications
  @moduledoc false

  use Application

  def client_ref, do: :exposed_ets
  def endpoint, do: "https://127.0.0.1:8080/"

  # Generate your own secret randomly e.g. using :crypto.strong_rand_bytes(32)
  # It must be equal to the server's.
  def secret, do: "VERY_SENSITIVE_SECRET_CHANGE_THIS" 

  def start(_type, _args) do
    import Supervisor.Spec, warn: false

    :ok =
      :backwater_client.start(
        client_ref(),
        %{ :endpoint => endpoint(),
           :secret => secret() })

    # Define workers and child supervisors to be supervised
    children = [
      # Starts a worker by calling: ExposedEtsClient.Worker.start_link(arg1, arg2, arg3)
      # worker(ExposedEtsClient.Worker, [arg1, arg2, arg3]),
    ]

    # See http://elixir-lang.org/docs/stable/elixir/Supervisor.html
    # for other strategies and supported options
    opts = [strategy: :one_for_one, name: ExposedEtsClient.Supervisor]
    Supervisor.start_link(children, opts)
  end

  def stop(_app) do
    :ok = :backwater_client.stop(client_ref())
  end
end
