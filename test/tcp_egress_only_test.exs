defmodule Sippet.Transports.TCP.EgressOnlyTest do
  use ExUnit.Case, async: false

  alias Sippet.Transports.TCP

  @moduletag :tcp_transport

  defmodule TestCore do
    @behaviour Sippet.Core

    @impl true
    def receive_request(_request, _key), do: :ok

    @impl true
    def receive_response(_response, _key), do: :ok

    @impl true
    def receive_error(_reason, _key), do: :ok
  end

  setup do
    sippet_name = :"sippet_eo_test_#{System.unique_integer([:positive])}"
    start_supervised!({Sippet, name: sippet_name})
    Sippet.register_core(sippet_name, TestCore)
    %{sippet: sippet_name}
  end

  defp start_transport(sippet, port, extra_opts) do
    start_supervised(%{
      id: {TCP, :"eo_#{port}"},
      start:
        {TCP, :start_link,
         [
           [
             name: sippet,
             address: {"127.0.0.1", :inet},
             port: port,
             transport_name: :"eo_#{port}"
           ] ++ extra_opts
         ]}
    })
  end

  test "an egress_only transport creates no listening socket (inbound refused)", %{
    sippet: sippet
  } do
    port = 21_000 + rem(System.unique_integer([:positive]), 2000)

    {:ok, _pid} = start_transport(sippet, port, egress_only: true)
    Process.sleep(50)

    # No listener bound: the kernel refuses inbound connections with RST.
    assert {:error, :econnrefused} =
             :gen_tcp.connect(~c"127.0.0.1", port, [:binary, {:active, false}], 1_000)
  end

  test "a normal (non-egress_only) transport does listen and accepts connections", %{
    sippet: sippet
  } do
    port = 23_000 + rem(System.unique_integer([:positive]), 2000)

    {:ok, _pid} = start_transport(sippet, port, [])
    Process.sleep(50)

    assert {:ok, socket} =
             :gen_tcp.connect(~c"127.0.0.1", port, [:binary, {:active, false}], 1_000)

    :gen_tcp.close(socket)
  end
end
