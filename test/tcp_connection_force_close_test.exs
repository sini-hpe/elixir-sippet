defmodule Sippet.Transports.TCP.ConnectionForceCloseTest do
  use ExUnit.Case, async: true

  alias Sippet.Transports.TCP.Connection

  test "force_close/1 abortively closes the socket and stops the connection" do
    # A real connected TCP socket pair on loopback.
    {:ok, listen} =
      :gen_tcp.listen(0, [:binary, {:active, false}, {:ip, {127, 0, 0, 1}}])

    {:ok, port} = :inet.port(listen)
    {:ok, client} = :gen_tcp.connect({127, 0, 0, 1}, port, [:binary, {:active, false}])
    {:ok, server} = :gen_tcp.accept(listen)

    {:ok, conn} =
      Connection.start_link(
        socket: server,
        sippet: :test_sippet,
        transport_name: :tcp_test,
        peer: {{127, 0, 0, 1}, 12_345}
      )

    # Transfer socket ownership to the connection process and activate it.
    :ok = Connection.activate(conn, server)

    ref = Process.monitor(conn)

    Connection.force_close(conn)

    # The connection process stops normally.
    assert_receive {:DOWN, ^ref, :process, ^conn, :normal}, 1_000

    # The peer observes the (abortive) close rather than a lingering half-open
    # connection.
    assert {:error, reason} = :gen_tcp.recv(client, 0, 1_000)
    assert reason in [:closed, :econnreset]

    :gen_tcp.close(client)
    :gen_tcp.close(listen)
  end
end
