defmodule Sippet.Transports.TCP.AsyncConnectTest do
  # P5GM-3867: a TCP connect that hangs must not block the transport, queued
  # messages are sent once connected or failed through the transaction, and a
  # response whose request connection has closed goes to its fallback target.
  use ExUnit.Case, async: false

  alias Sippet.Message
  alias Sippet.Transports.TCP

  @test_name :tcp_async_connect_test

  # Captures transport errors (Sippet.Router.receive_transport_error/3 goes to
  # the sharded handler when sharded transactions are on).
  defmodule ErrorSink do
    def receive_transport_error(_sippet, key, reason) do
      send(:tcp_async_connect_test, {:transport_error, key, reason})
      :ok
    end

    def handle_transport_message(_sippet, _raw, _from, _source), do: :ok
  end

  setup do
    Process.register(self(), @test_name)

    previous = {
      Application.get_env(:sip, :use_sharded_transactions),
      Application.get_env(:sip, :sharded_handler)
    }

    Application.put_env(:sip, :use_sharded_transactions, true)
    Application.put_env(:sip, :sharded_handler, ErrorSink)

    on_exit(fn ->
      {sharded, handler} = previous
      restore_env(:use_sharded_transactions, sharded)
      restore_env(:sharded_handler, handler)
    end)

    sippet = :"sippet_tcp_async_#{System.unique_integer([:positive])}"
    start_supervised!({Sippet, name: sippet})

    %{sippet: sippet}
  end

  defp restore_env(key, nil), do: Application.delete_env(:sip, key)
  defp restore_env(key, value), do: Application.put_env(:sip, key, value)

  # A connect function reporting every connect to the test, and holding the
  # connects to `held_ports` until the test sends `{:release, port, result}`
  # (`result` :connect, or an `{:error, reason}` to return).
  defp connect_fun(name, held_ports) do
    test = Process.whereis(@test_name)

    fn ip, port, opts, timeout ->
      send(test, {:connect_called, name, port, self()})

      if port in held_ports do
        receive do
          {:release, ^port, :connect} -> :gen_tcp.connect(ip, port, opts, timeout)
          {:release, ^port, {:error, _} = error} -> error
        end
      else
        :gen_tcp.connect(ip, port, opts, timeout)
      end
    end
  end

  defp start_tcp(sippet, name, opts \\ []) do
    base = [
      name: sippet,
      address: {"127.0.0.1", :inet},
      port: free_port(),
      transport_name: name,
      connect_fun: connect_fun(name, Keyword.get(opts, :held, []))
    ]

    {:ok, pid} =
      start_supervised(
        %{
          id: {TCP, name},
          start: {TCP, :start_link, [Keyword.merge(base, Keyword.delete(opts, :held))]}
        },
        id: name
      )

    pid
  end

  defp free_port do
    {:ok, s} = :gen_tcp.listen(0, [:binary, {:reuseaddr, true}])
    {:ok, port} = :inet.port(s)
    :gen_tcp.close(s)
    port
  end

  defp listen do
    {:ok, server} = :gen_tcp.listen(0, [:binary, {:active, false}, {:reuseaddr, true}])
    {:ok, port} = :inet.port(server)
    {server, port}
  end

  defp request(port, call_id \\ "async@127.0.0.1", cseq \\ 1) do
    Message.parse!(
      "OPTIONS sip:example.com SIP/2.0\r\n" <>
        "Via: SIP/2.0/TCP 127.0.0.1:#{port};branch=z9hG4bK#{call_id}#{cseq}\r\n" <>
        "Max-Forwards: 70\r\n" <>
        "From: <sip:alice@example.com>;tag=a\r\n" <>
        "To: <sip:bob@example.com>\r\n" <>
        "Call-ID: #{call_id}\r\n" <>
        "CSeq: #{cseq} OPTIONS\r\n" <>
        "Content-Length: 0\r\n\r\n"
    )
  end

  defp recv_all(socket, acc \\ "") do
    case :gen_tcp.recv(socket, 0, 300) do
      {:ok, data} -> recv_all(socket, acc <> data)
      {:error, :timeout} -> acc
    end
  end

  defp wait_until(fun, tries \\ 50) do
    cond do
      fun.() -> :ok
      tries == 0 -> flunk("condition not met")
      true -> Process.sleep(20) && wait_until(fun, tries - 1)
    end
  end

  describe "asynchronous connect" do
    test "a hanging connect to one peer does not delay sends to another", %{sippet: sippet} do
      tcp = start_tcp(sippet, :async_a, held: [1])
      {server_b, port_b} = listen()

      :ok = GenServer.call(tcp, {:send_message, request(port_b), "127.0.0.1", port_b, nil})
      {:ok, b} = :gen_tcp.accept(server_b, 2_000)
      assert {:ok, _} = :gen_tcp.recv(b, 0, 2_000)

      # Port 1 is held: its connect never completes during the test.
      {elapsed, :ok} =
        :timer.tc(fn -> GenServer.call(tcp, {:send_message, request(1), "127.0.0.1", 1, nil}) end)

      assert elapsed < 200_000
      assert_receive {:connect_called, :async_a, 1, _}

      {elapsed, :ok} =
        :timer.tc(fn ->
          GenServer.call(
            tcp,
            {:send_message, request(port_b, "second"), "127.0.0.1", port_b, nil}
          )
        end)

      assert elapsed < 200_000
      assert {:ok, data} = :gen_tcp.recv(b, 0, 1_000)
      assert data =~ "Call-ID: second"
    end

    test "messages queued during the connect are sent in order once connected", %{sippet: sippet} do
      {server, port} = listen()
      tcp = start_tcp(sippet, :async_b, held: [port])

      for n <- 1..3 do
        GenServer.cast(tcp, {:send_message, request(port, "q#{n}", n), "127.0.0.1", port, nil})
      end

      assert_receive {:connect_called, :async_b, ^port, connector}
      # A single connect per peer, however many messages are waiting.
      refute_receive {:connect_called, :async_b, ^port, _}, 100

      send(connector, {:release, port, :connect})
      {:ok, socket} = :gen_tcp.accept(server, 2_000)
      data = recv_all(socket)

      assert ["q1", "q2", "q3"] ==
               ~r/Call-ID: (\S+)/ |> Regex.scan(data, capture: :all_but_first) |> List.flatten()
    end

    test "a failed connect reports every queued transactional message", %{sippet: sippet} do
      {_server, port} = listen()
      tcp = start_tcp(sippet, :async_c, held: [port])

      GenServer.cast(tcp, {:send_message, request(port, "f1"), "127.0.0.1", port, :key1})
      GenServer.cast(tcp, {:send_message, request(port, "f2"), "127.0.0.1", port, nil})
      GenServer.cast(tcp, {:send_message, request(port, "f3"), "127.0.0.1", port, :key3})

      assert_receive {:connect_called, :async_c, ^port, connector}
      send(connector, {:release, port, {:error, :econnrefused}})

      assert_receive {:transport_error, :key1, :econnrefused}
      assert_receive {:transport_error, :key3, :econnrefused}
      refute_receive {:transport_error, _, _}, 100

      # The peer is not stuck: the next message triggers a new connect.
      GenServer.cast(tcp, {:send_message, request(port, "f4"), "127.0.0.1", port, :key4})
      assert_receive {:connect_called, :async_c, ^port, _}
    end

    test "the per-peer queue is bounded", %{sippet: sippet} do
      {_server, port} = listen()
      tcp = start_tcp(sippet, :async_d, held: [port], connect_queue_size: 2)

      for key <- [:k1, :k2, :k3] do
        GenServer.cast(tcp, {:send_message, request(port), "127.0.0.1", port, key})
      end

      assert_receive {:transport_error, :k3, :connect_queue_full}
      refute_receive {:transport_error, _, _}, 100
    end

    test "connects in progress count towards max_connections", %{sippet: sippet} do
      {_server, port} = listen()
      tcp = start_tcp(sippet, :async_e, held: [port, 1], max_connections: 1)

      GenServer.cast(tcp, {:send_message, request(port), "127.0.0.1", port, :k1})
      GenServer.cast(tcp, {:send_message, request(1), "127.0.0.1", 1, :k2})

      assert_receive {:transport_error, :k2, :max_connections}
      refute_receive {:transport_error, :k1, _}, 100
    end

    test "connections get a bounded send timeout", %{sippet: sippet} do
      {server, port} = listen()
      tcp = start_tcp(sippet, :async_f, send_timeout: 1_234)

      :ok = GenServer.call(tcp, {:send_message, request(port), "127.0.0.1", port, nil})
      {:ok, _} = :gen_tcp.accept(server, 2_000)
      wait_until(fn -> TCP.connection_count(tcp) == 1 end)

      %{connections: connections} = :sys.get_state(tcp)
      [conn] = connections |> Map.values() |> List.flatten()
      %{socket: socket} = :sys.get_state(conn)

      assert {:ok, opts} = :inet.getopts(socket, [:send_timeout, :send_timeout_close])
      assert opts[:send_timeout] == 1_234
      assert opts[:send_timeout_close] == true
    end
  end

  describe "response fallback target" do
    # Opens a connection to the server transport as a client would, so the
    # transport's pool holds the inbound connection. Returns the client socket
    # and the source_peer the request would carry.
    defp inbound_connection(tcp) do
      %{local_port: port} = :sys.get_state(tcp)
      {:ok, client} = :gen_tcp.connect(~c"127.0.0.1", port, [:binary, {:active, false}], 2_000)
      {:ok, {_ip, client_port}} = :inet.sockname(client)
      wait_until(fn -> TCP.connection_count(tcp) == 1 end)
      {client, {{127, 0, 0, 1}, client_port}}
    end

    defp response(source_peer, fallback) do
      {_ip, client_port} = source_peer

      request(client_port, "resp")
      |> Message.to_response(200)
      |> Map.put(:source_peer, source_peer)
      |> Map.put(:fallback_target, fallback)
    end

    test "an open request connection is reused and the fallback ignored", %{sippet: sippet} do
      server_tcp = start_tcp(sippet, :fb_server_a)
      _client_tcp = start_tcp(sippet, :fb_client_a)
      {fallback_server, fallback_port} = listen()

      {client, {_ip, client_port} = peer} = inbound_connection(server_tcp)
      response = response(peer, {:fb_client_a, "127.0.0.1", fallback_port})

      :ok = GenServer.call(server_tcp, {:send_message, response, "127.0.0.1", client_port, :k})

      assert {:ok, data} = :gen_tcp.recv(client, 0, 1_000)
      assert data =~ "SIP/2.0 200"
      assert {:error, :timeout} = :gen_tcp.accept(fallback_server, 200)
      refute_received {:connect_called, _, _, _}
    end

    test "after the request connection closed, the response goes to the fallback transport",
         %{sippet: sippet} do
      server_tcp = start_tcp(sippet, :fb_server_b)
      client_tcp = start_tcp(sippet, :fb_client_b)
      {fallback_server, fallback_port} = listen()

      {client, {_ip, client_port} = peer} = inbound_connection(server_tcp)
      :gen_tcp.close(client)
      wait_until(fn -> TCP.connection_count(server_tcp) == 0 end)

      response = response(peer, {:fb_client_b, "127.0.0.1", fallback_port})
      :ok = GenServer.call(server_tcp, {:send_message, response, "127.0.0.1", client_port, :k})

      assert_receive {:connect_called, :fb_client_b, ^fallback_port, _}
      {:ok, socket} = :gen_tcp.accept(fallback_server, 2_000)
      assert {:ok, data} = :gen_tcp.recv(socket, 0, 1_000)
      assert data =~ "SIP/2.0 200"

      # The connection comes from the fallback transport, not the server one.
      assert TCP.connection_count(client_tcp) == 1
      assert TCP.connection_count(server_tcp) == 0
      refute_received {:connect_called, :fb_server_b, _, _}
      refute_received {:transport_error, _, _}
    end

    test "a fallback naming the same transport connects to the fallback address",
         %{sippet: sippet} do
      server_tcp = start_tcp(sippet, :fb_server_c)
      {fallback_server, fallback_port} = listen()

      {client, {_ip, client_port} = peer} = inbound_connection(server_tcp)
      :gen_tcp.close(client)
      wait_until(fn -> TCP.connection_count(server_tcp) == 0 end)

      response = response(peer, {:fb_server_c, "127.0.0.1", fallback_port})
      :ok = GenServer.call(server_tcp, {:send_message, response, "127.0.0.1", client_port, :k})

      assert_receive {:connect_called, :fb_server_c, ^fallback_port, _}
      refute_received {:connect_called, :fb_server_c, ^client_port, _}
      {:ok, socket} = :gen_tcp.accept(fallback_server, 2_000)
      assert {:ok, data} = :gen_tcp.recv(socket, 0, 1_000)
      assert data =~ "SIP/2.0 200"
    end

    test "an unknown fallback transport fails the transaction", %{sippet: sippet} do
      server_tcp = start_tcp(sippet, :fb_server_d)
      {_ip, client_port} = peer = {{127, 0, 0, 1}, 1}

      response = response(peer, {:no_such_transport, "127.0.0.1", 2})
      :ok = GenServer.call(server_tcp, {:send_message, response, "127.0.0.1", client_port, :k})

      assert_receive {:transport_error, :k, :no_transport}
    end
  end

  describe "Sippet.Router.send_transport_message_async/3" do
    test "casts to the transport named by the target", %{sippet: sippet} do
      tcp = start_tcp(sippet, :async_router)
      {server, port} = listen()

      message = %{request(port) | target: {:async_router, "127.0.0.1", port}}
      assert :ok = Sippet.Router.send_transport_message_async(sippet, message, :k)

      {:ok, socket} = :gen_tcp.accept(server, 2_000)
      assert {:ok, data} = :gen_tcp.recv(socket, 0, 1_000)
      assert data =~ "OPTIONS"
      assert TCP.connection_count(tcp) == 1
    end

    test "reports a missing transport", %{sippet: sippet} do
      message = %{request(5060) | target: {:missing_transport, "127.0.0.1", 5060}}

      assert {:error, :no_transport} =
               Sippet.Router.send_transport_message_async(sippet, message, :k)

      assert_receive {:transport_error, :k, :no_transport}
    end
  end
end
