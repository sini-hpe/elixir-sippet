defmodule Sippet.Transports.TCP do
  @moduledoc """
  Implements a TCP transport for SIP.

  Manages a listening socket for incoming connections and a pool of
  outgoing connections keyed by `{ip, port}`.  Each accepted or
  established connection is handled by a
  `Sippet.Transports.TCP.Connection` process that performs SIP message
  framing (Content-Length based) over the TCP stream.

  TCP is a reliable transport – the transaction layer will not
  retransmit messages sent over TCP.
  """

  use GenServer

  alias Sippet.Message
  alias Sippet.Transports.TCP.Connection

  require Logger

  defstruct listen_socket: nil,
            family: :inet,
            sippet: nil,
            transport_name: nil,
            connections: %{},
            monitors: %{}

  @doc """
  Starts the TCP transport.
  """
  def start_link(options) when is_list(options) do
    name =
      case Keyword.fetch(options, :name) do
        {:ok, name} when is_atom(name) ->
          name

        {:ok, other} ->
          raise ArgumentError, "expected :name to be an atom, got: #{inspect(other)}"

        :error ->
          raise ArgumentError, "expected :name option to be present"
      end

    port =
      case Keyword.fetch(options, :port) do
        {:ok, port} when is_integer(port) and port > 0 and port < 65536 ->
          port

        {:ok, other} ->
          raise ArgumentError,
                "expected :port to be an integer between 1 and 65535, got: #{inspect(other)}"

        :error ->
          5060
      end

    {address, family} =
      case Keyword.fetch(options, :address) do
        {:ok, {address, family}} when family in [:inet, :inet6] and is_binary(address) ->
          {address, family}

        {:ok, address} when is_binary(address) ->
          {address, :inet}

        {:ok, other} ->
          raise ArgumentError,
                "expected :address to be an address or {address, family} tuple, got: " <>
                  "#{inspect(other)}"

        :error ->
          {"0.0.0.0", :inet}
      end

    transport_name =
      case Keyword.fetch(options, :transport_name) do
        {:ok, tn} when is_atom(tn) -> tn
        _ -> :tcp
      end

    ip =
      case resolve_name(address, family) do
        {:ok, ip} ->
          ip

        {:error, reason} ->
          raise ArgumentError,
                ":address contains an invalid IP or DNS name, got: #{inspect(reason)}"
      end

    GenServer.start_link(__MODULE__, {name, ip, port, family, transport_name})
  end

  @impl true
  def init({name, ip, port, family, transport_name}) do
    Sippet.register_transport(name, transport_name, :tcp, true)
    {:ok, nil, {:continue, {name, ip, port, family, transport_name}}}
  end

  @impl true
  def handle_continue({name, ip, port, family, transport_name}, nil) do
    listen_opts = [
      :binary,
      {:active, false},
      {:ip, ip},
      family,
      {:reuseaddr, true},
      {:nodelay, true},
      {:backlog, 128}
    ]

    case :gen_tcp.listen(port, listen_opts) do
      {:ok, listen_socket} ->
        Logger.debug(
          "#{inspect(self())} started transport " <>
            "#{stringify_ip(ip)}:#{port}/tcp (#{transport_name})"
        )

        state = %__MODULE__{
          listen_socket: listen_socket,
          family: family,
          sippet: name,
          transport_name: transport_name
        }

        # Start the acceptor loop in a linked process
        start_acceptor(listen_socket)

        {:noreply, state}

      {:error, reason} ->
        Logger.error(
          "#{inspect(self())} port #{port}/tcp " <>
            "#{inspect(reason)}, retrying in 10s..."
        )

        Process.sleep(10_000)
        {:noreply, nil, {:continue, {name, ip, port, family, transport_name}}}
    end
  end

  # -- Incoming connections --

  @impl true
  def handle_info({:tcp_accepted, client_socket}, state) do
    case :inet.peername(client_socket) do
      {:ok, {peer_ip, peer_port}} ->
        {:ok, _pid, new_state} = start_connection(state, client_socket, {peer_ip, peer_port})
        {:noreply, new_state}

      {:error, reason} ->
        Logger.warning("TCP transport: failed to get peer name: #{inspect(reason)}")
        :gen_tcp.close(client_socket)
        {:noreply, state}
    end
  end

  def handle_info({:DOWN, ref, :process, _pid, _reason}, state) do
    case Map.pop(state.monitors, ref) do
      {nil, _monitors} ->
        {:noreply, state}

      {peer, monitors} ->
        connections = Map.delete(state.connections, peer)
        {:noreply, %{state | connections: connections, monitors: monitors}}
    end
  end

  def handle_info(_msg, state) do
    {:noreply, state}
  end

  # -- Sending --

  @impl true
  def handle_call(
        {:send_message, message, to_host, to_port, key},
        _from,
        %{family: family, sippet: sippet} = state
      ) do
    Logger.debug([
      "sending message to #{stringify_hostport(to_host, to_port)}/tcp",
      ", #{inspect(key)}"
    ])

    with {:ok, to_ip} <- resolve_name(to_host, family),
         {:ok, conn_pid, state} <- get_or_connect(state, to_ip, to_port),
         iodata <- Message.to_iodata(message),
         :ok <- Connection.send_message(conn_pid, iodata) do
      {:reply, :ok, state}
    else
      {:error, reason} ->
        Logger.warning("tcp transport error for #{to_host}:#{to_port}: #{inspect(reason)}")

        if key != nil do
          Sippet.Router.receive_transport_error(sippet, key, reason)
        end

        {:reply, :ok, state}
    end
  end

  @impl true
  def terminate(reason, %{listen_socket: listen_socket}) when listen_socket != nil do
    Logger.debug("stopped tcp transport, reason: #{inspect(reason)}")
    :gen_tcp.close(listen_socket)
  end

  def terminate(_reason, _state), do: :ok

  # -- Connection management --

  defp get_or_connect(%{connections: connections} = state, ip, port) do
    case Map.get(connections, {ip, port}) do
      nil ->
        connect(state, ip, port)

      pid ->
        if Process.alive?(pid) do
          {:ok, pid, state}
        else
          # Stale entry – clean up and reconnect
          connections = Map.delete(connections, {ip, port})
          connect(%{state | connections: connections}, ip, port)
        end
    end
  end

  defp connect(state, ip, port) do
    connect_opts = [
      :binary,
      {:active, false},
      state.family,
      {:nodelay, true}
    ]

    case :gen_tcp.connect(ip, port, connect_opts, 5_000) do
      {:ok, socket} ->
        {:ok, conn_pid, new_state} = start_connection(state, socket, {ip, port})
        {:ok, conn_pid, new_state}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp start_connection(state, socket, {ip, port} = peer) do
    {:ok, pid} =
      Connection.start_link(
        socket: socket,
        sippet: state.sippet,
        transport_name: state.transport_name,
        peer: peer
      )

    Connection.activate(pid, socket)

    ref = Process.monitor(pid)
    connections = Map.put(state.connections, {ip, port}, pid)
    monitors = Map.put(state.monitors, ref, {ip, port})
    new_state = %{state | connections: connections, monitors: monitors}

    {ip_str, _} = peer
    Logger.debug("TCP connection established with #{stringify_ip(ip_str)}:#{port}")

    {:ok, pid, new_state}
  end

  # -- Acceptor --

  defp start_acceptor(listen_socket) do
    parent = self()
    spawn_link(fn -> accept_loop(parent, listen_socket) end)
  end

  defp accept_loop(parent, listen_socket) do
    case :gen_tcp.accept(listen_socket) do
      {:ok, client_socket} ->
        # Transfer ownership to the GenServer so it can delegate to Connection
        :gen_tcp.controlling_process(client_socket, parent)
        Kernel.send(parent, {:tcp_accepted, client_socket})
        accept_loop(parent, listen_socket)

      {:error, :closed} ->
        :ok

      {:error, reason} ->
        Logger.warning("TCP accept error: #{inspect(reason)}")
        Process.sleep(100)
        accept_loop(parent, listen_socket)
    end
  end

  # -- Helpers --

  defp resolve_name(host, family) when is_binary(host) do
    host
    |> String.to_charlist()
    |> :inet.getaddr(family)
  end

  defp resolve_name(host, family) when is_list(host) do
    :inet.getaddr(host, family)
  end

  defp resolve_name(host, _family) when is_tuple(host), do: {:ok, host}

  defp stringify_ip(ip) when is_tuple(ip) do
    ip |> :inet_parse.ntoa() |> to_string()
  end

  defp stringify_ip(ip), do: to_string(ip)

  defp stringify_hostport(host, port) do
    "#{host}:#{port}"
  end
end
