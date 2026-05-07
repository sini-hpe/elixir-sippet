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

  ## Options

    * `:idle_timeout` – per-connection idle timeout in ms (default 120 000)
    * `:message_timeout` – per-connection SIP header read timeout in ms (default 10 000)
    * `:connect_timeout` – outbound TCP connect timeout in ms (default 5 000)
    * `:max_connections` – maximum number of pooled connections (default 0 = unlimited)
    * `:keepalive_enabled` – whether to send CRLF keep-alive pings (default false)
    * `:keepalive_interval` – interval in ms between CRLF pings (default 30 000)
  """

  use GenServer

  alias Sippet.Message
  alias Sippet.Transports.TCP.Connection

  require Logger

  @default_idle_timeout 120_000
  @default_message_timeout 10_000
  @default_connect_timeout 5_000
  @default_max_connections 0
  @default_keepalive_interval 30_000
  @sweep_interval 30_000
  @min_accept_backoff 100
  @max_accept_backoff 5_000

  defstruct listen_socket: nil,
            family: :inet,
            sippet: nil,
            transport_name: nil,
            connections: %{},
            monitors: %{},
            idle_timeout: @default_idle_timeout,
            message_timeout: @default_message_timeout,
            connect_timeout: @default_connect_timeout,
            max_connections: @default_max_connections,
            keepalive_enabled: false,
            keepalive_interval: @default_keepalive_interval

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

    idle_timeout = Keyword.get(options, :idle_timeout, @default_idle_timeout)
    message_timeout = Keyword.get(options, :message_timeout, @default_message_timeout)
    connect_timeout = Keyword.get(options, :connect_timeout, @default_connect_timeout)
    max_connections = Keyword.get(options, :max_connections, @default_max_connections)
    keepalive_enabled = Keyword.get(options, :keepalive_enabled, false)
    keepalive_interval = Keyword.get(options, :keepalive_interval, @default_keepalive_interval)

    ip =
      case resolve_name(address, family) do
        {:ok, ip} ->
          ip

        {:error, reason} ->
          raise ArgumentError,
                ":address contains an invalid IP or DNS name, got: #{inspect(reason)}"
      end

    tcp_opts = %{
      idle_timeout: idle_timeout,
      message_timeout: message_timeout,
      connect_timeout: connect_timeout,
      max_connections: max_connections,
      keepalive_enabled: keepalive_enabled,
      keepalive_interval: keepalive_interval
    }

    GenServer.start_link(__MODULE__, {name, ip, port, family, transport_name, tcp_opts})
  end

  @impl true
  def init({name, ip, port, family, transport_name, tcp_opts}) do
    Sippet.register_transport(name, transport_name, :tcp, true)
    {:ok, nil, {:continue, {name, ip, port, family, transport_name, tcp_opts}}}
  end

  @impl true
  def handle_continue({name, ip, port, family, transport_name, tcp_opts}, nil) do
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
          transport_name: transport_name,
          idle_timeout: tcp_opts.idle_timeout,
          message_timeout: tcp_opts.message_timeout,
          connect_timeout: tcp_opts.connect_timeout,
          max_connections: tcp_opts.max_connections,
          keepalive_enabled: tcp_opts.keepalive_enabled,
          keepalive_interval: tcp_opts.keepalive_interval
        }

        # Start the acceptor loop in a linked process
        start_acceptor(listen_socket)

        # Start periodic stale connection sweep
        schedule_sweep()

        {:noreply, state}

      {:error, reason} ->
        Logger.error(
          "#{inspect(self())} port #{port}/tcp " <>
            "#{inspect(reason)}, retrying in 10s..."
        )

        Process.sleep(10_000)
        {:noreply, nil, {:continue, {name, ip, port, family, transport_name, tcp_opts}}}
    end
  end

  # -- Incoming connections --

  @impl true
  def handle_info({:tcp_accepted, client_socket}, state) do
    case :inet.peername(client_socket) do
      {:ok, {peer_ip, peer_port}} ->
        if pool_full?(state) do
          Logger.warning(
            "[#{state.sippet}][#{transport_label(state)}] TCP max_connections reached " <>
              "(#{map_size(state.connections)}), rejecting #{stringify_ip(peer_ip)}:#{peer_port}"
          )

          :gen_tcp.close(client_socket)
          emit_tcp_closed(state, "max_connections")
          {:noreply, state}
        else
          {:ok, _pid, new_state} =
            start_connection(state, client_socket, {peer_ip, peer_port}, :inbound)

          {:noreply, new_state}
        end

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
        emit_tcp_closed(state, "normal")
        {:noreply, %{state | connections: connections, monitors: monitors}}
    end
  end

  def handle_info(:sweep_stale, state) do
    new_state = sweep_stale_connections(state)
    schedule_sweep()
    {:noreply, new_state}
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
      "[#{state.sippet}][#{transport_label(state)}] sending message to #{stringify_hostport(to_host, to_port)}/tcp",
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

  def handle_call(:connection_count, _from, state) do
    {:reply, map_size(state.connections), state}
  end

  @impl true
  def terminate(reason, %{listen_socket: listen_socket, connections: connections})
      when listen_socket != nil do
    Logger.debug(
      "stopping tcp transport, reason: #{inspect(reason)}, draining #{map_size(connections)} connections"
    )

    # Close the listen socket first to stop accepting new connections
    :gen_tcp.close(listen_socket)

    # Stop all connection processes
    for {_peer, pid} <- connections, Process.alive?(pid) do
      GenServer.stop(pid, :normal, 5_000)
    end
  end

  def terminate(_reason, _state), do: :ok

  @doc """
  Returns the number of active connections in the pool.
  """
  @spec connection_count(pid()) :: non_neg_integer()
  def connection_count(pid) do
    GenServer.call(pid, :connection_count, 5_000)
  end

  # -- Connection management --

  defp get_or_connect(%{connections: connections} = state, ip, port) do
    case Map.get(connections, {ip, port}) do
      nil ->
        if pool_full?(state) do
          {:error, :max_connections}
        else
          connect(state, ip, port)
        end

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

    case :gen_tcp.connect(ip, port, connect_opts, state.connect_timeout) do
      {:ok, socket} ->
        {:ok, conn_pid, new_state} = start_connection(state, socket, {ip, port}, :outbound)
        {:ok, conn_pid, new_state}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp start_connection(state, socket, {ip, port} = peer, direction) do
    keepalive_interval =
      if state.keepalive_enabled, do: state.keepalive_interval, else: 0

    {:ok, pid} =
      Connection.start_link(
        socket: socket,
        sippet: state.sippet,
        transport_name: state.transport_name,
        peer: peer,
        idle_timeout: state.idle_timeout,
        message_timeout: state.message_timeout,
        keepalive_interval: keepalive_interval
      )

    Connection.activate(pid, socket)

    ref = Process.monitor(pid)
    connections = Map.put(state.connections, {ip, port}, pid)
    monitors = Map.put(state.monitors, ref, {ip, port})
    new_state = %{state | connections: connections, monitors: monitors}

    {ip_str, _} = peer
    Logger.debug("TCP connection established with #{stringify_ip(ip_str)}:#{port}")

    emit_tcp_opened(state, to_string(direction))

    {:ok, pid, new_state}
  end

  # -- Acceptor --

  defp start_acceptor(listen_socket) do
    parent = self()
    spawn_link(fn -> accept_loop(parent, listen_socket, @min_accept_backoff) end)
  end

  defp accept_loop(parent, listen_socket, _backoff) do
    case :gen_tcp.accept(listen_socket) do
      {:ok, client_socket} ->
        # Transfer ownership to the GenServer so it can delegate to Connection
        :gen_tcp.controlling_process(client_socket, parent)
        Kernel.send(parent, {:tcp_accepted, client_socket})
        accept_loop(parent, listen_socket, @min_accept_backoff)

      {:error, :closed} ->
        :ok

      {:error, reason} ->
        Logger.warning("TCP accept error: #{inspect(reason)}")
        Process.sleep(@min_accept_backoff)
        next_backoff = min(@min_accept_backoff * 2, @max_accept_backoff)
        accept_loop(parent, listen_socket, next_backoff)
    end
  end

  # -- Pool helpers --

  defp pool_full?(%{max_connections: 0}), do: false

  defp pool_full?(%{max_connections: max, connections: connections}) do
    map_size(connections) >= max
  end

  defp sweep_stale_connections(state) do
    {stale_peers, stale_refs} =
      Enum.reduce(state.connections, {[], []}, fn {peer, pid}, {peers, refs} ->
        if Process.alive?(pid) do
          {peers, refs}
        else
          ref =
            Enum.find_value(state.monitors, fn
              {r, ^peer} -> r
              _ -> nil
            end)

          {[peer | peers], if(ref, do: [ref | refs], else: refs)}
        end
      end)

    if stale_peers != [] do
      Logger.debug(
        "[#{state.sippet}][#{transport_label(state)}] sweeping #{length(stale_peers)} stale TCP connections"
      )
    end

    connections = Map.drop(state.connections, stale_peers)
    monitors = Map.drop(state.monitors, stale_refs)
    %{state | connections: connections, monitors: monitors}
  end

  defp schedule_sweep do
    Process.send_after(self(), :sweep_stale, @sweep_interval)
  end

  # -- Metrics emission --

  defp emit_tcp_opened(state, direction) do
    {stack, transport} = metric_labels(state)
    Sip.Stats.tcp_connection_opened(stack, transport, direction)
  rescue
    _ -> :ok
  end

  defp emit_tcp_closed(state, cause) do
    {stack, transport} = metric_labels(state)
    Sip.Stats.tcp_connection_closed(stack, transport, cause)
  rescue
    _ -> :ok
  end

  defp metric_labels(%{sippet: sippet, transport_name: tname}) do
    stack = Sip.Stats.stack_label(sippet)
    transport = Sip.Stats.transport_label(tname, sippet)
    {stack, transport}
  rescue
    _ -> {to_string(sippet), to_string(tname)}
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

  defp transport_label(%{sippet: sippet, transport_name: tn}) do
    prefix = Atom.to_string(sippet) <> "_"
    full = Atom.to_string(tn)

    case String.split(full, prefix, parts: 2) do
      ["", local] -> local
      _ -> full
    end
  end
end
