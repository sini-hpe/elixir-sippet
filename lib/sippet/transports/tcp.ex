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
    * `:dev` – bind the listening and outbound sockets to a network device
      (SO_BINDTODEVICE); `nil` disables (default)
    * `:security_protected` – require IPSec (ESP) protection via IP_XFRM_POLICY
      on the listening and outbound sockets (default false)
    * `:dscp` – DSCP value (0..63) written to the IP TOS byte (default nil)
  """

  use GenServer

  alias Sippet.Message
  alias Sippet.Transports.SocketPolicy
  alias Sippet.Transports.TCP.Connection

  require Logger

  @default_idle_timeout 120_000
  @default_message_timeout 10_000
  @default_connect_timeout 5_000
  @default_max_connections 0
  @default_keepalive_interval 30_000
  @default_conns_per_peer 1
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
            conns_per_peer: @default_conns_per_peer,
            keepalive_enabled: false,
            keepalive_interval: @default_keepalive_interval,
            dev: nil,
            security_protected: false,
            dscp: nil

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
    conns_per_peer = Keyword.get(options, :conns_per_peer, @default_conns_per_peer)
    keepalive_enabled = Keyword.get(options, :keepalive_enabled, false)
    keepalive_interval = Keyword.get(options, :keepalive_interval, @default_keepalive_interval)

    dev =
      case Keyword.fetch(options, :dev) do
        {:ok, d} when is_binary(d) and d != "" -> d
        _ -> nil
      end

    security_protected =
      case Keyword.fetch(options, :security_protected) do
        {:ok, true} -> true
        _ -> false
      end

    dscp =
      case Keyword.fetch(options, :dscp) do
        {:ok, v} when is_integer(v) and v >= 0 and v <= 63 -> v
        _ -> nil
      end

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
      conns_per_peer: max(conns_per_peer, 1),
      keepalive_enabled: keepalive_enabled,
      keepalive_interval: keepalive_interval,
      dev: dev,
      security_protected: security_protected,
      dscp: dscp
    }

    GenServer.start_link(__MODULE__, {name, ip, port, family, transport_name, tcp_opts})
  end

  @impl true
  def init({name, ip, port, family, transport_name, tcp_opts}) do
    # Bind the listening socket synchronously so that start_link only returns
    # {:ok, pid} once the socket is actually bound and the acceptor is running.
    # A bind failure (bad port, address in use, bad device) fails the start
    # loudly via {:stop, reason} instead of silently retrying.
    listen_opts =
      [
        :binary,
        {:active, false},
        {:ip, ip},
        family,
        {:reuseaddr, true},
        {:nodelay, true},
        {:backlog, 128}
      ] ++
        SocketPolicy.bind_to_device_opts(tcp_opts.dev) ++
        SocketPolicy.dscp_opts(tcp_opts.dscp)

    case :gen_tcp.listen(port, listen_opts) do
      {:ok, listen_socket} ->
        if tcp_opts.security_protected do
          SocketPolicy.apply_xfrm_policy(listen_socket, family, :tcp)
        end

        # Register only after the socket is bound, so the router never routes
        # to a transport whose socket is not ready.
        Sippet.register_transport(name, transport_name, :tcp, true)

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
          conns_per_peer: Map.get(tcp_opts, :conns_per_peer, @default_conns_per_peer),
          keepalive_enabled: tcp_opts.keepalive_enabled,
          keepalive_interval: tcp_opts.keepalive_interval,
          dev: tcp_opts.dev,
          security_protected: tcp_opts.security_protected,
          dscp: tcp_opts.dscp
        }

        # Start the acceptor loop in a linked process
        start_acceptor(listen_socket)

        # Start periodic stale connection sweep
        schedule_sweep()

        {:ok, state}

      {:error, reason} ->
        Logger.error(
          "#{inspect(self())} failed to bind #{stringify_ip(ip)}:#{port}/tcp " <>
            "(#{transport_name}): #{inspect(reason)}"
        )

        {:stop, {:listen_failed, reason}}
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
              "(#{total_connections(state.connections)}), rejecting #{stringify_ip(peer_ip)}:#{peer_port}"
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

      {{peer, pid}, monitors} ->
        emit_tcp_closed(state, "normal")

        {:noreply,
         %{state | connections: drop_conn(state.connections, peer, pid), monitors: monitors}}
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
        state
      ) do
    # RFC 3261 §18.2.2: for a response over a reliable transport, reuse the
    # connection the originating request arrived on when it is still alive.
    # Falls back to the Via-derived target below when no such connection exists.
    {result, state} =
      case reuse_connection(state, message) do
        {:ok, conn_pid} ->
          case Connection.send_message(conn_pid, Message.to_iodata(message)) do
            :ok -> {:ok, state}
            {:error, _reason} -> send_to_target(state, message, to_host, to_port)
          end

        :none ->
          send_to_target(state, message, to_host, to_port)
      end

    # Log the actual outcome so a logged send always reflects a real result.
    case result do
      :ok ->
        Logger.debug([
          "[#{state.sippet}][#{transport_label(state)}] sent message to #{stringify_hostport(to_host, to_port)}/tcp",
          ", #{inspect(key)}"
        ])

      {:error, reason} ->
        Logger.log(Sippet.Router.send_error_level(reason), [
          "[#{state.sippet}][#{transport_label(state)}] failed to send message to #{stringify_hostport(to_host, to_port)}/tcp",
          ", #{inspect(key)}: #{inspect(reason)}"
        ])

        # Notify the owning transaction so it can fail fast instead of waiting
        # for Timer B/F. Requires a non-nil transaction key from the caller.
        if key != nil do
          Sippet.Router.receive_transport_error(state.sippet, key, reason)
        end
    end

    {:reply, :ok, state}
  end

  def handle_call(:connection_count, _from, state) do
    {:reply, total_connections(state.connections), state}
  end

  @impl true
  def terminate(reason, %{listen_socket: listen_socket, connections: connections})
      when listen_socket != nil do
    Logger.debug(
      "stopping tcp transport, reason: #{inspect(reason)}, draining #{total_connections(connections)} connections"
    )

    # Close the listen socket first to stop accepting new connections
    :gen_tcp.close(listen_socket)

    # Stop all connection processes
    for {_peer, pids} <- connections, pid <- pids, Process.alive?(pid) do
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

  # Resolve the Via-derived destination and send, opening a connection (or
  # round-robining across the per-peer pool) as needed. Returns
  # `{:ok, state}` or `{{:error, reason}, state}`; logging and transaction
  # error notification are handled by the caller.
  defp send_to_target(%{family: family} = state, message, to_host, to_port) do
    with {:ok, to_ip} <- resolve_name(to_host, family),
         {:ok, conn_pid, state} <- get_or_connect(state, to_ip, to_port),
         :ok <- Connection.send_message(conn_pid, Message.to_iodata(message)) do
      {:ok, state}
    else
      {:error, reason} ->
        {{:error, reason}, state}
    end
  end

  # RFC 3261 §18.2.2: a response over a reliable transport reuses the connection
  # the originating request arrived on. `source_peer` is the request's peer
  # {ip, port}; it is only set on responses (see the server transaction).
  defp reuse_connection(state, message) do
    with true <- Message.response?(message),
         {ip, port} when not is_nil(ip) <- Map.get(message, :source_peer),
         [pid | _] <-
           state.connections |> Map.get({ip, port}, []) |> Enum.filter(&Process.alive?/1) do
      {:ok, pid}
    else
      _ -> :none
    end
  end

  defp get_or_connect(%{connections: connections} = state, ip, port) do
    key = {ip, port}
    live = connections |> Map.get(key, []) |> Enum.filter(&Process.alive?/1)
    state = %{state | connections: put_conns(connections, key, live)}

    cond do
      length(live) >= state.conns_per_peer ->
        # Pool for this peer is full – round-robin across existing connections.
        [pid | rest] = live
        {:ok, pid, %{state | connections: put_conns(state.connections, key, rest ++ [pid])}}

      pool_full?(state) ->
        case live do
          [pid | _] -> {:ok, pid, state}
          [] -> {:error, :max_connections}
        end

      true ->
        connect(state, ip, port)
    end
  end

  defp connect(state, ip, port) do
    connect_opts =
      [
        :binary,
        {:active, false},
        state.family,
        {:nodelay, true}
      ] ++
        SocketPolicy.bind_to_device_opts(state.dev) ++
        SocketPolicy.dscp_opts(state.dscp)

    case :gen_tcp.connect(ip, port, connect_opts, state.connect_timeout) do
      {:ok, socket} ->
        if state.security_protected do
          SocketPolicy.apply_xfrm_policy(socket, state.family, :tcp)
        end

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
    key = {ip, port}
    pids = Map.get(state.connections, key, [])
    connections = Map.put(state.connections, key, pids ++ [pid])
    monitors = Map.put(state.monitors, ref, {key, pid})
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

  # Connections are stored as %{{ip, port} => [pid]} so a peer may hold a small
  # pool of parallel connections (request fan-out) plus any inbound connections.
  defp total_connections(connections) do
    Enum.reduce(connections, 0, fn {_peer, pids}, acc -> acc + length(pids) end)
  end

  defp put_conns(connections, key, []), do: Map.delete(connections, key)
  defp put_conns(connections, key, pids), do: Map.put(connections, key, pids)

  defp drop_conn(connections, key, pid) do
    pids = connections |> Map.get(key, []) |> List.delete(pid)
    put_conns(connections, key, pids)
  end

  defp pool_full?(%{max_connections: 0}), do: false

  defp pool_full?(%{max_connections: max, connections: connections}) do
    total_connections(connections) >= max
  end

  defp sweep_stale_connections(state) do
    {connections, stale_count} =
      Enum.reduce(state.connections, {%{}, 0}, fn {peer, pids}, {acc, count} ->
        live = Enum.filter(pids, &Process.alive?/1)
        {put_conns(acc, peer, live), count + (length(pids) - length(live))}
      end)

    stale_refs =
      for {ref, {_key, pid}} <- state.monitors, not Process.alive?(pid), do: ref

    if stale_count > 0 do
      Logger.debug(
        "[#{state.sippet}][#{transport_label(state)}] sweeping #{stale_count} stale TCP connections"
      )
    end

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
