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
    * `:send_timeout` – socket send timeout in ms (`SO_SNDTIMEO`-like, with
      `send_timeout_close`) for every connection, so a peer that stops reading
      cannot block a send forever; `:infinity` disables (default 5 000)
    * `:connect_queue_size` – messages queued per peer while its connection is
      being set up; beyond that a message fails with `:connect_queue_full`
      (default 64)
    * `:max_pending_connects` – maximum number of outbound connects in progress
      at the same time (default 0 = unlimited)

  ## Asynchronous connect

  Outbound connections are opened by a short-lived helper process, so the
  transport never waits on `:gen_tcp.connect/4`: a peer that does not answer
  the SYN delays only the messages towards that peer. While a connect is in
  progress, messages for the peer are queued (see `:connect_queue_size`) and
  sent in order once it succeeds. If it fails, every queued message with a
  transaction key is reported through `Sippet.Router.receive_transport_error/3`.
  Connects in progress count towards `:max_connections` and `:conns_per_peer`.

  Messages are accepted both by `GenServer.call/3` and `GenServer.cast/2`
  (`{:send_message, message, host, port, key}`); the call always replies `:ok`
  and errors are reported through the transaction.

  ## Responses after the request connection has closed

  A response first reuses the connection its request arrived on
  (`source_peer`, RFC 3261 §18.2.2). When that connection is gone and the
  response carries a `fallback_target` `{transport, host, port}`, it is sent
  there instead of to the Via-derived destination: by this transport when it
  names this transport, otherwise forwarded to the named transport (e.g. the
  P-CSCF protected client port, TS 33.203 §7.1).
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
  @default_send_timeout 5_000
  @default_connect_queue_size 64
  @default_max_pending_connects 0
  @sweep_interval 30_000
  @min_accept_backoff 100
  @max_accept_backoff 5_000

  defstruct listen_socket: nil,
            local_ip: nil,
            local_port: nil,
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
            dscp: nil,
            egress_only: false,
            send_timeout: @default_send_timeout,
            connect_queue_size: @default_connect_queue_size,
            max_pending_connects: @default_max_pending_connects,
            connect_fun: &:gen_tcp.connect/4,
            # Outbound connects in progress: %{peer => %{pid, ref, queue, size}}
            # (queue in reverse order) and their monitors %{ref => peer}.
            connecting: %{},
            connectors: %{}

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

    send_timeout =
      case Keyword.get(options, :send_timeout, @default_send_timeout) do
        :infinity ->
          :infinity

        v when is_integer(v) and v > 0 ->
          v

        other ->
          raise ArgumentError,
                "expected :send_timeout to be a positive integer or :infinity, got: #{inspect(other)}"
      end

    connect_queue_size =
      max(Keyword.get(options, :connect_queue_size, @default_connect_queue_size), 1)

    max_pending_connects =
      Keyword.get(options, :max_pending_connects, @default_max_pending_connects)

    # Test hook: replaces :gen_tcp.connect/4 (same arity and return values).
    connect_fun = Keyword.get(options, :connect_fun, &:gen_tcp.connect/4)

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

    # Egress-only transports (e.g. the P-CSCF IPSec protected client port,
    # port_pc) send only: the P-CSCF opens outbound connections and receives
    # responses / in-dialog requests back on them, but MUST NOT accept new
    # inbound connections (TS 33.203 §7.4). We therefore do not create a
    # listening socket; inbound SYNs are refused by the kernel (RST).
    egress_only =
      case Keyword.fetch(options, :egress_only) do
        {:ok, true} -> true
        _ -> false
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
      dscp: dscp,
      egress_only: egress_only,
      send_timeout: send_timeout,
      connect_queue_size: connect_queue_size,
      max_pending_connects: max_pending_connects,
      connect_fun: connect_fun
    }

    GenServer.start_link(__MODULE__, {name, ip, port, family, transport_name, tcp_opts})
  end

  @doc """
  Force-closes pooled connections matching `matcher`, using an abortive
  (RST) close so the local sockets are freed immediately (no `FIN_WAIT`).

  `matcher` is one of:

    * `{:peers, [{ip, port}, ...]}` — close connections whose peer is exactly
      one of the given `{ip, port}` tuples (`ip` an `:inet.ip_address`).
    * `{:peer_ip, ip}` — close every connection whose peer IP is `ip`.

  Intended for tearing down connections whose underlying path is going away
  (e.g. an IPSec SA being deleted), where a clean FIN would never be
  acknowledged by an unreachable peer.
  """
  @spec close_peers(
          GenServer.server(),
          {:peers, [{:inet.ip_address(), :inet.port_number()}]} | {:peer_ip, :inet.ip_address()}
        ) :: :ok
  def close_peers(server, matcher) do
    GenServer.cast(server, {:close_peers, matcher})
  end

  @impl true
  def init({name, ip, port, family, transport_name, tcp_opts}) do
    if Map.get(tcp_opts, :egress_only, false) do
      init_egress_only(name, ip, port, family, transport_name, tcp_opts)
    else
      init_listening(name, ip, port, family, transport_name, tcp_opts)
    end
  end

  # Egress-only transport: send-only. No listening socket is created, so the
  # kernel refuses (RST) any inbound connection to this port. Outbound
  # connections still bind the local address:port via connect/3's
  # local_bind_opts, so P-CSCF-initiated flows and their return traffic
  # (responses + in-dialog requests) work normally.
  defp init_egress_only(name, ip, port, family, transport_name, tcp_opts) do
    Sippet.register_transport(name, transport_name, :tcp, true)

    Logger.debug(
      "#{inspect(self())} started egress-only transport " <>
        "#{stringify_ip(ip)}:#{port}/tcp (#{transport_name}) — inbound connections refused"
    )

    state = %__MODULE__{
      listen_socket: nil,
      local_ip: ip,
      local_port: port,
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
      dscp: tcp_opts.dscp,
      egress_only: true,
      send_timeout: tcp_opts.send_timeout,
      connect_queue_size: tcp_opts.connect_queue_size,
      max_pending_connects: tcp_opts.max_pending_connects,
      connect_fun: tcp_opts.connect_fun
    }

    schedule_sweep()
    {:ok, state}
  end

  defp init_listening(name, ip, port, family, transport_name, tcp_opts) do
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
        listen_reuseport_opts(tcp_opts.security_protected) ++
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
          local_ip: ip,
          local_port: port,
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
          dscp: tcp_opts.dscp,
          egress_only: false,
          send_timeout: tcp_opts.send_timeout,
          connect_queue_size: tcp_opts.connect_queue_size,
          max_pending_connects: tcp_opts.max_pending_connects,
          connect_fun: tcp_opts.connect_fun
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

  def handle_info({:tcp_connect_result, connector, peer, result}, state) do
    case Map.get(state.connecting, peer) do
      %{pid: ^connector, ref: ref} = pending ->
        Process.demonitor(ref, [:flush])
        state = drop_connecting(state, peer, ref)
        items = Enum.reverse(pending.queue)

        case result do
          {:ok, socket} ->
            {:ok, conn_pid, state} = start_connection(state, socket, peer, :outbound)
            {:noreply, flush_queued(state, conn_pid, items)}

          {:error, reason} ->
            {:noreply, fail_queued(state, items, reason)}
        end

      _ ->
        # Not the connect we are waiting for (should not happen): do not leak
        # the socket.
        with {:ok, socket} <- result, do: :gen_tcp.close(socket)
        {:noreply, state}
    end
  end

  def handle_info({:DOWN, ref, :process, _pid, reason}, %{connectors: connectors} = state)
      when is_map_key(connectors, ref) do
    # The connector died before reporting a result.
    peer = Map.fetch!(connectors, ref)
    %{queue: queue} = Map.fetch!(state.connecting, peer)
    state = drop_connecting(state, peer, ref)

    Logger.error(
      "[#{state.sippet}][#{transport_label(state)}] TCP connect to " <>
        "#{stringify_peer(peer)} crashed: #{inspect(reason)}"
    )

    {:noreply, fail_queued(state, Enum.reverse(queue), :connect_failed)}
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

  @impl true
  def handle_cast({:send_message, message, to_host, to_port, key}, state) do
    {:noreply, dispatch(state, message, to_host, to_port, key)}
  end

  def handle_cast({:close_peers, matcher}, state) do
    closed =
      for {peer, pids} <- state.connections, peer_matches?(peer, matcher), pid <- pids do
        Connection.force_close(pid)
        1
      end

    n = length(closed)

    if n > 0 do
      Logger.debug(
        "[#{state.sippet}][#{transport_label(state)}] force-closing #{n} connection(s) " <>
          "matching #{inspect(matcher)}"
      )
    end

    {:noreply, state}
  end

  # Matches a pooled connection's peer `{ip, port}` against a close matcher.
  defp peer_matches?({ip, _port}, {:peer_ip, ip}), do: true
  defp peer_matches?(_peer, {:peer_ip, _ip}), do: false
  defp peer_matches?(peer, {:peers, peers}), do: peer in peers
  defp peer_matches?(_peer, _matcher), do: false

  # -- Sending --

  @impl true
  def handle_call({:send_message, message, to_host, to_port, key}, _from, state) do
    # Never blocks on a connect; errors are reported through the transaction.
    {:reply, :ok, dispatch(state, message, to_host, to_port, key)}
  end

  def handle_call(:connection_count, _from, state) do
    {:reply, total_connections(state.connections), state}
  end

  @impl true
  def terminate(reason, %{listen_socket: listen_socket, connections: connections} = state)
      when listen_socket != nil do
    Logger.debug(
      "stopping tcp transport, reason: #{inspect(reason)}, draining #{total_connections(connections)} connections"
    )

    # Close the listen socket first to stop accepting new connections
    :gen_tcp.close(listen_socket)
    stop_connectors(state)

    # Stop all connection processes
    for {_peer, pids} <- connections, pid <- pids, Process.alive?(pid) do
      GenServer.stop(pid, :normal, 5_000)
    end
  end

  # Egress-only transport: no listen socket, but still drain any outbound
  # connection processes on shutdown.
  def terminate(reason, %{connections: connections} = state) do
    Logger.debug(
      "stopping egress-only tcp transport, reason: #{inspect(reason)}, " <>
        "draining #{total_connections(connections)} connections"
    )

    stop_connectors(state)

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

  # Sends (or queues, or forwards) one message and logs the outcome. Never
  # blocks on a connect. Returns the new state.
  defp dispatch(state, message, to_host, to_port, key) do
    # RFC 3261 §18.2.2: for a response over a reliable transport, reuse the
    # connection the originating request arrived on when it is still alive.
    {result, dest, state} =
      case reuse_connection(state, message) do
        {:ok, conn_pid} ->
          case send_on(conn_pid, message) do
            :ok -> {:ok, {to_host, to_port}, state}
            {:error, _reason} -> send_without_reuse(state, message, to_host, to_port, key)
          end

        :none ->
          send_without_reuse(state, message, to_host, to_port, key)
      end

    log_result(state, result, dest, key)
    state
  end

  # No reusable connection: use the response's fallback target when it has
  # one, else the given (Via-derived) destination.
  defp send_without_reuse(state, message, to_host, to_port, key) do
    case fallback_route(state, message) do
      {:forward, transport, host, port} ->
        {forward(state, transport, message, host, port, key), {host, port}, state}

      {:local, host, port} ->
        {result, state} = send_to_target(state, message, host, port, key)
        {result, {host, port}, state}

      :none ->
        {result, state} = send_to_target(state, message, to_host, to_port, key)
        {result, {to_host, to_port}, state}
    end
  end

  # A response's `fallback_target` (see the moduledoc) applies only once the
  # request connection is gone, i.e. only on this path.
  defp fallback_route(state, message) do
    case Map.get(message, :fallback_target) do
      {transport, host, port} when is_atom(transport) and is_integer(port) ->
        cond do
          not Message.response?(message) -> :none
          transport == state.transport_name -> {:local, host, port}
          true -> {:forward, transport, host, port}
        end

      _ ->
        :none
    end
  end

  # Hands the response to another transport of the same stack, which then
  # connects (asynchronously) to the fallback host and port. The forwarded copy
  # carries neither `source_peer` nor `fallback_target`, so it can only go to
  # the fallback destination.
  defp forward(state, transport, message, host, port, key) do
    case Registry.lookup(state.sippet, {:transport, transport}) do
      [{pid, _} | _] ->
        message = %{
          message
          | target: {transport, host, port},
            source_peer: nil,
            fallback_target: nil
        }

        GenServer.cast(pid, {:send_message, message, host, port, key})
        {:forwarded, transport}

      [] ->
        {:error, :no_transport}
    end
  end

  # Resolves the destination and sends on a pooled connection, or queues the
  # message behind a connect in progress (starting one if needed). Returns
  # `{:ok | :queued | {:error, reason}, state}`.
  defp send_to_target(%{family: family} = state, message, to_host, to_port, key) do
    case resolve_name(to_host, family) do
      {:ok, to_ip} ->
        route_to_peer(state, {to_ip, to_port}, {message, to_host, to_port, key})

      {:error, reason} ->
        {{:error, reason}, state}
    end
  end

  defp route_to_peer(state, peer, {message, _host, _port, _key} = item) do
    live = state.connections |> Map.get(peer, []) |> Enum.filter(&Process.alive?/1)
    state = %{state | connections: put_conns(state.connections, peer, live)}
    pending = Map.get(state.connecting, peer)

    cond do
      # Pool for this peer is full, or cannot grow right now: round-robin
      # across the existing connections.
      live != [] and
          (length(live) >= state.conns_per_peer or pending != nil or not can_connect?(state)) ->
        [pid | rest] = live
        state = %{state | connections: put_conns(state.connections, peer, rest ++ [pid])}
        {send_on(pid, message), state}

      pending != nil ->
        enqueue(state, peer, pending, item)

      pool_full?(state) ->
        {{:error, :max_connections}, state}

      connects_full?(state) ->
        {{:error, :max_pending_connects}, state}

      true ->
        {:queued, start_connect(state, peer, item)}
    end
  end

  defp enqueue(state, peer, %{size: size} = pending, item) do
    if size >= state.connect_queue_size do
      {{:error, :connect_queue_full}, state}
    else
      pending = %{pending | queue: [item | pending.queue], size: size + 1}
      {:queued, %{state | connecting: Map.put(state.connecting, peer, pending)}}
    end
  end

  # Runs the connect in a monitored helper process. The helper hands the socket
  # over to this process and reports `{:tcp_connect_result, helper, peer,
  # result}`; see handle_info/2.
  defp start_connect(state, {ip, port} = peer, item) do
    parent = self()
    connect_fun = state.connect_fun
    opts = connect_opts(state)
    timeout = state.connect_timeout
    security_protected = state.security_protected
    family = state.family

    {pid, ref} =
      spawn_monitor(fn ->
        result =
          case connect_fun.(ip, port, opts, timeout) do
            {:ok, socket} ->
              if security_protected do
                SocketPolicy.apply_xfrm_policy(socket, family, :tcp)
              end

              case :gen_tcp.controlling_process(socket, parent) do
                :ok ->
                  {:ok, socket}

                {:error, reason} ->
                  :gen_tcp.close(socket)
                  {:error, reason}
              end

            {:error, reason} ->
              {:error, reason}
          end

        send(parent, {:tcp_connect_result, self(), peer, result})
      end)

    Logger.debug(
      "[#{state.sippet}][#{transport_label(state)}] connecting to #{stringify_peer(peer)}/tcp"
    )

    pending = %{pid: pid, ref: ref, queue: [item], size: 1}

    %{
      state
      | connecting: Map.put(state.connecting, peer, pending),
        connectors: Map.put(state.connectors, ref, peer)
    }
  end

  defp connect_opts(state) do
    [
      :binary,
      {:active, false},
      state.family,
      {:nodelay, true}
    ] ++
      local_bind_opts(state) ++
      SocketPolicy.bind_to_device_opts(state.dev) ++
      SocketPolicy.dscp_opts(state.dscp)
  end

  defp drop_connecting(state, peer, ref) do
    %{
      state
      | connecting: Map.delete(state.connecting, peer),
        connectors: Map.delete(state.connectors, ref)
    }
  end

  # Sends the messages queued during the connect, in order.
  defp flush_queued(state, conn_pid, items) do
    Enum.each(items, fn {message, host, port, key} ->
      log_result(state, send_on(conn_pid, message), {host, port}, key)
    end)

    state
  end

  defp fail_queued(state, items, reason) do
    Enum.each(items, fn {_message, host, port, key} ->
      log_result(state, {:error, reason}, {host, port}, key)
    end)

    state
  end

  defp stop_connectors(%{connecting: connecting}) do
    for {_peer, %{pid: pid}} <- connecting, do: Process.exit(pid, :kill)
    :ok
  end

  # Connection.send_message/2 is a call: a connection that dies or does not
  # answer in time must fail this message, not crash the whole transport.
  defp send_on(conn_pid, message) do
    Connection.send_message(conn_pid, Message.to_iodata(message))
  catch
    :exit, {:timeout, _} -> {:error, :timeout}
    :exit, _reason -> {:error, :closed}
  end

  # Logs the actual outcome, so a logged send always reflects a real result,
  # and notifies the owning transaction of a failure so it can fail fast
  # instead of waiting for Timer B/F (requires a non-nil transaction key).
  defp log_result(state, :ok, {host, port}, key) do
    Logger.debug([
      "[#{state.sippet}][#{transport_label(state)}] sent message to #{stringify_hostport(host, port)}/tcp",
      ", #{inspect(key)}"
    ])
  end

  defp log_result(state, :queued, {host, port}, key) do
    Logger.debug([
      "[#{state.sippet}][#{transport_label(state)}] queued message to #{stringify_hostport(host, port)}/tcp",
      " until connected, #{inspect(key)}"
    ])
  end

  defp log_result(state, {:forwarded, transport}, {host, port}, key) do
    Logger.debug([
      "[#{state.sippet}][#{transport_label(state)}] request connection closed, response forwarded to ",
      "#{transport} for #{stringify_hostport(host, port)}/tcp, #{inspect(key)}"
    ])
  end

  defp log_result(state, {:error, reason}, {host, port}, key) do
    Logger.log(Sippet.Router.send_error_level(reason), [
      "[#{state.sippet}][#{transport_label(state)}] failed to send message to #{stringify_hostport(host, port)}/tcp",
      ", #{inspect(key)}: #{inspect(reason)}"
    ])

    if key != nil do
      Sippet.Router.receive_transport_error(state.sippet, key, reason)
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

  # For IPsec-protected (3GPP Gm) transports the outbound connection MUST
  # originate from the transport's own protected address and port (port_pc).
  # Otherwise the kernel picks a source address/ephemeral port that does not
  # match the XFRM OUT policy, so the packet egresses unprotected (in the
  # capture it went out from a link-local address in cleartext) and the UE
  # drops it. Binding the local end fixes this. Because the same address:port
  # is also held by this transport's listening socket, SO_REUSEPORT must be set
  # on BOTH sockets (SO_REUSEADDR alone yields :eaddrinuse against a socket in
  # LISTEN state); see listen_reuseport_opts/1.
  defp local_bind_opts(%{security_protected: true, local_ip: ip, local_port: port})
       when not is_nil(ip) and is_integer(port) do
    [{:ip, ip}, {:port, port}, {:reuseaddr, true}, {:reuseport, true}]
  end

  # For ordinary (non-IPsec) transports the outbound connection must still
  # originate from this transport's own configured local address. Otherwise the
  # kernel selects a source address that may not belong to this node's transport
  # set: e.g. when several 5G NFs share a subnet on the same host, an SCSCF
  # (192.168.60.33) NOTIFY to the PCSCF egressed with the PCSCF's own source IP
  # (192.168.60.31). Bind only the local IP and let the kernel pick an ephemeral
  # source port. Skip when the transport listens on a wildcard address, since
  # there is no single address to pin the outbound socket to.
  defp local_bind_opts(%{local_ip: ip}) when not is_nil(ip) do
    if wildcard_address?(ip), do: [], else: [{:ip, ip}]
  end

  defp local_bind_opts(_state), do: []

  defp wildcard_address?({0, 0, 0, 0}), do: true
  defp wildcard_address?({0, 0, 0, 0, 0, 0, 0, 0}), do: true
  defp wildcard_address?(_), do: false

  # SO_REUSEPORT on the listening socket so the outbound connect (above) may
  # share port_pc. Only enabled for IPsec-protected transports to avoid
  # changing bind semantics for ordinary listeners.
  defp listen_reuseport_opts(true), do: [{:reuseport, true}]
  defp listen_reuseport_opts(_), do: []

  defp start_connection(state, socket, {ip, port} = peer, direction) do
    keepalive_interval =
      if state.keepalive_enabled, do: state.keepalive_interval, else: 0

    # Bound :gen_tcp.send/2 so a peer that stops reading closes the connection
    # instead of blocking its Connection (and the transport calling it).
    _ = :inet.setopts(socket, send_timeout_opts(state.send_timeout))

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

  # Connects in progress count towards the limit.
  defp pool_full?(%{max_connections: max, connections: connections, connecting: connecting}) do
    total_connections(connections) + map_size(connecting) >= max
  end

  defp connects_full?(%{max_pending_connects: max, connecting: connecting})
       when is_integer(max) and max > 0,
       do: map_size(connecting) >= max

  defp connects_full?(_state), do: false

  defp can_connect?(state), do: not pool_full?(state) and not connects_full?(state)

  defp send_timeout_opts(:infinity), do: []
  defp send_timeout_opts(ms), do: [{:send_timeout, ms}, {:send_timeout_close, true}]

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

  defp stringify_peer({ip, port}), do: "#{stringify_ip(ip)}:#{port}"

  defp transport_label(%{sippet: sippet, transport_name: tn}) do
    prefix = Atom.to_string(sippet) <> "_"
    full = Atom.to_string(tn)

    case String.split(full, prefix, parts: 2) do
      ["", local] -> local
      _ -> full
    end
  end
end
