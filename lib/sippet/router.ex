defmodule Sippet.Router do
  @moduledoc false

  alias Sippet.{Message, Transactions, URI}
  alias Sippet.Message.{RequestLine, StatusLine}

  require Logger

  import Sippet, only: [supervisor_name: 1]

  # Telemetry event names (pre-built to avoid allocation on hot path)
  @event_msg_received [:sippet, :message, :received]
  @event_msg_sent [:sippet, :message, :sent]
  @event_msg_parse_error [:sippet, :message, :parse_error]
  @event_txn_started [:sippet, :transaction, :started]

  @doc false
  def handle_transport_message(sippet, iodata, from, source_transport \\ nil)

  def handle_transport_message(sippet, iodata, from, source_transport) when is_list(iodata) do
    binary =
      iodata
      |> IO.iodata_to_binary()

    handle_transport_message(sippet, binary, from, source_transport)
  end

  def handle_transport_message(_sippet, "", _from, _source_transport), do: :ok

  def handle_transport_message(sippet, "\n" <> rest, from, source_transport),
    do: handle_transport_message(sippet, rest, from, source_transport)

  def handle_transport_message(sippet, "\r\n" <> rest, from, source_transport),
    do: handle_transport_message(sippet, rest, from, source_transport)

  def handle_transport_message(sippet, raw, from, source_transport) do
    if sharded_transactions?() do
      # Sharded mode: cast to parse pool for async parsing + shard routing.
      # This frees the transport process to receive the next packet immediately.
      sharded_handler().handle_transport_message(sippet, raw, from, source_transport)
    else
      handle_transport_message_legacy(sippet, raw, from, source_transport)
    end
  end

  defp handle_transport_message_legacy(sippet, raw, from, source_transport) do
    with {:ok, message} <- parse_message(raw),
         prepared_message <- update_via(message, from),
         prepared_message <- %{
           prepared_message
           | source: source_transport,
             source_peer: source_peer(from)
         },
         :ok <- Message.validate(prepared_message, from) do
      :telemetry.execute(@event_msg_received, %{byte_size: byte_size(raw)}, %{
        sippet: sippet,
        kind: message_kind(prepared_message),
        method: message_method(prepared_message)
      })

      receive_transport_message(sippet, prepared_message)
    else
      {:error, reason} ->
        :telemetry.execute(@event_msg_parse_error, %{count: 1}, %{
          sippet: sippet,
          reason: reason
        })

        Logger.error(fn ->
          {protocol, address, port} = from

          [
            "discarded message from ",
            "#{ip_to_string(address)}:#{port}/#{protocol}: ",
            "#{inspect(reason)}"
          ]
        end)

        # RFC 3261 §18.3: for malformed requests, SHOULD send 400 Bad Request.
        # For responses, silently discard (already done by not acting).
        maybe_send_400(sippet, raw, from, source_transport, reason)
    end
  end

  # RFC 3261 §18.3: If a malformed message is a request, the element SHOULD
  # generate a 400 (Bad Request) response.  For responses, silently discard.
  # We re-parse the raw bytes (headers only) to extract enough to build a
  # response.  If even header parsing fails, there is nothing we can do.
  defp maybe_send_400(sippet, raw, from, source_transport, reason) do
    {_protocol, address, port} = from

    with [header | _] <- String.split(raw, ~r{\r?\n\r?\n}, parts: 2),
         {:ok, %Message{start_line: %RequestLine{}} = request} <- Message.parse(header) do
      request = update_via(request, from)
      host = ip_to_string(address)
      reason_str = to_string(reason)

      response =
        request
        |> Message.to_response(400)
        |> Map.put(:body, reason_str)
        |> Map.put(:target, {source_transport, host, port})
        |> Message.put_header(:content_length, byte_size(reason_str))

      send_transport_message(sippet, response, nil)
    else
      _ -> :ok
    end
  rescue
    e ->
      Logger.warning("failed to send 400 for malformed message: #{inspect(e)}")
  end

  defp parse_message(packet) do
    case String.split(packet, ~r{\r?\n\r?\n}, parts: 2) do
      [header, body] ->
        parse_message(header, body)

      [header] ->
        parse_message(header, "")
    end
  end

  # Extract the peer {ip, port} from the transport `from` tuple so responses
  # can reuse the connection the request arrived on (RFC 3261 §18.2.2).
  defp source_peer({_protocol, ip, port}), do: {ip, port}
  defp source_peer(_), do: nil

  defp parse_message(header, body) do
    case Message.parse(header) do
      {:ok, message} -> {:ok, %{message | body: body}}
      other -> other
    end
  end

  defp ip_to_string(ip) when is_binary(ip), do: ip
  defp ip_to_string(ip) when is_tuple(ip), do: :inet.ntoa(ip) |> to_string()

  defp update_via(%Message{start_line: %RequestLine{}} = request, {:wss, _ip, _from_port}),
    do: request

  defp update_via(%Message{start_line: %RequestLine{}} = request, {:ws, _ip, _from_port}),
    do: request

  defp update_via(%Message{start_line: %RequestLine{}} = request, {_protocol, ip, from_port}) do
    request
    |> Message.update_header_front(:via, fn
      {version, protocol, {via_host, via_port}, params} ->
        host = ip |> ip_to_string()

        params =
          if host != via_host do
            params |> Map.put("received", host)
          else
            params
          end

        params =
          if from_port != via_port do
            params |> Map.put("rport", to_string(from_port))
          else
            params
          end

        {version, protocol, {via_host, via_port}, params}
    end)
  end

  defp update_via(%Message{start_line: %StatusLine{}} = response, _from), do: response

  # Transient/operational send failures (remote unreachable, congestion, peer
  # reset). These are environmental and expected in the field, so they are
  # logged at :warning. Every other reason — including wrong parameters
  # (:einval, :badarg), a dead/closed local socket (:closed, :enotconn, :ebadf,
  # :epipe), an oversized datagram (:emsgsize) and unresolved names (:nxdomain)
  # — points at a bug or misconfiguration and is logged at :error.
  @transient_send_errors [
    :ehostunreach,
    :enetunreach,
    :eagain,
    :etimedout,
    :econnrefused,
    :econnreset,
    :enobufs,
    :timeout
  ]

  @doc """
  Classifies a socket send-failure reason into a `Logger` level.

  Returns `:warning` for known transient/operational errors and `:error` for
  everything else (buggy situations: wrong parameters, closed/wrong socket,
  oversized datagram, name resolution failure, or any unrecognised reason).
  """
  @spec send_error_level(term()) :: :warning | :error
  def send_error_level(reason) when reason in @transient_send_errors, do: :warning
  def send_error_level(_reason), do: :error

  @doc false
  def receive_transport_error(sippet, transaction_key, reason) do
    if sharded_transactions?() do
      sharded_handler().receive_transport_error(sippet, transaction_key, reason)
    else
      receive_transport_error_legacy(sippet, transaction_key, reason)
    end
  end

  defp receive_transport_error_legacy(sippet, transaction_key, reason) do
    case Registry.lookup(sippet, {:transaction, transaction_key}) do
      [] ->
        Logger.warning(fn ->
          case transaction_key do
            %Transactions.Client.Key{} ->
              "client key #{inspect(transaction_key)} not found"

            %Transactions.Server.Key{} ->
              "server key #{inspect(transaction_key)} not found"
          end
        end)

      [{pid, _}] ->
        # Send the response through the existing server key.
        case transaction_key do
          %Transactions.Client.Key{} ->
            Transactions.Client.receive_error(pid, reason)

          %Transactions.Server.Key{} ->
            Transactions.Server.receive_error(pid, reason)
        end
    end

    :ok
  end

  @doc false
  def send_transport_message(sippet, message, key) do
    {protocol, host, port} = get_destination(message)

    result =
      case Registry.meta(sippet, {:udp_socket, protocol}) do
        {:ok, {socket, family}} ->
          # Direct UDP send — bypass GenServer to avoid single-process bottleneck
          send_udp_direct(socket, family, sippet, message, host, port, key)

        :error ->
          # TCP or other transport — route through GenServer
          GenServer.call(
            {:via, Registry, {sippet, {:transport, protocol}}},
            {:send_message, message, host, port, key}
          )
      end

    :telemetry.execute(@event_msg_sent, %{count: 1}, %{
      sippet: sippet,
      kind: message_kind(message),
      method: message_method(message)
    })

    result
  end

  defp send_udp_direct(socket, family, sippet, message, host, port, key) do
    with {:ok, to_ip} <- host |> String.to_charlist() |> :inet.getaddr(family),
         iodata <- Message.to_iodata(message),
         :ok <- :gen_udp.send(socket, {to_ip, port}, iodata) do
      :ok
    else
      {:error, reason} ->
        Logger.log(
          send_error_level(reason),
          "[#{sippet}] udp direct send failed to #{host}:#{port}/udp, #{inspect(key)}: #{inspect(reason)}"
        )

        if key != nil do
          receive_transport_error(sippet, key, reason)
        end
    end
  end

  @doc false
  def to_core(sippet, fun, args) do
    case Registry.meta(sippet, :core) do
      :error ->
        raise RuntimeError, "Core not initialized"

      {:ok, module} ->
        Process.put(:sippet_calling, sippet)
        apply(module, fun, args)
    end
  end

  @doc false
  def send_transaction_request(sippet, %Message{start_line: %RequestLine{}} = outgoing_request) do
    if sharded_transactions?() do
      sharded_handler().send_transaction_request(sippet, outgoing_request)
    else
      send_transaction_request_legacy(sippet, outgoing_request)
    end
  end

  defp send_transaction_request_legacy(sippet, outgoing_request) do
    transaction = Transactions.Client.Key.new(outgoing_request)

    # Create a new client transaction now. The request is passed to the
    # transport once it starts.
    case start_client(sippet, transaction, outgoing_request) do
      {:ok, _} ->
        :ok

      {:ok, _, _} ->
        :ok

      _errors ->
        Logger.warning(fn ->
          "client transaction #{transaction} already exists"
        end)

        {:error, :already_started}
    end
  end

  @doc false
  def send_transaction_response(sippet, %Message{start_line: %StatusLine{}} = outgoing_response) do
    if sharded_transactions?() do
      sharded_handler().send_transaction_response(sippet, outgoing_response)
    else
      send_transaction_response_legacy(sippet, outgoing_response)
    end
  end

  defp send_transaction_response_legacy(sippet, outgoing_response) do
    server_key = Transactions.Server.Key.new(outgoing_response)

    case Registry.lookup(sippet, {:transaction, server_key}) do
      [] ->
        {:error, :no_transaction}

      [{pid, _}] ->
        # Send the response through the existing server transaction.
        Transactions.Server.send_response(pid, outgoing_response)
    end
  end

  @doc false
  defp receive_transport_message(sippet, %Message{start_line: %RequestLine{}} = incoming_request) do
    transaction = Transactions.Server.Key.new(incoming_request)

    case Registry.lookup(sippet, {:transaction, transaction}) do
      [] ->
        if incoming_request.start_line.method == :ack do
          # Redirect to the core directly. ACKs sent out of transactions
          # pertain to the core.
          to_core(sippet, :receive_request, [incoming_request, nil])
        else
          # Start a new server transaction now. The transaction will redirect
          # to the core once it starts. It will return errors only if there was
          # some kind of race condition when receiving the request.
          start_server(sippet, transaction, incoming_request)
        end

      [{pid, _}] ->
        # Redirect the request to the existing transaction. These are tipically
        # retransmissions or ACKs for 200 OK responses.
        Transactions.Server.receive_request(pid, incoming_request)
    end
  end

  @doc false
  defp receive_transport_message(sippet, %Message{start_line: %StatusLine{}} = incoming_response) do
    transaction = Transactions.Client.Key.new(incoming_response)

    case Registry.lookup(sippet, {:transaction, transaction}) do
      [] ->
        # Redirect the response to core. These are tipically retransmissions of
        # 200 OK for sent INVITE requests, and they have to be handled directly
        # by the core in order to catch the correct media handling.
        to_core(sippet, :receive_response, [incoming_response, nil])

      [{pid, _}] ->
        # Redirect the response to the existing client transaction. If needed,
        # the client transaction will redirect to the core from there.
        Transactions.Client.receive_response(pid, incoming_response)
    end
  end

  defp start_client(
         sippet,
         %Transactions.Client.Key{} = key,
         %Message{start_line: %RequestLine{}} = outgoing_request
       ) do
    module =
      case key.method do
        :invite -> Transactions.Client.Invite
        _otherwise -> Transactions.Client.NonInvite
      end

    timers = Sippet.Timers.get_timers(sippet)
    initial_data = Transactions.Client.State.new(outgoing_request, key, sippet, timers)

    DynamicSupervisor.start_child(
      supervisor_name(sippet),
      {module, [initial_data, [name: {:via, Registry, {sippet, {:transaction, key}}}]]}
    )
    |> tap(fn
      {:ok, _} ->
        :telemetry.execute(@event_txn_started, %{count: 1}, %{
          sippet: sippet,
          kind: :client,
          method: key.method
        })

      _ ->
        :ok
    end)
  end

  defp start_server(
         sippet,
         %Transactions.Server.Key{} = key,
         %Message{start_line: %RequestLine{}} = incoming_request
       ) do
    module =
      case key.method do
        :invite -> Transactions.Server.Invite
        _otherwise -> Transactions.Server.NonInvite
      end

    timers = Sippet.Timers.get_timers(sippet)
    initial_data = Transactions.Server.State.new(incoming_request, key, sippet, timers)

    DynamicSupervisor.start_child(
      supervisor_name(sippet),
      {module, [initial_data, [name: {:via, Registry, {sippet, {:transaction, key}}}]]}
    )
    |> tap(fn
      {:ok, _} ->
        :telemetry.execute(@event_txn_started, %{count: 1}, %{
          sippet: sippet,
          kind: :server,
          method: key.method
        })

      _ ->
        :ok
    end)
  end

  defp get_destination(%Message{target: target}) when is_tuple(target),
    do: target

  defp get_destination(%Message{start_line: %StatusLine{}, headers: %{via: via}} = message) do
    {_version, protocol, {host, port}, params} = hd(via)

    {host, port} =
      if Message.response?(message) do
        host =
          case params do
            %{"received" => received} -> received
            _otherwise -> host
          end

        port =
          case params do
            %{"rport" => ""} -> port
            %{"rport" => rport} -> rport |> String.to_integer()
            _otherwise -> port
          end

        {host, port}
      else
        {host, port}
      end

    {protocol, host, port}
  end

  defp get_destination(%Message{start_line: %RequestLine{request_uri: uri}} = request) do
    host = uri.host
    port = uri.port

    params =
      if uri.parameters == nil do
        %{}
      else
        URI.decode_parameters(uri.parameters)
      end

    protocol =
      if params |> Map.has_key?("transport") do
        Sippet.Message.to_protocol(params["transport"])
      else
        {_version, protocol, _sent_by, _params} = hd(request.headers.via)
        protocol
      end

    {protocol, host, port}
  end

  # Telemetry helpers — extract message metadata without allocating new structs
  defp message_kind(%Message{start_line: %RequestLine{}}), do: :request
  defp message_kind(%Message{start_line: %StatusLine{}}), do: :response

  defp message_method(%Message{start_line: %RequestLine{method: m}}), do: m

  defp message_method(%Message{start_line: %StatusLine{}, headers: %{cseq: {_, method}}}),
    do: method

  defp message_method(_), do: :unknown

  # -- Sharded-transactions feature flag --------------------------------

  defp sharded_transactions? do
    Application.get_env(:sip, :use_sharded_transactions, false)
  end

  defp sharded_handler do
    Application.get_env(:sip, :sharded_handler, Sip.ShardedRouter)
  end

  # -- Public parsing helpers (reused by ParseWorker) -------------------

  @doc """
  Parse, validate and prepare a raw SIP message for routing.

  Returns `{:ok, message}` on success, `{:error, reason}` on failure.
  Emits telemetry events for received messages and parse errors.
  """
  def parse_and_prepare(sippet, raw, from, source_transport) do
    with {:ok, message} <- parse_message(raw),
         prepared <- update_via(message, from),
         prepared <- %{prepared | source: source_transport},
         :ok <- Message.validate(prepared, from) do
      :telemetry.execute(@event_msg_received, %{byte_size: byte_size(raw)}, %{
        sippet: sippet,
        kind: message_kind(prepared),
        method: message_method(prepared)
      })

      {:ok, prepared}
    else
      {:error, reason} ->
        :telemetry.execute(@event_msg_parse_error, %{count: 1}, %{
          sippet: sippet,
          reason: reason
        })

        Logger.error(fn ->
          {protocol, address, port} = from

          [
            "discarded message from ",
            "#{ip_to_string(address)}:#{port}/#{protocol}: ",
            "#{inspect(reason)}"
          ]
        end)

        # RFC 3261 §18.3: for malformed requests, SHOULD send 400 Bad Request.
        maybe_send_400(sippet, raw, from, source_transport, reason)

        {:error, reason}
    end
  end
end
