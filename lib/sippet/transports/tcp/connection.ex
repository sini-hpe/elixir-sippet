defmodule Sippet.Transports.TCP.Connection do
  @moduledoc false

  use GenServer

  alias Sippet.Router

  require Logger

  @default_idle_timeout 120_000
  @default_message_timeout 10_000
  @default_keepalive_interval 0

  defstruct socket: nil,
            sippet: nil,
            transport_name: nil,
            peer: nil,
            buffer: <<>>,
            parse_state: :idle,
            timer: nil,
            keepalive_timer: nil,
            idle_timeout: @default_idle_timeout,
            message_timeout: @default_message_timeout,
            keepalive_interval: @default_keepalive_interval,
            active_n: 100

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts)
  end

  @doc """
  Transfers socket ownership to this process and activates it.
  Must be called by the process that currently owns the socket.
  """
  def activate(pid, socket) do
    :gen_tcp.controlling_process(socket, pid)
    GenServer.cast(pid, :activate)
  end

  @doc """
  Sends a SIP message (as iodata) over this connection.
  """
  def send_message(pid, iodata) do
    GenServer.call(pid, {:send, iodata}, 10_000)
  end

  @impl true
  def init(opts) do
    state = %__MODULE__{
      socket: Keyword.fetch!(opts, :socket),
      sippet: Keyword.fetch!(opts, :sippet),
      transport_name: Keyword.fetch!(opts, :transport_name),
      peer: Keyword.fetch!(opts, :peer),
      idle_timeout: Keyword.get(opts, :idle_timeout, @default_idle_timeout),
      message_timeout: Keyword.get(opts, :message_timeout, @default_message_timeout),
      keepalive_interval: Keyword.get(opts, :keepalive_interval, @default_keepalive_interval)
    }

    {:ok, state}
  end

  @impl true
  def handle_cast(:activate, state) do
    :inet.setopts(state.socket, [{:active, state.active_n}])
    {:noreply, state |> set_idle_timer() |> maybe_start_keepalive()}
  end

  @impl true
  def handle_call({:send, iodata}, _from, state) do
    case :gen_tcp.send(state.socket, iodata) do
      :ok ->
        {:reply, :ok, set_idle_timer(state)}

      {:error, reason} ->
        {:stop, :normal, {:error, reason}, state}
    end
  end

  @impl true
  def handle_info({:tcp, _socket, data}, state) do
    new_buffer = <<state.buffer::binary, data::binary>>
    parse(%{state | buffer: new_buffer})
  end

  def handle_info({:tcp_closed, _socket}, state) do
    {:stop, :normal, state}
  end

  def handle_info({:tcp_error, _socket, _reason}, state) do
    {:stop, :normal, state}
  end

  def handle_info({:tcp_passive, _socket}, state) do
    :inet.setopts(state.socket, [{:active, state.active_n}])
    {:noreply, state}
  end

  def handle_info(:idle_timeout, state) do
    {ip, port} = state.peer
    Logger.debug("TCP connection to #{stringify(ip, port)} idle timeout")
    {:stop, :normal, state}
  end

  def handle_info(:message_timeout, state) do
    {ip, port} = state.peer
    Logger.debug("TCP connection to #{stringify(ip, port)} message timeout")
    {:stop, :normal, state}
  end

  def handle_info(:keepalive, state) do
    case :gen_tcp.send(state.socket, "\r\n\r\n") do
      :ok ->
        {:noreply, schedule_keepalive(state)}

      {:error, _reason} ->
        {:stop, :normal, state}
    end
  end

  @impl true
  def terminate(_reason, %{socket: socket}) do
    :gen_tcp.close(socket)
  end

  # -- SIP message parsing from TCP stream --

  # Empty buffer in idle state: wait for more data
  defp parse(%{buffer: <<>>, parse_state: :idle} = state) do
    {:noreply, set_idle_timer(state)}
  end

  # Strip CRLF keep-alive pings in idle state
  defp parse(%{buffer: <<"\r\n", rest::binary>>, parse_state: :idle} = state) do
    # Per RFC 5626 §3.5.1, respond with CRLF for keep-alive
    :gen_tcp.send(state.socket, "\r\n")
    parse(%{state | buffer: rest})
  end

  defp parse(%{buffer: <<"\n", rest::binary>>, parse_state: :idle} = state) do
    parse(%{state | buffer: rest})
  end

  # Transition from idle to reading header
  defp parse(%{parse_state: :idle} = state) do
    parse(%{state | parse_state: :read_header} |> set_message_timer())
  end

  # Read header: look for double CRLF separator
  defp parse(%{parse_state: :read_header, buffer: buffer} = state) do
    case find_header_end(buffer) do
      :nomatch ->
        {:noreply, state}

      {pos, len} ->
        header = :binary.part(buffer, 0, pos + len)
        rest = :binary.part(buffer, pos + len, byte_size(buffer) - pos - len)

        case extract_content_length(header) do
          {:ok, clen} ->
            parse(%{state | buffer: rest, parse_state: {:read_body, header, clen}})

          :error ->
            # No Content-Length header: assume empty body
            deliver_message(header, <<>>, state)
            parse(%{state | buffer: rest, parse_state: :idle})
        end
    end
  end

  # Read body: accumulate until Content-Length bytes received
  defp parse(%{parse_state: {:read_body, header, clen}, buffer: buffer} = state) do
    if byte_size(buffer) >= clen do
      <<body::binary-size(clen), rest::binary>> = buffer
      deliver_message(header, body, state)
      parse(%{state | buffer: rest, parse_state: :idle})
    else
      {:noreply, state}
    end
  end

  defp find_header_end(buffer) do
    case :binary.match(buffer, "\r\n\r\n") do
      {pos, 4} -> {pos, 4}
      :nomatch -> :binary.match(buffer, "\n\n")
    end
  end

  defp extract_content_length(header) do
    case Regex.run(~r/(?:Content-Length|l)\s*:\s*(\d+)/i, header) do
      [_, length] -> {:ok, String.to_integer(length)}
      nil -> :error
    end
  end

  defp deliver_message(header, body, %{sippet: sippet, peer: {ip, port}, transport_name: tname}) do
    message = header <> body
    Router.handle_transport_message(sippet, message, {:tcp, ip, port}, tname)
  end

  # -- Timer management --

  defp set_idle_timer(state) do
    cancel_timer(state)
    ref = Process.send_after(self(), :idle_timeout, state.idle_timeout)
    %{state | timer: ref}
  end

  defp set_message_timer(state) do
    cancel_timer(state)
    ref = Process.send_after(self(), :message_timeout, state.message_timeout)
    %{state | timer: ref}
  end

  defp cancel_timer(%{timer: nil} = state), do: state

  defp cancel_timer(%{timer: ref} = state) do
    Process.cancel_timer(ref)

    receive do
      :idle_timeout -> :ok
      :message_timeout -> :ok
    after
      0 -> :ok
    end

    %{state | timer: nil}
  end

  # -- Keep-alive management --

  defp maybe_start_keepalive(%{keepalive_interval: interval} = state)
       when is_integer(interval) and interval > 0 do
    schedule_keepalive(state)
  end

  defp maybe_start_keepalive(state), do: state

  defp schedule_keepalive(%{keepalive_interval: interval} = state)
       when is_integer(interval) and interval > 0 do
    cancel_keepalive(state)
    ref = Process.send_after(self(), :keepalive, interval)
    %{state | keepalive_timer: ref}
  end

  defp schedule_keepalive(state), do: state

  defp cancel_keepalive(%{keepalive_timer: nil} = state), do: state

  defp cancel_keepalive(%{keepalive_timer: ref} = state) do
    Process.cancel_timer(ref)

    receive do
      :keepalive -> :ok
    after
      0 -> :ok
    end

    %{state | keepalive_timer: nil}
  end

  defp stringify(ip, port) when is_tuple(ip) do
    addr = ip |> :inet_parse.ntoa() |> to_string()
    "#{addr}:#{port}"
  end

  defp stringify(ip, port), do: "#{ip}:#{port}"
end
