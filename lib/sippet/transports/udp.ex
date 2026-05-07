defmodule Sippet.Transports.UDP do
  @moduledoc """
  Implements an UDP transport.

  The UDP transport consists basically in a single listening and sending
  process, this implementation itself.

  This process creates an UDP socket and keeps listening for datagrams in
  active mode. Its job is to forward the datagrams to the processing receiver
  defined in `Sippet.Transports.Receiver`.
  """

  use GenServer

  alias Sippet.Message

  require Logger

  defstruct socket: nil,
            family: :inet,
            sippet: nil,
            transport_name: nil,
            dev: nil

  @doc """
  Starts the UDP transport.
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
        _ -> :udp
      end

    dev =
      case Keyword.fetch(options, :dev) do
        {:ok, dev} when is_binary(dev) and dev != "" -> dev
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

    GenServer.start_link(
      __MODULE__,
      {name, ip, port, family, transport_name, dev, security_protected, dscp}
    )
  end

  @impl true
  def init({name, ip, port, family, transport_name, dev, security_protected, dscp}) do
    Sippet.register_transport(name, transport_name, :udp, false)

    {:ok, nil,
     {:continue, {name, ip, port, family, transport_name, dev, security_protected, dscp}}}
  end

  @impl true
  def handle_continue(
        {name, ip, port, family, transport_name, dev, security_protected, dscp},
        nil
      ) do
    sock_opts =
      [:binary, {:active, true}, {:ip, ip}, family] ++
        bind_to_device_opts(dev) ++ dscp_opts(dscp)

    case :gen_udp.open(port, sock_opts) do
      {:ok, socket} ->
        if security_protected do
          apply_xfrm_policy(socket, family)
        end

        Logger.debug(
          "#{inspect(self())} started transport " <>
            "#{stringify_sockname(socket)}/udp (#{transport_name})"
        )

        state = %__MODULE__{
          socket: socket,
          family: family,
          sippet: name,
          transport_name: transport_name,
          dev: dev
        }

        {:noreply, state}

      {:error, reason} ->
        Logger.error(
          "#{inspect(self())} port #{port}/udp " <>
            "#{inspect(reason)}, retrying in 10s..."
        )

        Process.sleep(10_000)

        {:noreply, nil,
         {:continue, {name, ip, port, family, transport_name, dev, security_protected, dscp}}}
    end
  end

  @impl true
  def handle_info(
        {:udp, _socket, from_ip, from_port, packet},
        %{sippet: sippet, transport_name: transport_name} = state
      ) do
    Sippet.Router.handle_transport_message(
      sippet,
      packet,
      {:udp, from_ip, from_port},
      transport_name
    )

    {:noreply, state}
  end

  @impl true
  def handle_cast(
        {:send_message, message, to_host, to_port, key},
        %{socket: socket, family: family, sippet: sippet} = state
      ) do
    Logger.debug([
      "[#{state.sippet}][#{transport_label(state)}] sending message to #{stringify_hostport(to_host, to_port)}/udp",
      ", #{inspect(key)}"
    ])

    with {:ok, to_ip} <- resolve_name(to_host, family),
         iodata <- Message.to_iodata(message),
         :ok <- :gen_udp.send(socket, {to_ip, to_port}, iodata) do
      :ok
    else
      {:error, reason} ->
        Logger.warning("udp transport error for #{to_host}:#{to_port}: #{inspect(reason)}")

        if key != nil do
          Sippet.Router.receive_transport_error(sippet, key, reason)
        end
    end

    {:noreply, state}
  end

  @impl true
  def terminate(reason, %{socket: socket}) do
    Logger.debug(
      "stopped transport #{stringify_sockname(socket)}/udp, reason: #{inspect(reason)}"
    )

    :gen_udp.close(socket)
  end

  defp resolve_name(host, family) do
    host
    |> String.to_charlist()
    |> :inet.getaddr(family)
  end

  defp stringify_sockname(socket) do
    {:ok, {ip, port}} = :inet.sockname(socket)

    address =
      ip
      |> :inet_parse.ntoa()
      |> to_string()

    "#{address}:#{port}"
  end

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

  defp bind_to_device_opts(nil), do: []
  defp bind_to_device_opts(dev) when is_binary(dev), do: [{:bind_to_device, dev}]

  defp dscp_opts(nil), do: []
  defp dscp_opts(dscp) when is_integer(dscp), do: [{:tos, Bitwise.bsl(dscp, 2)}]

  # Sets IP_XFRM_POLICY on the socket to require IPSec (ESP) protection for
  # incoming packets. Unprotected traffic is silently dropped by the kernel.
  # Requires CAP_NET_ADMIN.
  @ip_xfrm_policy 17
  @ipproto_esp 50
  @xfrm_inf 0xFFFFFFFFFFFFFFFF

  defp apply_xfrm_policy(socket, family) do
    {level, family_byte} = xfrm_level_and_family(family)
    policy_bin = build_xfrm_policy(family_byte)

    case :inet.setopts(socket, [{:raw, level, @ip_xfrm_policy, policy_bin}]) do
      :ok ->
        Logger.info("IPSec policy (require ESP) applied to #{stringify_sockname(socket)}/udp")

      {:error, reason} ->
        Logger.error(
          "Failed to apply IPSec policy to #{stringify_sockname(socket)}/udp: #{inspect(reason)}. " <>
            "Ensure the process has CAP_NET_ADMIN capability."
        )
    end
  end

  defp xfrm_level_and_family(:inet), do: {0, 2}
  defp xfrm_level_and_family(:inet6), do: {41, 10}

  defp build_xfrm_policy(family_byte) do
    # struct xfrm_userpolicy_info (168 bytes)
    # 56 bytes, family at offset 40
    sel = <<0::size(320), family_byte::little-16, 0::size(120)>>

    lft =
      <<
        @xfrm_inf::little-64,
        @xfrm_inf::little-64,
        @xfrm_inf::little-64,
        @xfrm_inf::little-64,
        # 64 bytes
        0::size(256)
      >>

    # 32 bytes
    curlft = <<0::size(256)>>
    # priority(4) + index(4) + dir=0(1) + action=0(1) + flags=0(1) + share=0(1) + pad(4)
    # 16 bytes
    tail = <<0::size(128)>>
    # 168 bytes
    policy_info = sel <> lft <> curlft <> tail

    # struct xfrm_user_tmpl (64 bytes)
    # id: daddr(16) + spi(4) + proto(1) + pad(3) = 24
    tmpl_id = <<0::size(128), 0::size(32), @ipproto_esp::8, 0::size(24)>>
    # family(2) + pad(2) + saddr(16) + reqid(4) + mode(1) + share(1) + optional(1) + pad(1)
    # + aalgos(4) + ealgos(4) + calgos(4) = 40
    tmpl_rest =
      <<family_byte::little-16, 0::size(16), 0::size(128), 0::size(32), 0::8, 0::8, 0::8, 0::8,
        0xFFFFFFFF::little-32, 0xFFFFFFFF::little-32, 0xFFFFFFFF::little-32>>

    # 64 bytes
    tmpl = tmpl_id <> tmpl_rest

    # 232 bytes
    policy_info <> tmpl
  end
end
