defmodule Sippet.Transports.SocketPolicy do
  @moduledoc """
  Shared socket option helpers for the UDP and TCP transports:

    * `bind_to_device_opts/1` — `SO_BINDTODEVICE` (bind the socket to a
      specific network interface).
    * `dscp_opts/1` — set the IP TOS byte from a DSCP value.
    * `apply_xfrm_policy/3` — set `IP_XFRM_POLICY` so the kernel drops any
      packet not protected by an IPSec (ESP) security association.

  The binary layout produced by `apply_xfrm_policy/3` mirrors the Linux
  `struct xfrm_userpolicy_info` + `struct xfrm_user_tmpl` and must not change.
  """

  import Bitwise

  require Logger

  @doc "Socket options that bind to a network device (SO_BINDTODEVICE)."
  @spec bind_to_device_opts(binary() | nil) :: list()
  def bind_to_device_opts(nil), do: []
  def bind_to_device_opts(dev) when is_binary(dev), do: [{:bind_to_device, dev}]

  @doc "Socket options that set the IP TOS byte from a DSCP value."
  @spec dscp_opts(non_neg_integer() | nil) :: list()
  def dscp_opts(nil), do: []
  def dscp_opts(dscp) when is_integer(dscp), do: [{:tos, bsl(dscp, 2)}]

  # Sets IP_XFRM_POLICY on the socket to require IPSec (ESP) protection for
  # incoming packets. Unprotected traffic is silently dropped by the kernel.
  # Requires CAP_NET_ADMIN.
  @ip_xfrm_policy 17
  @ipproto_esp 50
  @xfrm_inf 0xFFFFFFFFFFFFFFFF

  @doc """
  Applies the "require ESP" IPSec policy to `socket`. `proto` is only used to
  label log lines (e.g. `:udp` or `:tcp`).
  """
  @spec apply_xfrm_policy(:inet.socket() | port(), :inet | :inet6, atom()) :: :ok
  def apply_xfrm_policy(socket, family, proto) do
    {level, family_byte} = xfrm_level_and_family(family)
    policy_bin = build_xfrm_policy(family_byte)

    case :inet.setopts(socket, [{:raw, level, @ip_xfrm_policy, policy_bin}]) do
      :ok ->
        Logger.info(
          "IPSec policy (require ESP) applied to #{stringify_sockname(socket)}/#{proto}"
        )

      {:error, reason} ->
        Logger.error(
          "Failed to apply IPSec policy to #{stringify_sockname(socket)}/#{proto}: " <>
            "#{inspect(reason)}. Ensure the process has CAP_NET_ADMIN capability."
        )
    end

    :ok
  end

  defp stringify_sockname(socket) do
    case :inet.sockname(socket) do
      {:ok, {ip, port}} ->
        address = ip |> :inet_parse.ntoa() |> to_string()
        "#{address}:#{port}"

      _ ->
        "?"
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
