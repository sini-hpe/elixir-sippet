defmodule Sippet.Options do
  @moduledoc """
  Per-instance boolean options for Sippet stacks.

  Stores flags in an ETS table keyed by `{sippet_name, option_atom}`.
  Follows the same pattern as `Sippet.Timers`.

  ## Supported options

  * `:demote_peer_timeout` — when `true`, transaction-layer timeout
    shutdown messages are logged at `info` instead of `warning`.
    Useful for stacks facing peers outside our control (e.g. UE-facing
    `gm` / `gm_ipsec` stacks) where timeouts are expected under load.
  """

  @table :sippet_options

  @doc "Creates the ETS table. Call once at application startup."
  def setup do
    if :ets.whereis(@table) == :undefined do
      :ets.new(@table, [:named_table, :public, :set, read_concurrency: true])
    end

    :ok
  end

  @doc "Sets a boolean option for a sippet instance."
  @spec set(atom(), atom(), boolean()) :: :ok
  def set(sippet_name, key, value)
      when is_atom(sippet_name) and is_atom(key) and is_boolean(value) do
    :ets.insert(@table, {{sippet_name, key}, value})
    :ok
  end

  @doc "Returns the value of an option (default `false`)."
  @spec get(atom(), atom()) :: boolean()
  def get(sippet_name, key) when is_atom(sippet_name) and is_atom(key) do
    case :ets.lookup(@table, {sippet_name, key}) do
      [{_, value}] -> value
      [] -> false
    end
  end
end
