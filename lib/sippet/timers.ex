defmodule Sippet.Timers do
  @moduledoc """
  SIP transaction timer defaults and per-instance configuration.

  Timer names follow RFC 3261 §17 Table 4:

  | Timer | Default   | Section | Meaning                                  |
  |-------|-----------|---------|------------------------------------------|
  | T1    | 500 ms    | 17.1.1.1| RTT estimate                            |
  | T2    | 4 s       | 17.1.2.2| Max retransmit interval (non-INVITE)    |
  | T4    | 5 s       | 17.1.2.2| Max duration a message remains in network|
  | A     | T1        | 17.1.1.2| INVITE request retransmit (unreliable)  |
  | B     | 64*T1     | 17.1.1.2| INVITE transaction timeout              |
  | C     | > 3 min   | 16.6/11 | Proxy INVITE transaction timeout        |
  | D     | > 32 s    | 17.1.1.2| Response retransmit wait (INVITE client)|
  | E     | T1        | 17.1.2.2| Non-INVITE request retransmit (unreliable)|
  | F     | 64*T1     | 17.1.2.2| Non-INVITE transaction timeout          |
  | G     | T1        | 17.2.1  | INVITE response retransmit (server)     |
  | H     | 64*T1     | 17.2.1  | Wait for ACK receipt                    |
  | I     | T4        | 17.2.1  | ACK retransmit wait (INVITE server)     |
  | J     | 64*T1     | 17.2.2  | Non-INVITE response retransmit wait     |
  | K     | T4        | 17.1.2.2| Response retransmit wait (non-INVITE client)|

  ## Configuration

  Store timer overrides per Sippet instance via `set_timers/2`.
  Transactions read them at startup from their State's `timers` map.
  Values are in milliseconds.

  Keys are atoms: `:t1`, `:t2`, `:t4`, `:timer_a`, `:timer_b`, etc.
  Derived timers (e.g. `:timer_b` defaults to `64 * t1`) are
  resolved automatically when not explicitly set.
  """

  @table :sippet_timers

  @doc "Creates the ETS table. Call once at application startup."
  def setup do
    if :ets.whereis(@table) == :undefined do
      :ets.new(@table, [:named_table, :public, :set, read_concurrency: true])
    end

    :ok
  end

  # RFC 3261 §17 base defaults (milliseconds)
  @default_t1 500
  @default_t2 4_000
  @default_t4 5_000

  @doc """
  Returns the default timer values as a map.
  """
  def defaults do
    t1 = @default_t1
    t2 = @default_t2
    t4 = @default_t4

    %{
      t1: t1,
      t2: t2,
      t4: t4,
      timer_a: t1,
      timer_b: 64 * t1,
      timer_d: 32_000,
      timer_e: t1,
      timer_f: 64 * t1,
      timer_g: t1,
      timer_h: 64 * t1,
      timer_i: t4,
      timer_j: 64 * t1,
      timer_k: t4
    }
  end

  @doc """
  Resolves full timer map from user overrides.

  If `:t1`, `:t2`, or `:t4` are overridden, derived timers are
  recalculated unless they are also explicitly set.
  """
  def resolve(overrides) when is_map(overrides) do
    t1 = Map.get(overrides, :t1, @default_t1)
    t2 = Map.get(overrides, :t2, @default_t2)
    t4 = Map.get(overrides, :t4, @default_t4)

    base = %{
      t1: t1,
      t2: t2,
      t4: t4,
      timer_a: t1,
      timer_b: 64 * t1,
      timer_d: max(32_000, 64 * t1),
      timer_e: t1,
      timer_f: 64 * t1,
      timer_g: t1,
      timer_h: 64 * t1,
      timer_i: t4,
      timer_j: 64 * t1,
      timer_k: t4
    }

    Map.merge(base, overrides)
  end

  def resolve(nil), do: defaults()

  @doc """
  Stores timer configuration for a Sippet instance.
  """
  def set_timers(sippet_name, timers) when is_atom(sippet_name) and is_map(timers) do
    resolved = resolve(timers)
    :ets.insert(@table, {sippet_name, resolved})
    :ok
  end

  @doc """
  Returns the resolved timer map for a Sippet instance.
  """
  def get_timers(sippet_name) when is_atom(sippet_name) do
    case :ets.lookup(@table, sippet_name) do
      [{_, timers}] -> timers
      [] -> defaults()
    end
  end

  @doc """
  Returns a single timer value for a Sippet instance, with fallback
  to the RFC default.
  """
  def get(sippet_name, timer_name) when is_atom(sippet_name) and is_atom(timer_name) do
    timers = get_timers(sippet_name)
    Map.get(timers, timer_name) || Map.get(defaults(), timer_name)
  end
end
