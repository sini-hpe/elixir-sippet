defmodule Sippet.Transactions.Client.State do
  @moduledoc false

  alias Sippet.Message, as: Message
  alias Sippet.Message.RequestLine, as: RequestLine
  alias Sippet.Transactions, as: Transactions

  @typedoc "The client transaction key"
  @type key :: Transactions.Client.Key.t()

  @type t :: [
          request: Message.request(),
          key: key,
          sippet: atom,
          timers: map,
          extras: %{}
        ]

  defstruct request: nil,
            key: nil,
            sippet: nil,
            timers: %{},
            extras: %{}

  @doc """
  Creates the client transaction state.

  `timers` is an optional map of timer overrides. See `Sippet.Timers`
  for key names and defaults.
  """
  def new(
        %Message{start_line: %RequestLine{}} = outgoing_request,
        %Transactions.Client.Key{} = key,
        sippet,
        timers \\ %{}
      )
      when is_atom(sippet) do
    %__MODULE__{
      request: outgoing_request,
      key: key,
      sippet: sippet,
      timers: timers
    }
  end
end
