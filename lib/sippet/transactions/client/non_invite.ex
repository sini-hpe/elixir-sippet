defmodule Sippet.Transactions.Client.NonInvite do
  @moduledoc false

  use Sippet.Transactions.Client, initial_state: :trying

  import Map, only: [put: 3, delete: 2]
  import Process, only: [send_after: 3, cancel_timer: 1]

  alias Sippet.Message.StatusLine
  alias Sippet.Transactions.Client.State

  require Logger

  # RFC 3261 §17.1.2 defaults (overridable via data.timers)
  @default_t2 4_000
  @default_timer_e 500
  @default_timer_f 64 * @default_timer_e
  @default_timer_k 5_000

  defp timer(data, name, default), do: Map.get(data.timers, name, default)

  defp start_timers(%State{request: request, extras: extras} = data) do
    timer_f = timer(data, :timer_f, @default_timer_f)
    timer_e = timer(data, :timer_e, @default_timer_e)

    extras =
      extras
      |> put(:deadline_timer, send_after(self(), :deadline, timer_f))

    extras =
      if reliable?(request, data) do
        extras
      else
        extras
        |> put(:retry_timer, send_after(self(), timer_e, timer_e))
      end

    %{data | extras: extras}
  end

  defp cancel_timers(%State{extras: extras} = data) do
    extras =
      case extras do
        %{deadline_timer: deadline_timer} ->
          cancel_timer(deadline_timer)

          extras
          |> delete(:deadline_timer)

        _ ->
          extras
      end

    extras =
      case extras do
        %{retry_timer: retry_timer} ->
          cancel_timer(retry_timer)

          extras
          |> delete(:retry_timer)

        _ ->
          extras
      end

    %{data | extras: extras}
  end

  defp retry(next_wait, %State{request: request, extras: extras} = data) do
    send_request(request, data)

    extras =
      extras
      |> put(:retry_timer, send_after(self(), next_wait, next_wait))

    {:keep_state, %{data | extras: extras}}
  end

  def trying(:enter, _old_state, %State{request: request} = data) do
    send_request(request, data)

    {:keep_state, start_timers(data)}
  end

  def trying(:info, :deadline, data),
    do: timeout(data)

  def trying(:info, last_delay, data) when is_integer(last_delay) do
    t2 = timer(data, :t2, @default_t2)
    retry(min(last_delay * 2, t2), data)
  end

  def trying(:cast, {:incoming_response, response}, data) do
    receive_response(response, data)

    case StatusLine.status_code_class(response.start_line) do
      1 -> {:next_state, :proceeding, data}
      _ -> {:next_state, :completed, data}
    end
  end

  def trying(:cast, {:error, reason}, data),
    do: shutdown(reason, data)

  def trying(event_type, event_content, data),
    do: unhandled_event(event_type, event_content, data)

  def proceeding(:enter, _old_state, _data),
    do: :keep_state_and_data

  def proceeding(:info, :deadline, data),
    do: timeout(data)

  def proceeding(:info, last_delay, data) when is_integer(last_delay) do
    t2 = timer(data, :t2, @default_t2)
    retry(t2, data)
  end

  def proceeding(:cast, {:incoming_response, response}, data) do
    receive_response(response, data)

    case StatusLine.status_code_class(response.start_line) do
      1 -> {:keep_state, data}
      _ -> {:next_state, :completed, data}
    end
  end

  def proceeding(:cast, {:error, reason}, data),
    do: shutdown(reason, data)

  def proceeding(event_type, event_content, data),
    do: unhandled_event(event_type, event_content, data)

  def completed(:enter, _old_state, %State{request: request} = data) do
    data = cancel_timers(data)

    if reliable?(request, data) do
      {:stop, :normal, data}
    else
      timer_k = timer(data, :timer_k, @default_timer_k)
      {:keep_state, data, [{:state_timeout, timer_k, nil}]}
    end
  end

  def completed(:state_timeout, _nil, data),
    do: {:stop, :normal, data}

  def completed(:cast, {:incoming_response, _response}, _data),
    do: :keep_state_and_data

  def completed(:cast, {:error, _reason}, _data),
    do: :keep_state_and_data

  def completed(event_type, event_content, data),
    do: unhandled_event(event_type, event_content, data)
end
