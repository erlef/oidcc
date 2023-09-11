defmodule Oidcc.Token.Refresh do
  @moduledoc """
  Refresh Token struct
  """

  use Oidcc.RecordStruct,
    internal_name: :token,
    record_name: :oidcc_token_refresh,
    record_type_module: :oidcc_token,
    record_type_name: :refresh,
    hrl: "include/oidcc_token.hrl"

  @type t() :: %__MODULE__{
          token: String.t()
        }
end
