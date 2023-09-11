defmodule Oidcc.Token.Access do
  @moduledoc """
  Access Token struct
  """

  use Oidcc.RecordStruct,
    internal_name: :token,
    record_name: :oidcc_token_access,
    record_type_module: :oidcc_token,
    record_type_name: :access,
    hrl: "include/oidcc_token.hrl"

  @type t() :: %__MODULE__{
          token: String.t(),
          expires: pos_integer() | :undefined
        }
end
