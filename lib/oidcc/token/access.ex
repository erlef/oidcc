defmodule Oidcc.Token.Access do
  @moduledoc """
  Access Token struct
  """
  @moduledoc since: "3.0.0"

  use Oidcc.RecordStruct,
    internal_name: :token,
    record_name: :oidcc_token_access,
    record_type_module: :oidcc_token,
    record_type_name: :access,
    hrl: "include/oidcc_token.hrl"

  @typedoc since: "3.0.0"
  @type t() :: %__MODULE__{
          token: String.t(),
          expires: pos_integer() | :undefined
        }
end
