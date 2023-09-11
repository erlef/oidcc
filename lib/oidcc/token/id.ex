defmodule Oidcc.Token.Id do
  @moduledoc """
  ID Token struct
  """

  use Oidcc.RecordStruct,
    internal_name: :token,
    record_name: :oidcc_token_id,
    record_type_module: :oidcc_token,
    record_type_name: :id,
    hrl: "include/oidcc_token.hrl"

  @type t() :: %__MODULE__{
          token: String.t(),
          claims: :oidcc_jwt_util.claims()
        }
end
